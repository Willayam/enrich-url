from flask import Flask, request, jsonify
from urllib.parse import urlparse
import whois
from datetime import datetime
import dns.resolver
import requests
import functools
import logging
import time

app = Flask(__name__)

def log_function_time(func):
    @functools.wraps(func)
    def wrapper_log_function_time(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        logging.info(f"Function {func.__name__!r} executed in {(end_time - start_time):.4f}s")
        return result
    return wrapper_log_function_time

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

@log_function_time
def get_mx_records(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        return [str(record.exchange) for record in mx_records]
    except dns.resolver.NoAnswer:
        return None

@log_function_time
def get_spf_record(domain):
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        for record in txt_records:
            if record.to_text().startswith('"v=spf1'):
                return record.to_text()
        return None
    except dns.resolver.NoAnswer:
        return None

@log_function_time
def get_dkim_record(domain, selector):
    try:
        dkim_record_name = '{}._domainkey.{}'.format(selector, domain)
        dkim_records = dns.resolver.resolve(dkim_record_name, 'TXT')
        return dkim_records[0].to_text()
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None

@log_function_time
def get_dmarc_record(domain):
    try:
        dmarc_record_name = '_dmarc.' + domain
        dmarc_records = dns.resolver.resolve(dmarc_record_name, 'TXT')
        return dmarc_records[0].to_text()
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None

@log_function_time
def get_bimi_record(domain):
    try:
        bimi_record_name = '_bimi.' + domain
        bimi_records = dns.resolver.resolve(bimi_record_name, 'TXT')
        return bimi_records[0].to_text()
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None

@log_function_time
def fetch_subdomains(domain, retries=3, backoff_factor=1):
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    for attempt in range(retries):
        try:
            response = requests.get(url)
            if response.status_code == 200:
                json_data = response.json()
                subdomains = {entry.get('name_value') for entry in json_data if entry.get('name_value')}
                return list(subdomains)
            elif response.status_code == 429:
                sleep_time = backoff_factor * (2 ** attempt)
                logging.info(f"Rate limit hit, retrying in {sleep_time} seconds for domain: {domain}")
                time.sleep(sleep_time)
            else:
                logging.error(f"Failed to fetch data for {domain}. Status code: {response.status_code}")
        except Exception as e:
            logging.error(f"Exception occurred while fetching subdomains for {domain}: {e}")
    logging.error(f"Max retries exceeded for domain {domain}")
    return []

@log_function_time
def fetch_domain_info(url):
    domain = urlparse(url).netloc or url  # Fallback to use url as domain if netloc is empty
    try:
        domain_info = whois.whois(domain)
        # Format dates for JSON serialization
        created_date = domain_info.get('creation_date')
        expires_date = domain_info.get('expiration_date')
        if isinstance(created_date, datetime):
            created_date = created_date.strftime('%Y-%m-%d %H:%M:%S')
        if isinstance(expires_date, datetime):
            expires_date = expires_date.strftime('%Y-%m-%d %H:%M:%S')

        # Fetch DNS records
        mx_records = get_mx_records(domain)
        spf_record = get_spf_record(domain)
        dkim_record = get_dkim_record(domain, 'selector2')  # Assume 'selector2' or replace as needed
        dmarc_record = get_dmarc_record(domain)
        bimi_record = get_bimi_record(domain)
        subdomains = fetch_subdomains(domain)

        result = {
            'URL': url,
            'Jurisdiction': domain_info.get('country'),
            'DNS': ', '.join(domain_info.get('name_servers', [])) if isinstance(domain_info.get('name_servers', []), list) else domain_info.get('name_servers'),
            'Registrar': domain_info.get('registrar'),
            'Registrant': domain_info.get('org'),
            'Created': created_date,
            'Expires': expires_date,
            'MX_Records': mx_records,
            'SPF_Record': spf_record,
            'DKIM_Record': dkim_record,
            'DMARC_Record': dmarc_record,
            'BIMI_Record': bimi_record,
            'Subdomains': subdomains
        }
        return result
    except Exception as e:
        return {'URL': url, 'Error': str(e)}

@app.route('/webhook', methods=['POST'])
def webhook_handler():
    logging.info("Received webhook request")
    data = request.json
    if data and 'url' in data:
        logging.info(f"Processing URL: {data['url']}")
        result = fetch_domain_info(data['url'])
        return jsonify(result), 200
    else:
        logging.error("Missing 'url' key in JSON payload")
        return jsonify({"error": "Missing 'url' key in JSON payload"}), 400

if __name__ == '__main__':
    # Set up specific logger for the application
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
    
    app.logger.info("Starting Flask application on port 5001")
    app.run(debug=False, port=5001)