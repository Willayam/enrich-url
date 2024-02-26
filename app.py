from flask import Flask, request, jsonify
from urllib.parse import urlparse
import whois
from datetime import datetime
import dns.resolver

app = Flask(__name__)

def get_mx_records(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        return [str(record.exchange) for record in mx_records]
    except dns.resolver.NoAnswer:
        return None

def get_spf_record(domain):
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        for record in txt_records:
            if record.to_text().startswith('"v=spf1'):
                return record.to_text()
        return None
    except dns.resolver.NoAnswer:
        return None

def get_dkim_record(domain, selector):
    try:
        dkim_record_name = '{}._domainkey.{}'.format(selector, domain)
        dkim_records = dns.resolver.resolve(dkim_record_name, 'TXT')
        return dkim_records[0].to_text()
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None

def get_dmarc_record(domain):
    try:
        dmarc_record_name = '_dmarc.' + domain
        dmarc_records = dns.resolver.resolve(dmarc_record_name, 'TXT')
        return dmarc_records[0].to_text()
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None

def get_bimi_record(domain):
    try:
        bimi_record_name = '_bimi.' + domain
        bimi_records = dns.resolver.resolve(bimi_record_name, 'TXT')
        return bimi_records[0].to_text()
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None

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
        dkim_record = get_dkim_record(domain, 'selector2')  # Replace with the actual selector if known
        dmarc_record = get_dmarc_record(domain)
        bimi_record = get_bimi_record(domain)

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
            'BIMI_Record': bimi_record
        }
        return result
    except Exception as e:
        return {'URL': url, 'Error': str(e)}

@app.route('/webhook', methods=['POST'])
def webhook_handler():
    # Parse the JSON from the request body
    data = request.json
    if data and 'url' in data:
        # If 'url' key is present, process it
        result = fetch_domain_info(data['url'])
        return jsonify(result), 200
    else:
        # If 'url' key is not present, return an error response
        return jsonify({"error": "Missing 'url' key in JSON payload"}), 400

if __name__ == '__main__':
    app.run(debug=True, port=5001)  # Specify a different port if needed