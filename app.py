from flask import Flask, request, jsonify
from urllib.parse import urlparse
import whois
from datetime import datetime
import dns.resolver
import requests
import functools
import logging
import ssl
import socket
import threading
import time
import queue

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
        return []

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
def get_dkim_record(domain, selector='default'):
    try:
        dkim_record_name = f'{selector}._domainkey.{domain}'
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
def get_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                ssl_info = ssock.getpeercert()
                exp_date = datetime.strptime(ssl_info['notAfter'], '%b %d %H:%M:%S %Y %Z')
                issuer = ssl_info.get('issuer')
                issuer_str = ', '.join([f"{i[0]}={i[1]}" for i in issuer]) if issuer else "N/A"
                return {"domain": domain, "expiry_date": exp_date, "issuer": issuer_str}
    except Exception as e:
        return {"domain": domain, "error": str(e), "issuer": "Error fetching issuer"}

@log_function_time
def is_url_live(url):
    try:
        response = requests.get(url, timeout=3, allow_redirects=True)
        live = 200 <= response.status_code < 400
        status_code = response.status_code
        redirect_url = response.url if response.url != url else None
        return live, status_code, redirect_url
    except requests.RequestException as e:
        return False, str(e), None

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
                return ["Error fetching subdomains: Status code " + str(response.status_code)]
        except requests.RequestException as e:
            return ["Error fetching subdomains: " + str(e)]
    return ["Error fetching subdomains: Exceeded max retries"]

@log_function_time
def get_whois_info(domain):
    try:
        whois_info = whois.whois(domain)
        return whois_info
    except whois.parser.PywhoisError as e:
        return {"error": str(e)}

@app.route('/domain-info', methods=['GET'])
def domain_info():
    domain = request.args.get('domain')
    if domain:
        parsed_url = urlparse(domain)
        hostname = parsed_url.netloc or parsed_url.path  # Extract hostname if URL, else assume it's a domain

        # Multithreading to fetch records simultaneously
        queue_results = queue.Queue()

        def worker(target, *args):
            result = target(*args)
            queue_results.put(result)

        # Define tasks
        tasks = [
            (get_mx_records, hostname),
            (get_spf_record, hostname),
            (get_dkim_record, hostname),
            (get_dmarc_record, hostname),
            (get_bimi_record, hostname),
            (get_ssl_certificate, hostname),
            (is_url_live, f"http://{hostname}"),
            (fetch_subdomains, hostname),
            (get_whois_info, hostname)
        ]

        threads = [threading.Thread(target=worker, args=(task[0], *task[1:])) for task in tasks]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # Gather results
        results = [queue_results.get() for _ in tasks]

        return jsonify(results)
    else:
        return jsonify({"error": "No domain provided"}), 400

@app.route('/webhook', methods=['POST'])
def webhook_handler():
    logging.info("Received webhook request")
    data = request.json
    if data and 'url' in data:
        logging.info(f"Processing URL: {data['url']}")
        task_queue = queue.Queue()
        result_queue = queue.Queue()

        worker_threads = [threading.Thread(target=fetch_domain_info, args=(task_queue, result_queue)) for _ in range(4)]  # Adjust thread count as needed

        # Start worker threads
        for thread in worker_threads:
            thread.daemon = True  # Ensure threads exit with the main process
            thread.start()

        task_queue.put(data['url'])
        task_queue.join()      # Wait for the task to complete

        # Get results from the queue
        if not result_queue.empty():
            url, result = result_queue.get()
            return jsonify(result), 200
        else:
            return jsonify({"error": "Error processing URL"}), 500
    else:
        logging.error("Missing 'url' key in JSON payload")
        return jsonify({"error": "Missing 'url' key in JSON payload"}), 400

if __name__ == '__main__':
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
    
    app.logger.info("Starting Flask application on port 5001")
    app.run(debug=False, port=5001)