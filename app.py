import dns.resolver
import functools
import logging
import time
from flask import Flask, request, jsonify
import concurrent.futures
import whois
import requests
from datetime import datetime
import ssl
import socket

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
def format_date(date_field):
    """Ensure dates are in ISO 8601 format."""
    if not date_field:
        return None
    if isinstance(date_field, list):  # If the date field is a list, choose the first relevant date
        date_field = date_field[0]
    if isinstance(date_field, datetime):  # Format datetime objects to string
        return date_field.isoformat()
    return date_field  # In case the date is already a string or other format

def format_list_as_string(list_field):
    if not list_field:
        return None
    if isinstance(list_field, list):
        return ','.join([str(item).lower() for item in list_field])
    return str(list_field).lower()

@log_function_time
def fetch_whois_data(domain):
    try:
        whois_info = whois.whois(domain)
        domain_info = {
            "Created": format_date(whois_info.get("creation_date")),
            "Expires": format_date(whois_info.get("expiration_date")),
            "Updated": format_date(whois_info.get("updated_date")),
            "Registrar": whois_info.get("registrar"),
            "Registrant": whois_info.get("name") if whois_info.get("name") else whois_info.get("org"),
            "Jurisdiction": whois_info.get("country"),
            "NS": format_list_as_string(whois_info.get("name_servers")),
            "Email": format_list_as_string(whois_info.get("emails")),
            "WHOISServer": whois_info.get("whois_server"),
            "Status": format_list_as_string(whois_info.get("status"))
        }
        return domain_info
    except Exception as e:
        return {"error": str(e)}

@log_function_time
def fetch_dns_records(domain):
    def fetch_record(record_type):
        try:
            if record_type in ['MX', 'TXT', 'A', 'DNSKEY']:
                records = dns.resolver.resolve(domain, record_type)
                if record_type == 'A':
                    return 'A', [str(record.address) for record in records]
                elif record_type == 'DNSKEY':
                    # If DNSKEY records are found, it's an indication that DNSSEC may be used
                    return 'DNSSEC', "Enabled"
                else:
                    return record_type, [record.to_text() for record in records]
            elif record_type == 'DMARC':
                return 'DMARC', [record.to_text() for record in dns.resolver.resolve('_dmarc.' + domain, 'TXT')]
            elif record_type == 'BIMI':
                return 'BIMI', [record.to_text() for record in dns.resolver.resolve('_bimi.' + domain, 'TXT')]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            return record_type, f"No {record_type} records found"
        except dns.resolver.NoNameservers:
            return 'DNSSEC', "No DNSSEC records found"

    records = {}
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # Include 'A' for A records and 'DNSKEY' to check for DNSSEC
        future_to_record = {executor.submit(fetch_record, record_type): record_type for record_type in ['MX', 'TXT', 'A', 'DMARC', 'BIMI', 'DNSKEY']}
        for future in concurrent.futures.as_completed(future_to_record):
            record_type, result = future.result()
            if record_type == 'TXT':
                # Process TXT records to separate SPF and generic TXT records
                spf_records = [r for r in result if r.startswith('"v=spf1')]
                dkim_records = [r for r in result if r.startswith('v=DKIM1')]  # Example to capture DKIM records, might need adjustment based on actual selector
                records["SPF"] = spf_records if spf_records else "No SPF record found"
                records["DKIM"] = dkim_records if dkim_records else "No DKIM record found"
                records[record_type] = result  # Keep all TXT records if needed
            else:
                records[record_type] = result

    # If DNSKEY wasn't found, it indicates DNSSEC is not enabled
    if 'DNSSEC' not in records:
        records['DNSSEC'] = "Disabled"

    return records

@log_function_time
def fetch_url_data(domain):
    # Initialize results with more meaningful default values
    results = {
        "IsAccessible": "false",
        "HTTPStatusCode": None,
        "RedirectURL": None,
        "HTTP": "false",
        "HTTPS": "false",
    }
    
    # Initialize an empty set to track protocols over which the domain is accessible
    accessible_protocols = set()

    for protocol in ["http", "https"]:
        url = f"{protocol}://{domain}"
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            # Check if the response status code indicates success
            if 200 <= response.status_code < 400:
                results["IsAccessible"] = "true"
                results["HTTPStatusCode"] = response.status_code
                accessible_protocols.add(protocol)
                if response.history:  # If there are any redirects
                    # Note: You might want to handle the case where there are multiple redirects differently
                    results["RedirectURL"] = response.url
            else:
                logging.info(f"Non-successful status code {response.status_code} for {url}")
        except requests.RequestException as e:
            logging.error(f"RequestException for {url}: {e}")

    # Update protocol-specific accessibility based on successful connections
    for protocol in ["http", "https"]:
        results[protocol.upper()] = "true" if protocol in accessible_protocols else "false"
    
    return results

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
def fetch_ssl_info_for_subdomains(executor, subdomains):
    # Use the executor to submit a job for fetching SSL info for each subdomain
    future_to_ssl_info = {executor.submit(fetch_ssl_info_for_subdomain, sub): sub for sub in subdomains}
    ssl_info_results = []
    for future in concurrent.futures.as_completed(future_to_ssl_info):
        try:
            ssl_info_results.append(future.result())
        except Exception as exc:
            subdomain = future_to_ssl_info[future]
            logging.error(f"SSL info fetching for {subdomain} generated an exception: {exc}")
            ssl_info_results.append({"SubdomainName": subdomain, "error": str(exc)})
    return ssl_info_results


@log_function_time
def fetch_ssl_info_for_subdomain(subdomain):
    try:
        context = ssl.create_default_context()
        # Connect to the subdomain over port 443 (SSL) with a timeout
        with socket.create_connection((subdomain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=subdomain) as ssock:
                cert = ssock.getpeercert()

                # Extract the necessary information from the certificate
                cert_common_name = cert.get("subjectAltName", [("DNS", "N/A")])[0][1]  # Use SAN for commonName if available
                
                # Extract issuer information and specifically look for the 'organizationName' (O) entry
                issuer = next((item[0][1] for item in cert.get('issuer') if item[0][0] == 'organizationName'), "N/A")

                # Parse certificate validity dates
                valid_from = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z').isoformat()
                valid_until = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').isoformat()

                # Extract covered domains from the certificate's subjectAltName
                covered_domains_list = [item[1] for item in cert.get("subjectAltName", []) if item[0] == "DNS"]

                return {
                    "SubdomainName": subdomain,
                    "CertificateAuthorityName": issuer,
                    "CertificateCommonName": cert_common_name,
                    "CertificateCoveredDomains": ", ".join(covered_domains_list),
                    "CertificateValidFrom": valid_from,
                    "CertificateValidUntil": valid_until
                }
    except Exception as e:
        return {
            "SubdomainName": subdomain,
            "error": str(e)
        }
    
def aggregate_data(domain, whois_data, dns_data, url_data, subdomains, ssl_info):
    final_data = {
        "Domain": domain,
        "Created": whois_data.get("Created", None),
        "Expires": whois_data.get("Expires", None),
        "Updated": whois_data.get("Updated", None),
        # "TLD": "PLACEHOLDER",
        "Registrar": whois_data.get("Registrar", None),
        "Registrant": whois_data.get("Registrant", None),
        "Jurisdiction": whois_data.get("Jurisdiction", None),
        "Status": whois_data.get("Status", None),
        "Email": whois_data.get("Email", None),
        "WHOISServer": whois_data.get("WHOISServer", None),
        "IsAccessible": url_data.get("IsAccessible", None),
        "HTTPStatusCode": url_data.get("HTTPStatusCode", None),
        "RedirectURL": url_data.get("RedirectURL", None),
        "HTTP": url_data.get("HTTP", "false"),
        "HTTPS": url_data.get("HTTPS", "false"),
        # "TLS": "PLACEHOLDER",
        "DNSSEC": dns_data.get('DNSSEC', "Disabled"),
        "NS": whois_data.get("NS", None),
        "Subdomains": [{
            "SubdomainName": ssl.get("SubdomainName", None),
            "CertificateAuthorityName": ssl.get("CertificateAuthorityName", None),
            "CertificateCommonName": ssl.get("CertificateCommonName", None),
            "CertificateCoveredDomains": ssl.get("CertificateCoveredDomains", None),
            "CertificateValidFrom": ssl.get("CertificateValidFrom", None),
            "CertificateValidUntil": ssl.get("CertificateValidUntil", None),
        } for ssl in ssl_info],
        "MX": ", ".join(dns_data.get('MX', [])) if dns_data.get('MX') and dns_data.get('MX') != "No MX records found" else None,
        "SPF": ", ".join(dns_data.get('SPF', [])) if dns_data.get('SPF') and dns_data.get('SPF') != "No SPF record found" else None,
        "DKIM": ", ".join(dns_data.get('DKIM', [])) if 'DKIM' in dns_data and dns_data.get('DKIM') and dns_data.get('DKIM') != "No DKIM record found" else None,
        "DMARC": ", ".join(dns_data.get('DMARC', [])) if dns_data.get('DMARC') and dns_data.get('DMARC') != "No DMARC records found" else None,
        "BIMI": ", ".join(dns_data.get('BIMI', [])) if dns_data.get('BIMI') and dns_data.get('BIMI') != "No BIMI records found" else None,
        "A": ", ".join(dns_data.get('A', [])) if dns_data.get('A') and dns_data.get('A') != "No A records found" else None,
    }

    return final_data

@log_function_time
@app.route('/domain-info', methods=['GET'])
@log_function_time
def handle_webhook():
    domain = request.args.get('domain')
    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    with concurrent.futures.ThreadPoolExecutor() as executor:
        # Submit tasks for parallel execution
        future_to_whois = executor.submit(fetch_whois_data, domain)
        future_to_dns = executor.submit(fetch_dns_records, domain)
        future_to_url = executor.submit(fetch_url_data, domain)
        future_to_subdomains = executor.submit(fetch_subdomains, domain)

        # Use as_completed to efficiently wait for tasks to finish
        whois_data, dns_data, url_data, subdomains = None, None, None, None
        for future in concurrent.futures.as_completed([future_to_whois, future_to_dns, future_to_url, future_to_subdomains]):
            result = future.result()
            if future == future_to_whois:
                whois_data = result
            elif future == future_to_dns:
                dns_data = result
            elif future == future_to_url:
                url_data = result
            elif future == future_to_subdomains:
                subdomains = result

        # Fetch SSL info for subdomains in parallel
        ssl_info = fetch_ssl_info_for_subdomains(executor, subdomains)

    # Aggregate all fetched data
    final_data = aggregate_data(domain, whois_data, dns_data, url_data, subdomains, ssl_info)
    return jsonify(final_data)

if __name__ == '__main__':
    # app.run(debug=True)
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
    
    app.logger.info("Starting Flask application on port 5001")
    app.run(debug=False, port=5001)