from flask import Flask, request, jsonify
from urllib.parse import urlparse
import whois
from datetime import datetime

app = Flask(__name__)

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

        result = {
            'URL': url,
            'Jurisdiction': domain_info.get('country'),
            'DNS': ', '.join(domain_info.get('name_servers', [])) if isinstance(domain_info.get('name_servers', []), list) else domain_info.get('name_servers'),
            'Registrar': domain_info.get('registrar'),
            'Registrant': domain_info.get('org'),
            'Created': created_date,
            'Expires': expires_date
        }
        return result
    except Exception as e:
        return {'URL': url, 'Error': str(e)}

@app.route('/webhook', methods=['POST'])
def webhook():
    data = request.json  # Assuming the incoming request has JSON body
    if data and 'url' in data:
        result = fetch_domain_info(data['url'])
        return jsonify(result), 200  # Return the fetched information as JSON
    else:
        return jsonify({"error": "Invalid request, URL is missing."}), 400

if __name__ == '__main__':
    app.run(debug=True, port=5001)  # Specify a different port if needed