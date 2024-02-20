from flask import Flask, request, jsonify
from urllib.parse import urlparse
import threading

app = Flask(__name__)

def fetch_domain_info(url):
    domain = urlparse(url).netloc or url  # Fallback to use url as domain if netloc is empty
    print(f"Fetching info for domain: {domain}")  # Debugging print
    try:
        domain_info = whois.whois(domain)
        result = {
            'URL': url,
            'Jurisdiction': domain_info.get('country'),
            'DNS': ', '.join(domain_info.get('name_servers', [])),  # Join list into string
            'Registrar': domain_info.get('registrar'),
            'Registrant': domain_info.get('org'),
            'Created': domain_info.get('creation_date'),
            'Expires': domain_info.get('expiration_date')
        }
        print(result)  # Debugging print
        return result
    except Exception as e:
        print(f"Error fetching info for {url}: {e}")  # Debugging print
        return {'URL': url, 'Error': str(e)}

def process_request(data):
    # Assuming 'data' contains the URL in a 'url' key
    url = data.get('url')
    if url:
        result = fetch_domain_info(url)
        print(result)  # This will print the result to your console for debugging
        # Depending on your requirements, you might want to do something with the result here
    else:
        print("No URL provided in the data")

@app.route('/webhook', methods=['POST'])
def webhook():
    data = request.json  # Assuming the incoming request has JSON body
    if data:
        # Process the data in a new thread to avoid blocking the response
        threading.Thread(target=process_request, args=(data,)).start()
        return jsonify({"status": "processing"}), 202
    else:
        return jsonify({"error": "Invalid request"}), 400

if __name__ == '__main__':
    app.run(debug=True, port=5000)  # Run the server
