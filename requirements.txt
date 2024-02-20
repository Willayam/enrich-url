from flask import Flask, request, jsonify
import threading

app = Flask(__name__)

def process_request(data):
    # Placeholder for your existing function to process the data
    # For example, fetch_domain_info(url)
    print(data)
    # You should integrate your domain fetching code here

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
