from flask import Flask, request
app = Flask(__name__)
@app.route('/')
def index():
    with open('/home/sahil/Elevate-Labs-Final-Projects/honeypot/logs/http_access.log', 'a') as f:
        f.write(f"Access: {request.remote_addr}\n")
    return "Welcome to Fake Web Server"
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80)
