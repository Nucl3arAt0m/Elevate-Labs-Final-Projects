from flask import Flask, render_template, request
from scanner import scan
import os

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    results = []
    if request.method == 'POST':
        target_url = request.form.get('url').strip()
        if target_url:
            results = scan(target_url)
    return render_template('scan.html', results=results)

@app.route('/download_log')
def download_log():
    log_path = '~/Elevate-Labs-Final-Projects/vuln_scanner/vulnerabilities.log'
    if os.path.exists(log_path):
        return send_file(log_path, as_attachment=True)
    return "Log file not found", 404

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5001)
