from flask import Flask, render_template, request, send_file
from pymongo import MongoClient
import pandas as pd
from fetch_threats import fetch_virustotal, fetch_abuseipdb

app = Flask(__name__)
client = MongoClient('mongodb://localhost:27017/')
db = client['cti_db']

@app.route('/', methods=['GET', 'POST'])
def dashboard():
    query_result = None
    if request.method == 'POST':
        ioc_value = request.form.get('ioc').strip()
        ioc_type = 'ip' if ioc_value.replace('.', '').isdigit() else 'domain'
        ioc = {'type': ioc_type, 'value': ioc_value}
        fetch_virustotal(ioc)
        if ioc_type == 'ip':
            fetch_abuseipdb(ioc)
        query_result = db.threats.find({'ioc': ioc_value}).limit(2)
    threats = db.threats.find().sort('timestamp', -1).limit(10)
    return render_template('dashboard.html', threats=threats, query_result=query_result)

@app.route('/tag/<ioc>/<tag>')
def add_tag(ioc, tag):
    db.threats.update_many({'ioc': ioc}, {'$addToSet': {'tags': tag}})
    return dashboard()

@app.route('/export')
def export():
    threats = db.threats.find()
    data = []
    for threat in threats:
        ip = threat.get('ioc', 'N/A')
        source = threat.get('source', 'N/A')
        score = (threat.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                 if source == 'VirusTotal' else
                 threat.get('data', {}).get('abuseConfidenceScore', 'N/A'))
        tags = ', '.join(threat.get('tags', []))
        data.append({'IOC': ip, 'Source': source, 'Score': score, 'Tags': tags})
    pd.DataFrame(data).to_csv('/home/nuclearatom/Elevate-Labs-Final-Projects/cti/threats_export.csv', index=False)
    return send_file('threats_export.csv', as_attachment=True)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
