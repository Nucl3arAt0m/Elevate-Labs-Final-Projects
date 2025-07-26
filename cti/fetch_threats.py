import requests
from pymongo import MongoClient
from datetime import datetime, timezone  # Keep timezone import

from config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY

client = MongoClient('mongodb://localhost:27017/')
db = client['cti_db']
threats = db['threats']

# Sample IOCs
iocs = [
    {'type': 'ip', 'value': '8.8.8.8'},
    {'type': 'ip', 'value': '185.230.125.9'},
    {'type': 'domain', 'value': 'example.com'}
]

def fetch_virustotal(ioc):
    if ioc['type'] == 'ip':
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ioc["value"]}'
    elif ioc['type'] == 'domain':
        url = f'https://www.virustotal.com/api/v3/domains/{ioc["value"]}'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            data['source'] = 'VirusTotal'
            data['timestamp'] = datetime.now(timezone.utc)  # Use timezone.utc
            data['ioc'] = ioc['value']
            data['ioc_type'] = ioc['type']
            threats.insert_one(data)
            print(f"VirusTotal: Stored {ioc['value']}")
    except Exception as e:
        print(f"VirusTotal: Error for {ioc['value']}: {e}")

def fetch_abuseipdb(ioc):
    if ioc['type'] != 'ip':
        return
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ioc['value'], 'maxAgeInDays': 90}
    headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
    try:
        response = requests.get(url, params=params, headers=headers)
        if response.status_code == 200:
            data = response.json()
            data['source'] = 'AbuseIPDB'
            data['timestamp'] = datetime.now(timezone.utc)  # Use timezone.utc
            data['ioc'] = ioc['value']
            data['ioc_type'] = ioc['type']
            threats.insert_one(data)
            print(f"AbuseIPDB: Stored {ioc['value']}")
    except Exception as e:
        print(f"AbuseIPDB: Error for {ioc['value']}: {e}")

for ioc in iocs:
    fetch_virustotal(ioc)
    fetch_abuseipdb(ioc)
