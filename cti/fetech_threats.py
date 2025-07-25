import pandas as pd
import requests
from pymongo import MongoClient
from cti.config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY
import time

# Connect to MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['cti_db']
threats_collection = db['threats']

# Load honeypot IPs
try:
    logs = pd.read_json('/home/sahil/Elevate-Labs-Final-Projects/honeypot/logs/cowrie.json', lines=True)
    ip_list = logs['src_ip'].unique()
except ValueError:
    print("No honeypot logs found.")
    ip_list = ['8.8.8.8', '185.230.125.9', '203.0.113.1']  # Mock IPs from Project 14

# Fetch VirusTotal data
for ip in ip_list:
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            threats_collection.insert_one({'source': 'virustotal', 'ip': ip, 'data': response.json()})
        else:
            print(f"VirusTotal failed for {ip}: {response.status_code}")
    except Exception as e:
        print(f"Error querying VirusTotal for {ip}: {e}")
    time.sleep(15)  # Respect rate limit (4/min)

# Fetch AbuseIPDB data
for ip in ip_list:
    url = f'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip, 'maxAgeInDays': 90}
    headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
    try:
        response = requests.get(url, params=params, headers=headers)
        if response.status_code == 200:
            threats_collection.insert_one({'source': 'abuseipdb', 'ip': ip, 'data': response.json()})
        else:
            print(f"AbuseIPDB failed for {ip}: {response.status_code}")
    except Exception as e:
        print(f"Error querying AbuseIPDB for {ip}: {e}")
    time.sleep(0.1)  # Respect rate limit
