from pymongo import MongoClient
import matplotlib.pyplot as plt
from datetime import datetime, timezone
import seaborn as sns

sns.set(style="whitegrid")

client = MongoClient('mongodb://localhost:27017/')
db = client['cti_db']
threats = db.threats.find().sort('timestamp', 1)

vt_dates = []
vt_scores = []
vt_labels = []
abuse_dates = []
abuse_scores = []
abuse_labels = []

for threat in threats:
    timestamp = threat.get('timestamp', datetime.now(timezone.utc))
    if threat.get('source') == 'VirusTotal':
        score = threat.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
        score = min(score * 10, 100)
        vt_dates.append(timestamp)
        vt_scores.append(score)
        vt_labels.append(threat.get('ioc', 'N/A'))
    elif threat.get('source') == 'AbuseIPDB':
        score = threat.get('data', {}).get('abuseConfidenceScore', 0)
        abuse_dates.append(timestamp)
        abuse_scores.append(score)
        abuse_labels.append(threat.get('ioc', 'N/A'))

plt.figure(figsize=(8, 4))
if vt_dates:
    plt.plot(vt_dates, vt_scores, color='blue', label='VirusTotal', linewidth=2)
    for i, (date, score, label) in enumerate(zip(vt_dates, vt_scores, vt_labels)):
        y_offset = 5 if i % 2 == 0 else -5
        plt.text(date, score + y_offset, label, fontsize=8, ha='center', va='center')
if abuse_dates:
    plt.plot(abuse_dates, abuse_scores, color='red', label='AbuseIPDB', linewidth=2)
    for i, (date, score, label) in enumerate(zip(abuse_dates, abuse_scores, abuse_labels)):
        y_offset = 5 if i % 2 == 0 else -5
        plt.text(date, score + y_offset, label, fontsize=8, ha='center', va='center')

plt.title('Threat Scores Over Time', fontsize=12, pad=15)
plt.xlabel('Timestamp', fontsize=10)
plt.ylabel('Normalized Score (0-100)', fontsize=10)
plt.xticks(rotation=45, ha='right', fontsize=8)
plt.yticks(fontsize=8)
plt.legend(title='Source', fontsize=8)
plt.tight_layout()
plt.savefig('/home/nuclearatom/Elevate-Labs-Final-Projects/cti/static/threat_plot.png', dpi=150)
plt.close()
