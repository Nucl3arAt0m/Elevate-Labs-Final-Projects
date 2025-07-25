import pandas as pd
import matplotlib.pyplot as plt

try:
    logs = pd.read_json('/home/sahil/Elevate-Labs-Final-Projects/honeypot/logs/cowrie.json', lines=True)
except ValueError:
    print("No JSON logs found.")
    exit(1)

login_attempts = logs[logs['eventid'].str.contains('cowrie.login')]
ip_counts = login_attempts['src_ip'].value_counts()
repeated_attempts = ip_counts[ip_counts > 3]
print("Repeated Login Attempts by IP:")
print(repeated_attempts)

with open('/home/sahil/Elevate-Labs-Final-Projects/honeypot/repeated_attempts.txt', 'w') as f:
    f.write(str(repeated_attempts))

plt.figure(figsize=(10, 5))
repeated_attempts.plot(kind='bar')
plt.title('Repeated Login Attempts by IP')
plt.xlabel('IP Address')
plt.ylabel('Number of Attempts')
plt.savefig('/home/sahil/Elevate-Labs-Final-Projects/screenshots/repeated_attempts_plot.png')
plt.close()
