import pandas as pd
import matplotlib.pyplot as plt
import geoip2.database

try:
    logs = pd.read_json('/home/sahil/Elevate-Labs-Final-Projects/honeypot/logs/cowrie.json', lines=True)
except ValueError:
    print("No JSON logs found.")
    exit(1)

ip_list = logs['src_ip'].unique()
reader = geoip2.database.Reader('/home/sahil/Elevate-Labs-Final-Projects/honeypot/GeoLite2-City.mmdb')
countries = []
for ip in ip_list:
    try:
        if ip not in ['127.0.0.1', '10.0.2.2']:
            country = reader.city(ip).country.name
        else:
            country = 'Local'
        countries.append(country)
    except:
        countries.append('Unknown')

country_counts = pd.Series(countries).value_counts()
country_counts.to_csv('/home/sahil/Elevate-Labs-Final-Projects/honeypot/geolocation_data.csv')

plt.figure(figsize=(10, 5))
country_counts.plot(kind='bar')
plt.title('Attacker IP Geolocation')
plt.xlabel('Country')
plt.ylabel('Number of Attempts')
plt.savefig('/home/sahil/Elevate-Labs-Final-Projects/screenshots/geolocation_plot.png')
plt.close()
