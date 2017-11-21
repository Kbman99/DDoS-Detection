from db import session, UniqueVictims
import maxminddb

reader = maxminddb.open_database('GeoLite2-City.mmdb')

unique_ips = session.query(UniqueVictims).all()

for ip in unique_ips:
    current_ip = reader.get(ip.ip)['location']
    ip.lat = current_ip['latitude']
    ip.long = current_ip['longitude']

session.commit()
