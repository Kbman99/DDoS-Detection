from db import session, UniqueVictims
import maxminddb

reader = maxminddb.open_database('GeoLite2-City.mmdb')
asn = maxminddb.open_database('GeoLite2-ASN.mmdb')

unique_ips = session.query(UniqueVictims).all()

for ip in unique_ips:
    try:
        current_ip = reader.get(ip.ip)
        asn_ip = asn.get(ip.ip)
        if 'city' in current_ip:
            ip.city = current_ip['city']['names']['en']
        if 'country' in current_ip:
            ip.country = current_ip['country']['names']['en']
        if asn_ip:
            ip.isp = asn_ip['autonomous_system_organization']
    except TypeError:
        continue

session.commit()
