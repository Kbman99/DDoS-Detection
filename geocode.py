from db import session, UniqueVictims
import maxminddb


def maxmind_geocode():
    """
    Fill in all location details using maxminddb including the latitude, longitude,
    city, country and ISP of the victim

    :return:
    """
    reader = maxminddb.open_database('GeoLite2-City.mmdb')
    asn = maxminddb.open_database('GeoLite2-ASN.mmdb')

    unique_ips = session.query(UniqueVictims).all()

    for ip in unique_ips:
        try:
            current_ip = reader.get(ip.ip)
            asn_ip = asn.get(ip.ip)
            ip.lat = current_ip['location']['latitude']
            ip.long = current_ip['location']['longitude']
            if 'city' in current_ip:
                ip.city = current_ip['city']['names']['en']
            if 'country' in current_ip:
                ip.country = current_ip['country']['names']['en']
            if asn_ip:
                ip.isp = asn_ip['autonomous_system_organization']
        except TypeError:
            continue
    session.commit()


if __name__ == '__main__':
    maxmind_geocode()
