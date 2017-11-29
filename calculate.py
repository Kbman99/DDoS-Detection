from db import session, UniqueVictims, Victims
from sqlalchemy.sql import func


def calc_totals():
    """
    Calculate the total time frame the IP appears in and the udp/tcp/icmp packet
    count as well as the packets/s rate
    :return:
    """
    all_victims = session.query(UniqueVictims).all()

    for victim in all_victims:
        ip = victim.ip
        victim.time_frame_count = session.query(Victims).filter_by(ip=ip).count()
        victim.tcp_count = session.query(func.sum(Victims.tcp_count).filter(Victims.ip == ip)).scalar()
        victim.udp_count = session.query(func.sum(Victims.udp_count).filter(Victims.ip == ip)).scalar()
        victim.icmp_count = session.query(func.sum(Victims.icmp_count).filter(Victims.ip == ip)).scalar()
        victim.rate = (victim.udp_count + victim.tcp_count + victim.icmp_count)/(victim.time_frame_count * 60)

    session.commit()


if __name__ == '__main__':
    calc_totals()
