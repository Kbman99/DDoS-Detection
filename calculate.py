from db import session, UniqueVictims, Victims
from sqlalchemy.sql import func

victim = session.query(UniqueVictims).first()
all_victims = session.query(UniqueVictims).all()

for victim in all_victims:
    ip = victim.ip
    victim.time_frame_count = session.query(Victims).filter_by(ip=ip).count()
    victim.rate = (victim.udp_count + victim.tcp_count + victim.icmp_count)/(victim.time_frame_count * 60)

session.commit()
