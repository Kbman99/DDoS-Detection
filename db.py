from sqlalchemy import create_engine, Column, BIGINT, Integer, \
    String, ForeignKey, Numeric, Sequence
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.engine.url import URL
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import func

import config

DeclarativeBase = declarative_base()

engine = create_engine(URL(**config.DATABASE))
Session = sessionmaker(bind=engine)
session = Session()


def create_tables(engine):
    """"""
    DeclarativeBase.metadata.create_all(engine)


def create_timeframe(**args):
    # Pass in process.current_event.start_time
    return Timeframes(*args)


def create_victim(**args):
    return Victims(*args)


def add_table(session):
    session.add()


class Timeframes(DeclarativeBase):
    """Sqlalchemy timeframes model"""
    def __init__(self, time_frame, tcp, udp, icmp, ip):
        self.time_frame = int(time_frame)
        self.tcp_total = tcp
        self.udp_total = udp
        self.icmp_total = icmp
        self.ip_total = ip

    __tablename__ = 'time_frames'

    time_frame = Column('time_frame', BIGINT, primary_key=True)
    tcp_total = Column('tcp_total', Integer, nullable=True, default=0)
    udp_total = Column('udp_total', Integer, nullable=True, default=0)
    icmp_total = Column('icmp_total', Integer, nullable=True, default=0)
    ip_total = Column('ip_total', Integer, nullable=True, default=0)


class UniqueVictims(DeclarativeBase):
    """Sqlalchemy unique victims model"""
    def __init__(self, ip, lat=0, long=0):
        self.ip = ip
        self.lat = lat
        self.long = long
        self.udp_count = 0
        self.tcp_count = 0
        self.icmp_count = 0
        self.timeframe_count = 0
        self.rate = 0
        self.city = None
        self.country = None
        self.isp = None

    __tablename__ = 'unique_victims'

    ip = Column('ip', String, primary_key=True)
    lat = Column('lat', Numeric(10, 6), default=0)
    long = Column('long', Numeric(10, 6), default=0)
    udp_count = Column('udp_count', Integer, default=0)
    tcp_count = Column('tcp_count', Integer, default=0)
    icmp_count = Column('icmp_count', Integer, default=0)
    time_frame_count = Column('time_frame_count', Integer, default=0)
    rate = Column('rate', Numeric(10, 2), default=0)
    city = Column('city', String)
    country = Column('country', String)
    isp = Column('isp', String)


class Victims(DeclarativeBase):
    """Sqlalchemy victims model"""
    def __init__(self, ip, tcp, udp, icmp, time_frame):
        self.ip = ip
        self.tcp_count = tcp
        self.udp_count = udp
        self.icmp_count = icmp
        self.time_frame = time_frame

    __tablename__ = 'victims'

    id = Column(Integer, autoincrement=True, primary_key=True)
    ip = Column('ip', String, ForeignKey("unique_victims.ip", onupdate="CASCADE", ondelete="CASCADE"), primary_key=True)
    tcp_count = Column('tcp_count', Integer, nullable=True, default=0)
    udp_count = Column('udp_count', Integer, nullable=True, default=0)
    icmp_count = Column('icmp_count', Integer, nullable=True, default=0)
    time_frame = Column('time_frame', BIGINT, ForeignKey("time_frames.time_frame"), primary_key=True)

# DeclarativeBase.metadata.create_all(bind=engine)
# DeclarativeBase.metadata.create_all(bind=engine)
# DeclarativeBase.metadata.tables['victims'].create(bind=engine)
# session.commit()
# class UniqueLocation(DeclarativeBase):
#     """Sqlalchemy Unique Location models"""
#     def __init__(self, lat, long, ip_count, tcp_count, udp_count, icmp_count):
#         self.lat = lat
#         self.long = long
#         self.ip_count = ip_count
#         self.tcp_count = tcp_count
#         self.udp_count = udp_count
#         self.icmp_count = icmp_count
#
#     __tablename__ = 'unique_location'
#
#     lat = Column('lat', Numeric(10, 6), primary_key=True)
#     long = Column('long', Numeric(10, 6), primary_key=True)
#     ip_count = Column('ip_count', Integer)
#     tcp_count = Column('tcp_count', Integer)
#     udp_count = Column('udp_count', Integer)
#     icmp_count = Column('icmp_count', Integer)


# query = session.query(UniqueVictims).all()
# unique_ = []
# count = 0
# for q in query:
#     victims = session.query(Victims).all()
#     tcp_total = udp_total = icmp_total = 0
#     ip_count = len(victims)
#     for victim in victims:
#         # totals = session.query(Victims.ip).label('sum').filter_by(ip=victim.ip).all()
#         tcp_total += session.query(func.sum(Victims.tcp_count).filter(Victims.ip == victim.ip)).scalar()
#         udp_total += session.query(func.sum(Victims.udp_count).filter(Victims.ip == victim.ip)).scalar()
#         icmp_total += session.query(func.sum(Victims.icmp_count).filter(Victims.ip == victim.ip)).scalar()
#     count += 1
#     print("Done with {}".format(count))
#
# session.bulk_save_objects(unique_loc)
# session.commit()

# unique_victims = session.query(UniqueVictims).all()
#
# for v in unique_victims:
#     current_victim = v
#     v_ip = current_victim.ip
#     unique_victims = session.query(Victims).filter_by(ip=v_ip).all()
#     v.time_frame_count = session.query(func.count(Victims).filter(Victims.ip == v_ip)).scalar()
#     v.tcp_total += session.query(func.sum(Victims.tcp_count).filter(Victims.ip == v_ip)).scalar()
#     v.udp_total += session.query(func.sum(Victims.udp_count).filter(Victims.ip == v_ip)).scalar()
#     v.icmp_total += session.query(func.sum(Victims.icmp_count).filter(Victims.ip == v_ip)).scalar()
#

# q = session.query(Victims.ip.distinct().label("ip"))
#
# ips = [row.ip for row in q.all()]
#
# unique_victims = []
#
# # try:
# #     DeclarativeBase.metadata.tables["uniquevictims"].create(bind=engine)
# # except Exception as e:
# #     print("woops")
#
# for ip in ips:
#     unique_victims.append(UniqueVictims(ip=ip, lat=0, long=0))
#
# session.bulk_save_objects(unique_victims)
# session.commit()

