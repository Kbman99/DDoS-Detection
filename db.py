from sqlalchemy import create_engine, Column, BIGINT, Integer, String, ForeignKey, Numeric
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.engine.url import URL
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import func

import config

DeclarativeBase = declarative_base()

engine = create_engine(URL(**config.DATABASE))
Session = sessionmaker(bind=engine)
session = Session()


# class SessionManager:
#     def __init__(self):
#         self.session = Session()


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
    def __init__(self, timeframe, tcp, udp, icmp, ip):
        self.timeframe = timeframe
        self.tcp_total = tcp
        self.udp_total = udp
        self.icmp_total = icmp
        self.ip_total = ip

    __tablename__ = 'timeframes'

    timeframe = Column('timeframe', BIGINT, primary_key=True)
    tcp_total = Column('tcp_total', Integer, nullable=True, default=0)
    udp_total = Column('udp_total', Integer, nullable=True, default=0)
    icmp_total = Column('icmp_total', Integer, nullable=True, default=0)
    ip_total = Column('ip_total', Integer, nullable=True, default=0)


class UniqueVictims(DeclarativeBase):
    """Sqlalchemy unique victims model"""
    def __init__(self, ip, lat, long):
        self.ip = ip
        self.lat = lat
        self.long = long

    __tablename__ = 'uniquevictims'

    ip = Column('ip', String, primary_key=True)
    lat = Column('lat', Numeric(10, 6), default=0)
    long = Column('long', Numeric(10, 6), default=0)


class Victims(DeclarativeBase):
    """Sqlalchemy victims model"""
    def __init__(self, ip, tcp, udp, icmp, timeframe):
        self.ip = ip
        self.tcp_count = tcp
        self.udp_count = udp
        self.icmp_count = icmp
        self.timeframe = timeframe

    __tablename__ = 'victims'

    ip = Column('ip', String, ForeignKey("uniquevictims.ip"), primary_key=True)
    tcp_count = Column('tcp_count', Integer, nullable=True, default=0)
    udp_count = Column('udp_count', Integer, nullable=True, default=0)
    icmp_count = Column('icmp_count', Integer, nullable=True, default=0)
    timeframe = Column('timeframe', BIGINT, ForeignKey("timeframes.timeframe"), primary_key=True)


class UniqueLocation(DeclarativeBase):
    """Sqlalchemy Unique Location models"""
    def __init__(self, lat, long, ip_count, tcp_count, udp_count, icmp_count):
        self.lat = lat
        self.long = long
        self.ip_count = ip_count
        self.tcp_count = tcp_count
        self.udp_count = udp_count
        self.icmp_count = icmp_count

    __tablename__ = 'unique_location'

    lat = Column('lat', Numeric(10, 6), primary_key=True)
    long = Column('long', Numeric(10, 6), primary_key=True)
    ip_count = Column('ip_count', Integer)
    tcp_count = Column('tcp_count', Integer)
    udp_count = Column('udp_count', Integer)
    icmp_count = Column('icmp_count', Integer)

l = session.query(Timeframes).all()

for i in l:
    print(i)
# query = session.query(UniqueVictims.lat, UniqueVictims.long).distinct().all()
# unique_loc = []
# count = 0
# for q in query:
#     victims = session.query(UniqueVictims).filter_by(lat=q.lat, long=q.long).all()
#     tcp_total = udp_total = icmp_total = 0
#     ip_count = len(victims)
#     for victim in victims:
#         # totals = session.query(Victims.ip).label('sum').filter_by(ip=victim.ip).all()
#         tcp_total += session.query(func.sum(Victims.tcp_count).filter(Victims.ip == victim.ip)).scalar()
#         udp_total += session.query(func.sum(Victims.udp_count).filter(Victims.ip == victim.ip)).scalar()
#         icmp_total += session.query(func.sum(Victims.icmp_count).filter(Victims.ip == victim.ip)).scalar()
#     unique_loc.append(UniqueLocation(q.lat, q.long, ip_count, tcp_total, udp_total, icmp_total))
#     count += 1
#     print("Done with {}".format(count))
#
# session.bulk_save_objects(unique_loc)
# session.commit()
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

