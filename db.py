from sqlalchemy import create_engine, Column, BIGINT, Integer, String, ForeignKey, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.engine.url import URL
from sqlalchemy.orm import sessionmaker

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
    lat = Column('lat', Float(6), default=0)
    long = Column('long', Float(6), default=0)


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

