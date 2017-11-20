from sqlalchemy import create_engine, Column, BIGINT, Integer, String, ForeignKey
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


class Victims(DeclarativeBase):
    """Sqlalchemy victims model"""
    def __init__(self, ip, tcp, udp, icmp, timeframe):
        self.ip = ip
        self.tcp_count = tcp
        self.udp_count = udp
        self.icmp_count = icmp
        self.timeframe = timeframe

    __tablename__ = 'victims'

    ip = Column('ip', String, primary_key=True)
    tcp_count = Column('tcp_count', Integer, nullable=True, default=0)
    udp_count = Column('udp_count', Integer, nullable=True, default=0)
    icmp_count = Column('icmp_count', Integer, nullable=True, default=0)
    timeframe = Column('timeframe', BIGINT, ForeignKey("timeframes.timeframe"), primary_key=True)


# timeframe = Timeframes(timeframe=1245345234634, tcp_total=0, udp_total=0, icmp_total=0, ip_total=1)
# session.add(timeframe)
#
# session.commit()
#
# victim = Victims(ip='10.0.0.1', tcp_count=0, udp_count=0, icmp_count=0, timeframe=1245345234634)
# session.add(victim)
#
# session.commit()
# l = session.query(Timeframes).filter_by(timeframe=1385856000).first()
# input()