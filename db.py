from sqlalchemy import create_engine, Column, BIGINT, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.engine.url import URL
from sqlalchemy.orm import Session

import config

DeclarativeBase = declarative_base()


def db_connect():
    """
    Performs database connection using database settings from config.py.
    Returns sqlalchemy engine instance
    """
    return create_engine(URL(**config.DATABASE))


def create_tables(engine):
    """"""
    DeclarativeBase.metadata.create_all(engine)


class Timeframes(DeclarativeBase):
    """Sqlalchemy timeframes model"""
    __tablename__ = 'timeframes'

    timeframe = Column('timeframe', BIGINT, primary_key=True)
    tcp_total = Column('tcp_total', Integer, nullable=True)
    udp_total = Column('udp_total', Integer, nullable=True)
    icmp_total = Column('icmp_total', Integer, nullable=True)
    ip_total = Column('ip_total', Integer, nullable=True)


class Victims(DeclarativeBase):
    """Sqlalchemy victims model"""
    __tablename__ = 'victims'

    ip = Column('ip', String, primary_key=True)
    tcp_count = Column('tcp_count', Integer, nullable=True)
    udp_count = Column('udp_count', Integer, nullable=True)
    icmp_count = Column('icmp_count', Integer, nullable=True)
    timeframe = Column('timeframe', BIGINT, ForeignKey("timeframes.timeframe"), primary_key=True)


db = db_connect()

session = Session(bind=db)

# timeframe = Timeframes(timeframe=1245345234634, tcp_total=0, udp_total=0, icmp_total=0, ip_total=1)
# session.add(timeframe)
#
# session.commit()
#
# victim = Victims(ip='10.0.0.1', tcp_count=0, udp_count=0, icmp_count=0, timeframe=1245345234634)
# session.add(victim)
#
# session.commit()
for v in session.query(Timeframes):
    session.delete(v)
session.commit()
