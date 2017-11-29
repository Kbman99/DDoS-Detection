import socket
import sys
import time

import dpkt
from dpkt.compat import compat_ord

from attack import Events

from db import session
from db import Victims, Timeframes, UniqueVictims

from sqlalchemy.exc import IntegrityError


class ProcessPcap:
    def __init__(self, filename, timeout=60.000000):
        self.filename = filename
        self.session = session
        self.current_event = None
        self.next_event_frame = 0
        self.events = []
        self.timeout = timeout
        self.pcap = None
        self.ddos_occurrences = {}
        self.processed_packets = 0
        self.processed_data = 0
        self.print_timer = 0
        self.filter_timer = 0
        self.process_timer = 0
        self.check_timer = 0
        self.new_attack_timer = 0
        self.new_event_timer = 0
        self.main_timer = 0
        self.if_timer = 0

    def read_pcap(self):
        with open(self.filename, 'rb') as f:
            self.pcap = dpkt.pcapng.Reader(f)
            self.process_packets()

    def process_packets(self):
        for timestamp, buf in self.pcap:
            start = time.time()
            self.processed_data += sys.getsizeof(buf)
            self.check_time(timestamp)
            self.processed_packets += 1
            start1 = time.time()
            ip_dst, ip_src, data = process_packets(buf, timestamp)
            self.process_timer += time.time() - start1
            start3 = time.time()
            if ip_dst is None or ip_src is None or data is None:
                continue
            self.if_timer += time.time() - start3
            start2 = time.time()
            self.current_event.add_attack(ip_src, ip_dst, data)
            self.new_attack_timer += time.time() - start2
            self.main_timer += time.time() - start

    def check_time(self, current_time):
        start = time.time()
        if self.next_event_frame == 0 or self.next_event_frame < current_time:
            if self.current_event:
                print("Processed data size: {}".format(self.processed_data))
                # Create check here to see if any DDoSes occurred
                self.current_event.filter_attacks(self)
                self.db_add()
            self.next_event_frame = current_time + self.timeout
            start1 = time.time()
            # self.current_event = AttackEvents(current_time)
            self.current_event = Events(current_time)
            end1 = time.time()
            self.new_event_timer += end1 - start1

        end = time.time()
        self.check_timer += end - start

    def db_add(self):
        """
        Adds the current time frame and all DDoS occurences for the given time frame to the database

        :return:
        """
        time = self.current_event.start_time
        ddos_events = self.ddos_occurrences[time]
        ip_total, tcp_total, udp_total, icmp_total = self.totals(ddos_events)
        time_frame = Timeframes(time_frame=time, tcp=tcp_total,udp=udp_total, icmp=icmp_total,
                                ip=ip_total)
        if self.session.query(Timeframes).filter_by(time_frame=time).first():
            return
        else:
            try:
                self.session.add(time_frame)
                self.session.commit()
                # unique_victims = []
                victims = []
                for dst_ip, sources in ddos_events.items():
                    for source in sources:
                        if not self.session.query(UniqueVictims).filter_by(ip=source.src_ip).first():
                            # unique_victims.append(UniqueVictims(ip=source.src_ip))
                            session.add(UniqueVictims(ip=source.src_ip))
                            session.commit()
                        victims.append(Victims(ip=source.src_ip, tcp=source.tcp_count, udp=source.udp_count,
                                               icmp=source.icmp_count, time_frame=time))
                # session.bulk_save_objects(unique_victims)
                # session.commit()
                session.bulk_save_objects(victims)
                session.commit()
            except IntegrityError as e:
                print("Integrity Error occurred when inserting new timeframe or ddos objects")
                print("The keys already exist in the database")
                return

    def totals(self, ddoses):
        ip_total = tcp_total = udp_total = icmp_total = 0
        for k, sources in ddoses.items():
            for s in sources:
                tcp_total += s.tcp_count
                udp_total += s.udp_count
                icmp_total += s.icmp_count
                ip_total += 1
        return ip_total, tcp_total, udp_total, icmp_total


def mac_addr(address):
    """Convert a MAC address to a readable/printable string
       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)


def inet_to_str(inet):
    """Convert inet object to a string
        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def process_packets(buf, timestamp):
    """Process and print out information about each packet in a pcap
       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """
    eth = dpkt.ethernet.Ethernet(buf)
    # Make sure the Ethernet data contains an IP packet
    if not isinstance(eth.data, dpkt.ip.IP):
        print('Non IP Packet type not supported {}\n'.format(eth.data.__class__.__name__))
        return None, None, None

    # Now unpack the data within the Ethernet frame (the IP packet)
    # Pulling out src, dst, length, fragment info, TTL, and Protocol
    ip = eth.data
    data = ip.data
    # if isinstance(data, ICMP) and data.type is dpkt.icmp.ICMP_UNREACH_PORT:
    #     print("ISSA UDP ATTACK")
    return inet_to_str(ip.dst), inet_to_str(ip.src), data


def test():
    """Open up a test pcap file and print out the packets"""
    pcap_processor = ProcessPcap('14.pcap')
    pcap_processor.read_pcap()


if __name__ == '__main__':
    test()
