import datetime
import socket
import sys
import time
import os

import dpkt
from dpkt.compat import compat_ord

from attack import AttackEvents

from db import session
import db
from db import Victims, Timeframes

from sqlalchemy.exc import IntegrityError

from tqdm import tqdm


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

    def read_pcap(self):
        with open(self.filename, 'rb') as f:
            self.pcap = dpkt.pcapng.Reader(f)
            self.process_packets()

    def process_packets(self):
        # tq = tqdm(self.pcap, total=os.path.getsize(self.filename), unit='B')
        # buf_total = 0
        # for timestamp, buf in tq:
        for timestamp, buf in self.pcap:
            # print(len(buf))
            start = time.time()
            self.processed_data += sys.getsizeof(buf)
            self.check_time(timestamp)
            self.processed_packets += 1
            dst_ip, protocol = process_packets(self, buf, timestamp)
            if dst_ip is None or protocol is None:
                continue
            self.current_event.new_event(inet_to_str(dst_ip), protocol)
            # buf_total += len(buf)
            # tq.update(len(buf))

    def check_time(self, current_time):
        start = time.time()
        if self.next_event_frame == 0 or self.next_event_frame < current_time:
            if self.current_event:
                print("Processed data size: {}".format(self.processed_data))
                # Create check here to see if any DDoSes occurred
                self.current_event.filter_attacks(self)
                self.events.append(self.current_event)
                # for k, v in self.ddos_occurrences.items():
                #     for ddos in v:
                        # print(self.check_timer)
                        # print(self.print_timer)
                        # print("DDoS: {}".format(ddos.ip))
                        # print("UDP: {}  TCP: {}  ICMP: {}".format(ddos.udp_count, ddos.tcp_count, ddos.icmp_count))
                        # print("--------------------------------\n")
                # TODO: Add DDoS Occurences to database at current time
                self.add_ddos()
            self.next_event_frame = current_time + self.timeout
            start1 = time.time()
            self.current_event = AttackEvents(current_time)
            end1 = time.time()
            self.new_attack_timer += end1 - start1

        end = time.time()
        self.check_timer += end - start

    def add_ddos(self):
        """
        Adds the current time frame and all DDoS occurences for the given time frame to the database

        :return:
        """
        ddos_events = self.ddos_occurrences[self.current_event.start_time]
        ip_total, tcp_total, udp_total, icmp_total = self.totals(ddos_events)
        timeframe = Timeframes(timeframe=self.current_event.start_time, tcp=tcp_total,
                               udp=udp_total, icmp=icmp_total, ip=ip_total)
        if self.session.query(Timeframes).filter_by(timeframe=self.current_event.start_time).first():
            return
        else:
            try:
                self.session.add(timeframe)
                self.session.commit()
                attack_objects = []
                for ddos in ddos_events:
                    attack_objects.append(Victims(timeframe=self.current_event.start_time, ip=ddos.ip, tcp=ddos.tcp_count,
                                           udp=ddos.udp_count, icmp=ddos.icmp_count))
                self.session.bulk_save_objects(attack_objects)
                self.session.commit()
            except IntegrityError as e:
                print("Integrity Error occurred when inserting new timeframe or ddos objects")
                print("The keys already exist in the database")
                return

    def totals(self, ddoses):
        ip_total = tcp_total = udp_total = icmp_total = 0
        for ddos in ddoses:
            ip_total += 1
            tcp_total += ddos.tcp_count
            udp_total += ddos.udp_count
            icmp_total += ddos.icmp_count
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


def process_packets(processer, buf, timestamp):
    """Process and print out information about each packet in a pcap
       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """
    # For each packet in the pcap process the contents
    # Print out the timestamp in UTC
    start = time.time()
    # print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))

    # Unpack the Ethernet frame (mac src/dst, ethertype)
    eth = dpkt.ethernet.Ethernet(buf)
    # print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)

    # Make sure the Ethernet data contains an IP packet
    if not isinstance(eth.data, dpkt.ip.IP):
        print('Non IP Packet type not supported {}\n'.format(eth.data.__class__.__name__))
        return None, None

    # Now unpack the data within the Ethernet frame (the IP packet)
    # Pulling out src, dst, length, fragment info, TTL, and Protocol
    ip = eth.data

    # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
    # do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
    # more_fragments = bool(ip.off & dpkt.ip.IP_MF)
    # fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

    # Print out the info
    # print('IP: {} -> {}  (len={} ttl={} DF={} MF={} offset={})'.format
    #       (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl,
    #        do_not_fragment, more_fragments, fragment_offset))
    # print('IP: {} -> {}  )'.format(inet_to_str(ip.src), inet_to_str(ip.dst)))
    #
    # print('Protocol: {}\n'.format(ip.p))
    end = time.time()
    processer.print_timer += end - start
    return ip.dst, ip.p


def test():
    """Open up a test pcap file and print out the packets"""
    # with open('14.pcap', 'rb') as f:
    #     pcap = dpkt.pcapng.Reader(f)
    #     process_packets(pcap)
    pcap_processor = ProcessPcap('14.pcap')
    pcap_processor.read_pcap()


if __name__ == '__main__':
    test()
