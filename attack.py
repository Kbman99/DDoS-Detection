from dpkt.udp import UDP
from dpkt.tcp import TCP
from dpkt.icmp import ICMP
import dpkt


class Events:
    """
    Stores attack events for a given timeframe
    """
    def __init__(self, timestamp):
        self.attacks = {}
        self.start_time = int(timestamp)

    def add_attack(self, src_ip, dst_ip, data):
        """
        Add Destination object to attacks dict

        :param src_ip: Source IP
        :param dst_ip: Destination IP
        :param data: Packet Data
        :return:
        """
        if dst_ip not in self.attacks:
            self.attacks[dst_ip] = Destination(dst_ip)
        self.attacks[dst_ip].add_src(src_ip, data)

    def filter_attacks(self, pcap_processor):
        """
        Filter through all events to find sources which have been DDoSed

        :param pcap_processor: Processor object for main program
        :return:
        """
        ddos_attacks = {}
        for dst_ip, dest in self.attacks.items():
                for src_ip, src in dest.sources.items():
                    if src.infer_ddos():
                        if src_ip not in ddos_attacks:
                            ddos_attacks[src_ip] = [src]
                        else:
                            ddos_attacks[src_ip].append(src)
        pcap_processor.ddos_occurrences[self.start_time] = ddos_attacks


class Destination:
    """
    Represents the destination IP of a given packet, where the source IP
    of the respective packet is stored in the dictionary for checking
    """
    def __init__(self, ip):
        self.dest_ip = ip
        self.sources = {}

    def add_src(self, src_ip, data):
        if src_ip not in self.sources:
            self.sources[src_ip] = Source(src_ip)
        self.sources[src_ip].detect_protocol(data)


class Source:
    def __init__(self, ip):
        self.src_ip = ip
        self.udp_count = 0
        self.tcp_count = 0
        self.icmp_count = 0

    def udp(self):
        self.udp_count += 1

    def tcp(self):
        self.tcp_count += 1

    def icmp(self):
        self.icmp_count += 1

    def detect_protocol(self, data):
        if isinstance(data, TCP):
            self.tcp()
        elif isinstance(data, ICMP):
            if data.type is dpkt.icmp.ICMP_UNREACH_PORT:
                self.udp()
            else:
                self.icmp()
        elif isinstance(data, UDP):
            self.udp()

    def infer_ddos(self):
        if self.icmp_count >= 10 or self.udp_count >= 10 or self.tcp_count >= 10:
            return self
        else:
            return None


class Attack:
    """
    Holds info for each unique IP address in a given timeframe
    """
    def __init__(self, ip):
        self.ip = ip
        self.udp_count = 0
        self.tcp_count = 0
        self.icmp_count = 0

    def udp(self):
        self.udp_count += 1

    def tcp(self):
        self.tcp_count += 1

    def icmp(self):
        self.icmp_count += 1

    def infer_ddos(self):
        if self.icmp_count >= 10 or self.udp_count >10 or self.tcp_count >= 10:
            return self
        else:
            return None


class AttackEvents:
    """
    Stores attack events for a given timeframe
    """
    def __init__(self, timestamp):
        self.attacks = {}
        self.start_time = int(timestamp)

    def new_event(self, src_ip, protocol):
        if protocol == 6:
            if src_ip not in self.attacks:
                self.attacks[src_ip] = Attack(src_ip)
            self.attacks[src_ip].tcp()
        elif protocol == 17:
            if src_ip not in self.attacks:
                self.attacks[src_ip] = Attack(src_ip)
            self.attacks[src_ip].udp()
        elif protocol == 58 or protocol == 1:
            if src_ip not in self.attacks:
                self.attacks[src_ip] = Attack(src_ip)
            self.attacks[src_ip].icmp()

    def filter_attacks(self, pcap_processor):
        ddos_attacks = []
        for k, v in self.attacks.items():
            if v.infer_ddos():
                ddos_attacks.append(v)
        pcap_processor.ddos_occurrences[int(self.start_time)] = ddos_attacks
