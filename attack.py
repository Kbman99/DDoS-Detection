class Attacker:
    """

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
        if self.icmp_count + self.udp_count + self.tcp_count >= 10:
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
        if self.icmp_count + self.udp_count + self.tcp_count >= 10:
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
