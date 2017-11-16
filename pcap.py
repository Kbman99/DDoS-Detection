import os
import dpkt


print(os.getcwd())

f = open('14.pcap', 'rb')
p = dpkt.pcapng.Reader(f)

for ts, buf in p:
    print(ts, len(buf))
