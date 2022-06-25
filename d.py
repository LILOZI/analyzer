from scapy.all import *
from time import sleep
from scapy.layers.inet import *
from scapy.layers.http import HTTPResponse
import webbrowser
import os



target_ip = "10.0.0.17"
dst_ip = '10.0.0.20'
target_port = 5000

ip = IP(src='10.0.0.20', dst=target_ip)

tcp = TCP(sport=80, dport=80, flags="S", seq=RandShort(), ack=0)

p = ip / tcp

send(p, count=1, verbose=0)

SYN = 0X02
ACK = 0X10

pkt = sniff(lfilter=lambda x: x.haslayer(TCP) and x[TCP].flags & SYN and x[TCP].flags & ACK, count=1)

tcp = TCP(sport=80, dport=80, flags="A", seq=pkt[0][TCP].ack, ack=pkt[0][TCP].seq + 1)

p2 = ip / tcp

send(p2, count=1, verbose=0)
sleep(1)
getStr = 'GET / HTTP/1.1\r\nHost: 10.0.0.17\r\n\r\n'
request = IP(dst='10.0.0.17') / TCP(dport=80, sport=pkt[0][TCP].dport,
                                    seq=pkt[0][TCP].ack, ack=pkt[0][TCP].seq + 1, flags='A') / getStr

send(request, count=1, verbose=1)

htm = sniff(filter=f'src host {target_ip} and dst host {dst_ip}', count=1)

f = open('hey.html', 'w')

f.write(str(htm[0][Raw]))

b = 'file:///'+os.getcwd()+'/'+'hey.html'
webbrowser.open_new_tab(b)

