from scapy.all import *
from scapy.layers.inet import *
from pyfiglet import *
from termcolor import colored
from scapy.layers.http import HTTPRequest
import os


def write_to_file(mac, num_pkt, ban_status):
    flag = 0
    index = 0
    f = open('LoginHistory.txt', 'r')
    text = f.readlines()

    for line in text:
        index += 1
        if mac in line:
            flag = 1
            break
    if flag == 1:
        text[index - 1] = f'{mac}   {num_pkt}          {ban_status}\n'
    else:
        text.append(f'{mac}   {num_pkt}          {ban_status}\n')
    with open('LoginHistory.txt', 'w') as file:
        file.writelines(text)
    return


def read_from_file(dic):
    if os.stat('LoginHistory.txt').st_size == 0:
        return dic

    with open('LoginHistory.txt', 'r') as file:
        text = file.readlines()
        for line in text:
            words = line.split()
            mac = words[0]
            try:
                num_pkt = int(words[1])
            except ValueError:
                num_pkt = words[1].replace("'", "")
            ban_status = words[2] == 'True'
            dic[mac] = [num_pkt, ban_status]

    return dic


def sniff_http():
    s = sniff(lfilter=lambda x: x.haslayer(HTTPRequest), prn=lambda y: y.summary(), count=1)
    return s


#  Sniff the http packet from the users who made the three-way handshake


def send_http(pkt):
    html = "HTTP/1.1 200 OK\r\n"
    html += "Server: 10.0.0.17\r\n"
    html += "Content-Length: 70\r\n"
    html += "\r\n"
    html += '<html> <head>Hello</head> <body> <p>Hello hello :)</p> </body> </html>'

    an = IP(src="10.0.0.17", dst=pkt[0][IP].src) / TCP(sport=80, dport=80, flags="A", seq=pkt[0][TCP].ack + 1,
                                                       ack=pkt[0][TCP].seq) / html
    send(an, count=1)

    return


# Send http response packet to the client


def check_banned():
    syn = 0x02
    ack = 0x10
    src_ip = '10.0.0.17'
    tcp = TCP(sport=80, dport=80, flags="S", seq=RandShort(), ack=0)
    for banned in dic.items():
        if banned[1][1] is True:
            ip = IP(src=src_ip, dst=banned[0])
            p = ip / tcp
            send(p, count=1, verbose=0)

            an = sniff(lfilter=lambda x: x.haslayer(TCP) and x[TCP].flags & syn and x[TCP].flags & ack, count=1,
                       timeout=1.5)
            try:
                if an[0].summary() is None:
                    pass
                # If ack_pkt is None an Error will happen, if it is not None then the client answered us.
                else:
                    tcp = TCP(sport=5000, dport=RandShort(), flags="A", seq=an[0][TCP].ack, ack=an[0][TCP].seq + 1)
                    p2 = ip / tcp / raw
                    send(p2, count=1, verbose=0)

            except IndexError:
                if an.summary() is None:
                    pass
                    # DIDN'T ANSWERED STAYS BANNED
            finally:
                # After both situations print
                print_log()

    return


# After a certain amount of time allow the banned client send another packet/ send one to him

# Sending SA packets to check if the client answers


def send_sa(pkt):
    src_ip = '10.0.0.17'
    ip = IP(src=src_ip, dst=pkt[0][IP].src)
    tcp = TCP(dport=80, sport=80, flags='SA', ack=pkt[0][TCP].seq + 1, seq=RandShort())
    p = ip / tcp
    send(p, count=3, verbose=0)

    return


# Prints
def print_log():
    dic_items = dic.items()
    os.system('cls')
    result = figlet_format("Packets Analyzer")
    print(colored(result, "blue"))

    print(" " * 7, colored('Mac', 'yellow'), " " * 9, colored('Packets', 'magenta'), " " * 5, colored('Banned', 'red'))
    for item in dic_items:
        mac = item[0]
        num_pkt = item[1][0]
        ban_status = item[1][1]
        if ban_status is False:
            print(colored(f'{mac}', 'yellow'), " " * 3, colored(f'{num_pkt}', "magenta"), " " * 10,
                  colored('No', 'green'))
        else:
            print(colored(f'{mac}', 'yellow'), " " * 3, colored(f'{num_pkt}', "magenta"), " " * 10,
                  colored('Yes', 'red'))
        write_to_file(mac, num_pkt, ban_status)
    return


def analyzer():
    global dic

    syn = 0x02
    ack = 0x10
    # Sniff the first Syn packet
    syn_pkt = sniff(lfilter=lambda x: x.haslayer(TCP) and x[TCP].flags & syn,
                    count=1, filter=f'dst host 10.0.0.17')

    # Checks if the Syn packet came from a banned computer
    if syn_pkt[0][TCP].flags == 'S' and syn_pkt[0][Ether].src in dic and dic[syn_pkt[0][Ether].src][1] is False:

        # Sends packet and waits for an answer
        send_sa(syn_pkt)
        ack_pkt = sniff(lfilter=lambda x: x.haslayer(TCP) and x[TCP].flags & ack,
                        filter=f'src host {syn_pkt[0][IP].src}', count=1, timeout=1.5)

        # If the timeout function is activated ack_pkt equals None
        try:
            if ack_pkt[0].summary() is None and syn_pkt[0][Ether].src in dic:
                pass
            else:
                req = sniff_http()
                send_http(req)
                return
            # If it is None an Error will happen, if it is not None then the client answered us, so we don't need to
            # do anything.
        except IndexError:

            if ack_pkt.summary() is None and syn_pkt[0][Ether].src in dic:
                dic[syn_pkt[0][Ether].src][0] += 1

                if dic[syn_pkt[0][Ether].src][0] == 5:
                    dic[syn_pkt[0][Ether].src] = ['5++', True]
                # Print only if the client didn't answer, if he answered nothing changed and there is no need to print
        finally:
            print_log()

    # If the mac address is not in the dictionary we want to set there, we wait until we know if he answered or not
    # to set the first value.
    if syn_pkt[0][TCP].flags == 'S' and syn_pkt[0][Ether].src not in dic:
        send_sa(syn_pkt)

        ack_pkt = sniff(lfilter=lambda x: x.haslayer(TCP) and x[TCP].flags & ack,
                        filter=f'src host {syn_pkt[0][IP].src}', count=1, timeout=1.5)

        try:
            if ack_pkt[0].summary() is None and syn_pkt[0][Ether].src not in dic:
                pass
            # If ack_pkt is None an Error will happen, if it is not None then the client answered us.
            # Because the mac address is not in the dictionary we will add it with 0 as his value because he answered.
            else:
                dic[syn_pkt[0][Ether].src] = [0, False]

        except IndexError:
            if ack_pkt.summary() is None and syn_pkt[0][Ether].src not in dic:
                dic[syn_pkt[0][Ether].src] = [1, False]
        finally:
            # After both situations print
            print_log()


dic = {}
dic = read_from_file(dic)
print_log()
while True:
    analyzer()
