from scapy.all import *
from scapy.layers.inet import *
from pyfiglet import *
from termcolor import colored
from scapy.layers.http import HTTPRequest
import os


# Write the history of the mac addresses to a file.
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


# Read the history of the mac addresses from a file.
def read_from_file():
    data = {}
    if os.stat('LoginHistory.txt').st_size == 0:
        return data

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
            data[mac] = [num_pkt, ban_status]

    return data


#  Sniff the http packet from the users who made the three-way handshake
def sniff_http(pkt):
    s = sniff(lfilter=lambda x: x.haslayer(HTTPRequest), filter=f'src host {pkt[0][IP].src}', count=1)
    return s


# Send http response packet to the client


def send_http(pkt):
    html = "HTTP/1.1 200 OK\r\n"
    html += "Server: 10.60.1.91\r\n"
    html += "Content-Length: 70\r\n"
    html += "\r\n"
    html += '<html> <head>Hello</head> <body> <p>Hello hello :)</p> </body> </html>'

    an = IP(src="10.60.1.91", dst=pkt[0][IP].src) / TCP(sport=80, dport=80, flags="FA", seq=pkt[0][TCP].ack + 1,
                                                       ack=pkt[0][TCP].seq) / html
    send(an, count=1)

    return


# Try to create a connection with the banned addresses and if they answer remove them from the banned list

def check_banned():
    syn = 0x02
    ack = 0x10
    src_ip = '10.60.1.91'
    tcp = TCP(sport=80, dport=80, flags="S", seq=RandShort(), ack=0)
    for banned in banned_dic.items():
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
                valid_dic[banned] = [3, False]
                banned_dic.pop(banned)

        except IndexError:
            if an.summary() is None:
                pass
                # DIDN'T ANSWERED STAYS BANNED
        finally:
            # After both situations print
            print_log()

    return


# Prints and update the file.
def print_log():
    ban_items = banned_dic.items()
    val_items = valid_dic.items()
    os.system('cls')
    result = figlet_format("Packets Analyzer")
    print(colored(result, "blue"))

    print(" " * 7, colored('Mac', 'yellow'), " " * 9, colored('Packets', 'magenta'), " " * 5, colored('Banned', 'red'))
    for item in val_items:
        mac = item[0]
        num_pkt = item[1][0]
        print(colored(f'{mac}', 'yellow'), " " * 3, colored(f'{num_pkt}', "magenta"), " " * 10,
              colored('No', 'green'))
        write_to_file(mac, num_pkt, False)

    for item in ban_items:
        mac = item[0]
        num_pkt = item[1][0]
        print(colored(f'{mac}', 'yellow'), " " * 3, colored(f'{num_pkt}', "magenta"), " " * 10,
              colored('Yes', 'red'))
        write_to_file(mac, num_pkt, True)

    return


def sniff_syn():
    syn = 0x02

    # Sniff the first Syn packet
    syn_pkt = sniff(lfilter=lambda x: x.haslayer(TCP) and x[TCP].flags & syn and x[Ether].src not in banned_dic,
                    count=1, filter=f'dst host 10.60.1.91')
    return syn_pkt


# Sending SA packets to check if the client answers


def send_sa(pkt):
    src_ip = '10.60.1.91'
    ip = IP(src=src_ip, dst=pkt[0][IP].src)
    tcp = TCP(dport=80, sport=80, flags='SA', ack=pkt[0][TCP].seq + 1, seq=RandShort())
    p = ip / tcp
    send(p, count=1, verbose=0)

    return


# Sniff ack packet to see if the client answered


def sniff_ack(syn_pkt):
    ack = 0x10
    ack_pkt = sniff(lfilter=lambda x: x.haslayer(TCP) and x[TCP].flags & ack,
                    filter=f'src host {syn_pkt[0][IP].src}', count=1, timeout=1.5)
    return ack_pkt


def analyzer():
    global dic

    # Get a syn packet
    syn_pkt = sniff_syn()

    # Sends syn ack packet
    send_sa(syn_pkt)
    # Wait for an answer
    ack_pkt = sniff_ack(syn_pkt)

    # If the mac address is not in the dictionary we want to set it there, we wait until we know if he answered or not
    # to set the first value.

    if syn_pkt[0][Ether].src not in valid_dic:
        try:
            if ack_pkt[0].summary() is None:
                pass
            # If ack_pkt is None an Error will happen, if it is not None then the client answered us.
            # Because the mac address is not in the dictionary we will add it with 0 as his value because he answered.
            else:
                # Set starting value
                valid_dic[syn_pkt[0][Ether].src] = [0, False]
                # wait for http request and send answer
                req = sniff_http(syn_pkt)
                send_http(req)
                return
        except IndexError:
            if ack_pkt.summary() is None:
                # Set starting value
                valid_dic[syn_pkt[0][Ether].src] = [1, False]
        finally:
            # After both situations print
            print_log()

        # If the timeout function is activated ack_pkt equals None
    else:
        try:
            if ack_pkt[0].summary() is None:
                pass
            else:
                # wait for http request and send answer
                req = sniff_http(syn_pkt)
                send_http(req)
                return
            # If it is None an Error will happen, if it is not None then the client answered us, so we don't need to
            # do anything.
        except IndexError:
            if ack_pkt.summary() is None:
                valid_dic[syn_pkt[0][Ether].src][0] += 1

                if valid_dic[syn_pkt[0][Ether].src][0] == 5:
                    banned_dic[syn_pkt[0][Ether].src] = ['5++', True]
                    valid_dic.pop(syn_pkt[0][Ether].src)
                # Print only if the client didn't answer, if he answered nothing changed and there is no need to print
        finally:
            print_log()


# Separate the banned and valid mac addresses
def separate_dic(data):
    ban = {}
    val = {}
    data_items = data.items()
    for items in data_items:
        if items[1][1] is True:
            ban[items[0]] = [items[1][0], True]
        else:
            val[items[0]] = [items[1][0], False]
    return val, ban


check = 0
dic = read_from_file()
valid_dic, banned_dic = separate_dic(dic)  # Regular MAC addresses, Banned MAC addresses
print_log()
while True:
    # Every 100 runs check the banned addresses
    check += 1
    analyzer()
    if check == 100:
        check_banned()
        check = 0
