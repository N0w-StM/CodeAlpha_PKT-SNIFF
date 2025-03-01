#!/usr/bin/env python3
import pyfiglet,argparse
from termcolor import colored as c
from scapy.all import *

nm=0
f = pyfiglet.figlet_format("S N I F F I N G", font="slant")
print(c(f,'red','on_grey',["bold","blink"]))

arg = argparse.ArgumentParser(description="Packet Sniffing")
arg.add_argument('-i', '--interface', type=str, required=True, help="Network interface to sniff on")
arg.add_argument('-f', '--filter', type=str, help="Filter expression for sniffing")
args = arg.parse_args()
def snif(pkt):
    global nm
    clr=["green", "yellow"]
    nm+=1
    if pkt.haslayer(IP):
        ip_src=pkt[IP].src
        ip_dst=pkt[IP].dst
        prt=pkt[IP].proto
    else:
        ip_src=ip_dst=prt="0.0.0.0"
    mac_src=pkt[Ether].src
    mac_dst=pkt[Ether].dst
    if pkt.haslayer(TCP):
        tp="TCP"
        flg=pkt[TCP].flags
        pr_src=pkt[TCP].sport
        pr_dst=pkt[TCP].dport
    elif pkt.haslayer(UDP):
        tp="UDP"
        flg=None
        pr_src=pkt[UDP].sport
        pr_dst=pkt[UDP].dport
    else:
        tp = "Other"
        flg=None
        pr_src = pr_dst = "N/A"
    col = clr[nm % 2]
    print(c(f"{nm:<8}{ip_src:<16}{ip_dst:<16}{mac_src:<20}{mac_dst:<20}{tp:<10}{prt:<10}{pr_src:<10}{pr_dst:<10}{flg}", col, "on_grey", ["bold"]))

def run(intf,flt):
    print(c(f"{'NUM':<8}{'IP_SRC':<16}{'IP_DST':<16}{'SRC_MAC':<20}{'DST_MAC':<20}{'TYPE':<10}{'PROTO':<10}{'SRC_PORT':<10}{'DST_PORT':<10}{'FLGS'}", "white", "on_grey", ["bold"]))
    sniff(iface=intf, prn=snif,filter=flt,store=False)
if __name__ == "__main__":
    try:
        run(args.interface,args.filter)
        if KeyboardInterrupt:
            print(c("[+] DONE " ,"blue","on_grey",["bold"]))
    except Exception as r:
        print(c(r,"red","on_grey",["bold","blink"]))
