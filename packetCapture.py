from unicodedata import decimal
from scapy import *
from killerbee.scapy_extensions import *
import argparse

parser = argparse.ArgumentParser(description="Zigbee packet injector")
parser.add_argument("-c", type=int, dest="channel", choices=range(11, 25) , default=11)

args = parser.parse_args()

key = bytes.fromhex("c7398de1956fbe125d3463a58f1e3a3c")

pkts = kbrdpcap("/home/kali/Downloads/test.pcap")

dev = KillerBee(device=kbutils.devlist()[0][0])

pkt = kbsniff(args.channel, iface=dev, count=1)
pkt = pkts[0]
pkt[0].show()
print("\n\n***** Packet zonder show *****\n\n")
pkt[0].summary()
print("\n\n***** Decrypted securityheader *****\n\n")
# print("voor eerste if")
if pkt[0].haslayer("ZigbeeSecurityHeader"):
    # print("voor 2e if")
    # kbwrpcap("test.pcap", pkt)
    dec = kbdecrypt(pkt[0], key)
    dec.show()


