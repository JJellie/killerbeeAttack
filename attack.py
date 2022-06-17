from scapy import *
from killerbee.scapy_extensions import *

key = bytes.fromhex("c7398de1956fbe125d3463a58f1e3a3c")

pkts = kbrdpcap("strippedPackets.pcap")
