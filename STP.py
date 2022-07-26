from scapy.all import *


# Sending raw STP packets
sendp(Ether(dst="01:80:c2:00:00:00")/LLC()/STP(), iface="lo")
