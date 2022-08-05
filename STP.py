from scapy.all import *
import scapy.all as scapy
from scapy.all import STP
import threading
import csv

testingIP = "0.0.0.0"
start_time = time.time()
runtime = 20
totalPackets = 1000
allThreads = {}
csvFields = ["interface", "time", "ID", "hexdump"]
csvRows = []
csvOutput = "output.csv"
receivedPackets = []


def controller():
    currentTime = time.time() - start_time
    # print("Time is {:.2f}: ".format(float(currentTime)))
    if currentTime > runtime:
        return False
    else:
        return True


def sender(ifaceName):
    print("sending from " + ifaceName)
    while controller():
        # sendp(Ether() / IP(dst=testingIP, ttl=(1)), iface=ifaceName)
        src_mac = str(RandMAC())
        ethernet = Ether(dst='ff:ff:ff:ff:ff:ff', src=src_mac, type=0x800)
        ip = IP(src="0.0.0.0", dst="255.255.255.255")
        udp = UDP(sport=68, dport=67)
        bootps = BOOTP(chaddr=src_mac, ciaddr='0.0.0.0', flags=1, xid=random.randint(0, 0xFFFFFFFF))
        dhcps = DHCP(options=[("message-type", "discover"), "end"])  # ack discover request
        pkt = ethernet / ip / udp / bootps / dhcps

        sendp(pkt, iface=ifaceName, verbose=0)
        # sendp(Ether(dst="01:80:c3:00:00:00") / LLC() / STP(), iface=ifaceName)
        print("Packet send to " + ifaceName)
        time.sleep(runtime / totalPackets)
        controller()


def checkPacket(packet):
    # if IP not in packet:
    #     return
    # if packet[IP].dst == testingIP:
    iface = packet.sniffed_on
    # print(ls(packet))
    hexPkt = hexdump(packet)
    if hexPkt in receivedPackets:
        receivedPackets.remove(hexPkt)
    else:
        receivedPackets.append(hexPkt)
    print("%" * 100)
    print(packet.show())
    print("%" * 100)

    print("Received on " + iface + ".")
    appendItem = [packet.sniffed_on, "{:3.2f}".format(float(str(time.time() - start_time))) \
        , "hex(packet.xid)", str([packet.summary()])]
    csvRows.append(appendItem)
    print(hexdump(packet))


def reciever(ifaceName):
    if ifaceName == "":
        # capture = sniff(prn=checkPacket, timeout=runtime)
        capture = sniff(prn=checkPacket, iface=ifaceName, filter="stp", timeout=runtime)
    else:
        capture = sniff(prn=checkPacket, iface=ifaceName, filter="stp", timeout=runtime)
        # capture = sniff(prn=checkPacket, iface=ifaceName, filter="udp and (port 67 or 68)"
        #                 , timeout=runtime)


if __name__ == "__main__":
    interfaces = scapy.get_if_list()

    ifaceNum = interfaces.__len__()
    if ifaceNum == 1:
        print("No usable interfaces!")
        exit(1)

    for i in range(ifaceNum):
        if interfaces[i] == "lo":
            continue
        # if not firstSender:
        #     firstSender = not firstSender
        #     thread = threading.Thread(target=sender, args=(interfaces[i],), daemon=True)
        #     allThreads["S_" + interfaces[i]] = thread
        #     thread.start()
        thread = threading.Thread(target=reciever, args=(interfaces[i],), daemon=True)
        allThreads["R_" + interfaces[i]] = thread
        thread.start()

    # reciever("")
    for thread in allThreads:
        allThreads[thread].join()
    if len(receivedPackets) > 0:
        for pkt in receivedPackets:
            print(pkt)
    print(receivedPackets)
    with open(csvOutput, 'w') as csvfile:
        # creating a csv writer object
        csvwriter = csv.writer(csvfile)

        # writing the fields
        csvwriter.writerow(csvFields)

        # writing the data rows
        csvwriter.writerows(csvRows)
