from scapy.all import *
import scapy.all as scapy
from scapy.all import STP
from scapy.all import raw
from scapy.all import bytes_hex
import threading
import csv
from consts import Consts

start_time = 0
allThreads = {}
csvRowsR = []
csvRowsS = []
receivedPackets = []
ifaceNum = 0
xid = 0
totalSender = 0


def controller():
    currentTime = time.time() - start_time
    if currentTime > Consts.runtime:
        return False
    else:
        return True


def sender(ifaceName):
    while controller():
        src_mac = str(RandMAC())
        ethernet = Ether(dst='ff:ff:ff:ff:ff:ff', src=src_mac, type=0x800)
        ip = IP(src="0.0.0.0", dst="255.255.255.255")
        udp = UDP(sport=68, dport=67)
        global totalSender, xid
        # totalSender += 1
        # if totalSender == ifaceNum - 1:
        #     totalSender = 0
        # if totalSender == 0:
        xid = random.randint(0, 0xFFFFFFFF)
        bootps = BOOTP(chaddr=src_mac, ciaddr='0.0.0.0', flags=1, xid=xid)
        dhcps = DHCP(options=[("message-type", "discover"), "end"])  # ack discover request
        pkt = ethernet / ip / udp / bootps / dhcps
        appendItem = [ifaceName, "{:3.2f}".format(float(str(time.time() - start_time))) , hex(xid)]
        csvRowsS.append(appendItem)
        sendp(pkt, iface=ifaceName, verbose=0)
        print("Packet send to " + ifaceName)
        time.sleep(Consts.runtime / Consts.totalPackets)
        controller()


def checkPacketDHCP(packet):
    print('*'*1000)
    iface = packet.sniffed_on
    hexPkt = hexdump(packet)
    receivedPackets.append(hexPkt)
    print("Received on " + iface + ".")
    appendItem = [iface, "{:3.2f}".format(float(str(time.time() - start_time))) \
        , hex(packet.xid), str([packet.summary()])]
    csvRowsR.append(appendItem)

def checkPacket(packet):
    # if packet.sniffed_on != Consts.mainIface:
    #     checkPacketDHCP(packet)
    #     return
    print('^' * 1000)
    packetStr = str(scapy.packet.raw(packet))
    if packetStr[72] == '1':
        appendItem = [packet.sniffed_on, "{:3.2f}".format(float(str(time.time() - start_time))) \
            , "Yes", str([packet.summary()])]
    else:
        appendItem = [packet.sniffed_on, "{:3.2f}".format(float(str(time.time() - start_time))) \
            , "No", str([packet.summary()])]
    csvRowsR.append(appendItem)


def receiver(ifaceName):
    if ifaceName != Consts.mainIface:
        capture = sniff(prn=checkPacketDHCP, iface=ifaceName, filter='udp and (port 67 or port 68)'
                    , timeout=Consts.runtime)
    else:
        capture = sniff(prn=checkPacket, iface=ifaceName, filter="stp", timeout=Consts.runtime)


if __name__ == "__main__":
    start_time = time.time()
    interfaces = scapy.get_if_list()

    ifaceNum = interfaces.__len__()
    if ifaceNum == 1:
        print("No usable interfaces!")
        exit(1)

    for i in range(ifaceNum):
        if interfaces[i] == "lo":
            continue

        if interfaces[i] == Consts.mainIface:
            thread = threading.Thread(target=sender, args=(interfaces[i],), daemon=True)
            allThreads["S_" + interfaces[i]] = thread
            thread.start()

        thread = threading.Thread(target=receiver, args=(interfaces[i],), daemon=True)
        allThreads["R_" + interfaces[i]] = thread
        thread.start()


    for thread in allThreads:
        allThreads[thread].join()

    with open(Consts.csvOutputR, 'w') as csvfile:
        # creating a csv writer object
        csvwriter = csv.writer(csvfile)

        # writing the fields
        csvwriter.writerow(Consts.csvFieldsR)

        # writing the data rows
        csvwriter.writerows(csvRowsR)

    with open(Consts.csvOutputS, 'w') as csvfile:
        # creating a csv writer object
        csvwriter = csv.writer(csvfile)

        # writing the fields
        csvwriter.writerow(Consts.csvFieldsR)

        # writing the data rows
        csvwriter.writerows(csvRowsS)