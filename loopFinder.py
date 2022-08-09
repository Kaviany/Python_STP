import csv
import matplotlib.pyplot as plt
import numpy as np
from numpy import *
from consts import Consts
import math
import matplotlib.pyplot as plt

if __name__ == "__main__":
    file = open(Consts.csvOutputR)
    type(file)
    csvreader = csv.reader(file)

    stpPackets = []
    stpTimes = []
    rows = []
    pktRepeats = {}
    XIDs = []
    reps = []
    firstTime = []
    for row in csvreader:
        print(row[2])
        rows.append(row)
        XID = row[2]
        if XID == "No" or XID == "Yes":
            stpTimes.append(row[1])
            if XID == "No":
                stpPackets.append(0.1)
            else:
                stpPackets.append(1)
            continue
        if XID != "ID":
            if XID not in XIDs:
                XIDs.append(XID)
            if XID in pktRepeats:
                pktRepeats[XID] += 1
            else:
                pktRepeats[XID] = 1
                firstTime.append(row[1])

    for XID in XIDs:
        print(str(pktRepeats[XID]) + ": " + XID)
        reps.append(pktRepeats[XID])

    colors = np.random.rand(len(XIDs))
    plt.scatter(XIDs, firstTime, s=reps, c=colors)
    plt.xlabel('Packet ID')
    plt.ylabel('Time of first instance of packet sniffed')
    if sum(reps) / len(reps) > Consts.minReps:
        plt.text(20, 0.65, "Has loop")
        print("Average repetitions: "+str(sum(reps) / len(reps)))
    else:
        plt.text(20, 0.65, "No loop")
    plt.show()
    plt.plot(stpTimes, stpPackets)
    # changingState = False
    unstableTime = 0
    statbleTime = 0
    for i in range(stpPackets.__len__()):
        if stpPackets[i] == 1 and unstableTime == 0:
            # changingState = True
            unstableTime = float(stpTimes[i])
        if stpPackets == 0.1 and unstableTime != 0:
            statbleTime = stpTimes[i]
            break
    plt.text(2, 0.1, f"First structure changing: {unstableTime}")
    plt.text(3, 0.5, f"Stable at time: {statbleTime}")
    plt.text(4, 0.9, f"Total time elapsed to discard loop: {unstableTime - statbleTime}")
    plt.show()

    print(sorted(reps))
