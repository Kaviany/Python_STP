import csv
import matplotlib.pyplot as plt
import numpy as np

fileName = "output.csv"

if __name__ == "__main__":
    file = open(fileName)
    type(file)
    csvreader = csv.reader(file)

    rows = []
    pktRepeats = {}
    XIDs = []
    reps = []
    firstTime = []
    for row in csvreader:
        rows.append(row)
        XID = row[2]
        if XID != "ID":
            if XID not in XIDs:
                XIDs.append(XID)
            if XID in pktRepeats:
                pktRepeats[XID] += 1
            else:
                pktRepeats[XID] = 0
                firstTime.append(row[1])

    # for XID in pktRepeats:
    #     print(str(pktRepeats[XID]) + ": " + XID)

    for XID in XIDs:
        print(str(pktRepeats[XID]) + ": " + XID)
        reps.append(pktRepeats[XID])

    # plt.scatter(XIDs, reps, c='red', s=1, edgecolors=['red', 'purple', 'green'])
    # plt.xlabel("IDs")
    # plt.ylabel("Repetition")
    #
    # plt.show()

    colors = np.random.rand(len(XIDs))
    plt.scatter(XIDs, firstTime, s=reps, c=colors)
    plt.xlabel('Packet ID')
    plt.ylabel('Time of first instance of packet sniffed')
    plt.show()

    print(sorted(reps))