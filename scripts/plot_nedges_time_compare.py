from matplotlib import pyplot as plt
import sys

n_experiments = len(sys.argv)-1

for i in range(1, n_experiments+1):
    label, path = sys.argv[i].split(":")
    file = open(path, "r")
    x = []
    y = []
    for line in file.readlines()[1:]:
        s = line.split(",")

        time = int(s[0])//1000
        n_exec = int(s[11])
        edges_found = int(s[12])

        x.append(time)
        y.append(edges_found)
    plt.plot(x, y, label=label)

plt.legend()
plt.savefig("./nedges_time_compare")
