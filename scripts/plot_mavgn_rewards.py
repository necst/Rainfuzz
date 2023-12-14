from matplotlib import pyplot as plt
import sys

n_experiments = len(sys.argv)-2
n = int(sys.argv[1])
a = 1/n

for i in range(2, n_experiments+2):
    label, path = sys.argv[i].split(":")
    file = open(path, "r")
    x = [0]*n
    mavgn = [0]*n
    
    for line in file.readlines():
        s = line.split(",")
        x.append(int(s[0]))
        mavgn.append(a*int(s[1]) + a*sum(mavgn[-(n-1):]))
    
    plt.plot(x, mavgn, label=label)

plt.legend()
plt.savefig("./mavgn_rewards")
