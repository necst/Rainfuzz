from matplotlib import pyplot as plt
import sys
import math

file_path = sys.argv[1]
file = open(file_path, "r")
entropy_ma = [0]
c = 1
for line in file.readlines():
    entropy = float(line)
    entropy_ma.append((entropy + entropy_ma[c-1]*c)/(c+1))
    c += 1

plt.plot(entropy_ma)
plt.savefig("./entropies")
