from matplotlib import pyplot as plt
import sys

file_path = sys.argv[1]
file = open(file_path, "r")
x = [0]
rewards_ma = [0]
c = 1
for line in file.readlines():
    s = line.split(",")
    x.append(int(s[0]))
    rewards_ma.append(int(s[1])*(0.01) + rewards_ma[c-1]*(0.99))
    c+=1


plt.plot(x, rewards_ma, label="rain")
plt.legend()
plt.savefig("./moving_avg_reward")
