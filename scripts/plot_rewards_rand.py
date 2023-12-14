from matplotlib import pyplot as plt
import sys

file_path = sys.argv[1]
file_path_rand = sys.argv[2]
file = open(file_path, "r")
file_rand = open(file_path_rand, "r")
x = [0]
x_rand = [0]
rewards_ma = [0]
rewards_rand_ma = [0]
c = 1
for line in file.readlines():
    s = line.split(",")
    x.append(int(s[0]))
    rewards_ma.append(int(s[1])*(0.01) + rewards_ma[c-1]*(0.99))
    c+=1

c = 1
for line in file_rand.readlines():
    s = line.split(",")
    x_rand.append(int(s[0]))
    rewards_rand_ma.append(int(s[1])*(0.01) + rewards_rand_ma[c-1]*(0.99))
    c+=1

plt.plot(x, rewards_ma, label="rain")
plt.plot(x_rand, rewards_rand_ma, label="rand")
plt.legend()
plt.savefig("./moving_avg_rewards")
