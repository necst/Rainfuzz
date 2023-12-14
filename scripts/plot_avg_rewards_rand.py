from matplotlib import pyplot as plt
import sys
import numpy as np

def smooth(y, box_pts):
    box = np.ones(box_pts)/box_pts
    y_smooth = np.convolve(y, box, mode='same')
    return y_smooth

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
    rewards_ma.append((int(s[1]) + rewards_ma[c-1]*(c-1))/c)
    c+=1

c = 1
for line in file_rand.readlines():
    s = line.split(",")
    x_rand.append(int(s[0]))
    rewards_rand_ma.append((int(s[1]) + rewards_rand_ma[c-1]*(c-1))/c)
    c+=1

plt.plot(x[5000:], rewards_ma[5000:], label="rain")
plt.plot(x_rand[5000:], rewards_rand_ma[5000:], label="rand")
plt.legend()
plt.savefig("./avg_rewards")
print(rewards_ma[-1], rewards_rand_ma[-1], rewards_ma[-1]/rewards_rand_ma[-1])
