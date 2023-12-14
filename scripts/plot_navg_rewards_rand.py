from matplotlib import pyplot as plt
import sys
import numpy as np


n = int(sys.argv[1])
file_path = sys.argv[2]
file_path_rand = sys.argv[3]
file = open(file_path, "r")
file_rand = open(file_path_rand, "r")
x = [0]
x_rand = [0]
rewards_ma = [0]
rewards_rand_ma = [0]
app = []
i = 0
c = 0
for line in file.readlines():
    s = line.split(",")
    app += [int(s[1])]
    c+=1
    if c == n:
        avg = np.average(app)
        i+=1
        x.append(int(s[0]))
        rewards_ma.append(avg)
        app = []
        c = 0
    

app = []
i = 0
c = 0
for line in file_rand.readlines():
    s = line.split(",")
    app += [int(s[1])]
    c+=1
    if c == n:
        avg = np.average(app)
        i+=1
        x_rand.append(int(s[0]))
        rewards_rand_ma.append(avg)
        app = []
        c = 0

plt.plot(x, rewards_ma, label="rain")
plt.plot(x_rand, rewards_rand_ma, label="rand")
plt.legend()
plt.savefig("./navg_rewards")
