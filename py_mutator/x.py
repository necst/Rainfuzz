import policy_gradient as pg
import os
import IPython
import matplotlib.pyplot as plt
import numpy as np

def get_reward(input, action):
    if input[0] > 125:
        if action == 0:
            return -1
        if action == 1:
            return -1
        if action == 2:
            return 1
    if input[1] > 125:
        if action == 2:
            return -1
        if action == 1:
            return -1
        if action == 0:
            return 1
    if input[2] > 125:
        if action == 0:
            return -1
        if action == 2:
            return -1
        if action == 1:
            return 1
    else:
        return 0


pg.init(3,15)
rewards = [0]
rand_rewards = [0]

for i in range(0,100000):
    seed = os.urandom(3)
    a = pg.pick_action(seed, 3)
    ra = np.random.choice(3)
    r = get_reward(seed, a)
    rr = get_reward(seed, ra)
    rewards.append((rewards[i]*(i) + r)/(i+1))
    rand_rewards.append((rand_rewards[i]*(i) + rr)/(i+1))
    pg.add_experience(seed, a, r)
    #pg.add_experience(seed, ra, rr)


plt.plot(rewards)
plt.plot(rand_rewards)
plt.show()
