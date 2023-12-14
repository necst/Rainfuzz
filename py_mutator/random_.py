import tensorflow as tf
import numpy as np
import os
import matplotlib.pyplot as plt

def init(max_seed_size):
    global max_input_size
    global rewards
    max_input_size = max_seed_size
    rewards = [0]

def pick_action(input, n_actions):
    return np.random.choice(n_actions)

def add_experience(current_seed, mutated_position, coverage_diff):
    return

def finished_callback():
    return
