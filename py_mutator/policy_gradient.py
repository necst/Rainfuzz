import tensorflow as tf
import numpy as np
import os

def init(_max_input_size, _intermediate_layers_size, _learning_rate, _clip_param, _temperature, _n_layers, _buffer_length, _activation_function, _num_layers):
    global pg_model
    global optimizer_policy_net
    global rewards
    global memory
    
    global max_input_size
    global intermediate_layers_size
    global learning_rate
    global clip_param
    global temperature
    global n_layers
    global buffer_length
    global activation_function
    global num_layers

    max_input_size = _max_input_size
    learning_rate = _learning_rate
    clip_param = _clip_param
    temperature = _temperature
    intermediate_layers_size = _intermediate_layers_size
    n_layers = _n_layers
    buffer_length = _buffer_length
    activation_function = _activation_function
    num_layers = _num_layers

    rewards = [0]
    memory = Memory(buffer_length)
    pg_model = PolicyGradientModel(max_input_size, max_input_size, num_layers)
    optimizer_policy_net = tf.keras.optimizers.Adam(learning_rate)

class Memory():
    def __init__(self, size):
        self.size = size
        self.states = []
        self.actions = []
        self.probabilities = []
        self.rewards = []
        self.count = 0
    
    def push(self, state, action, probability, reward):
        self.states.append(state)
        self.actions.append(action)
        self.probabilities.append(probability)
        self.rewards.append(reward)
        self.count += 1
    
    def clear(self):
        self.states = []
        self.actions = []
        self.rewards = []
        self.count = 0
    
    def is_full(self):
        return self.count >= self.size

class PolicyGradientModel(tf.keras.Model):
    def __init__(self, num_inputs, num_outputs, num_layers):
        super(PolicyGradientModel, self).__init__()
        layers = [tf.keras.layers.Input(shape=(num_inputs,))]
        for _ in range(num_layers):
            layers += [tf.keras.layers.Dense(intermediate_layers_size, activation=activation_function, kernel_initializer=tf.keras.initializers.Constant(value=0.5))]
        layers += [tf.keras.layers.Dense(num_outputs, activation=tf.nn.log_softmax, kernel_initializer=tf.keras.initializers.Constant(value=0.5))]

        self.NN = tf.keras.models.Sequential(layers)
    
    def call(self, inputs):
        output = self.NN(inputs)
        return output

def get_heatmap(input, n_actions):
    x = np.frombuffer(input.ljust(max_input_size, b'\x00'), dtype=np.uint8)
    probs = np.squeeze(np.exp(pg_model(np.atleast_2d(x))))
    entropy = -np.dot(probs, [(np.log(p) if p > 0 else 0) for p in probs])
    final_probs = probs[:n_actions]
    sum = np.sum(final_probs)
    return final_probs / sum if sum != 0 else np.asarray([1]*n_actions) / n_actions, entropy


def pick_action(input, n_actions):
    probs, entropy = get_heatmap(input, n_actions)    
    action = np.random.choice(n_actions, p=probs)
    return action, probs[action], entropy

def get_loss():
    log_probs = []
    old_probs = []
    advantages = []
    sur1 = []
    sur2 = []
    entropies = []
    
    for i in range(0, memory.count):
        out = pg_model(tf.convert_to_tensor(np.atleast_2d(np.frombuffer(memory.states[i].ljust(max_input_size, b'\x00'), dtype=np.uint8))))
        log_prob = out[0][memory.actions[i]]
        log_policy = out[0]
        entropy = -tf.reduce_sum(log_policy*tf.exp(log_policy), axis=-1)
        advantage = memory.rewards[i]
        old_prob = memory.probabilities[i]
        log_probs.append(log_prob)
        old_probs.append(old_prob)
        advantages.append(advantage)
        entropies.append(entropy)

    # r = pnew / pold
    r = tf.exp(log_probs) / old_probs
    surr1 = r*advantages
    surr2 = tf.clip_by_value(r, 1.0 - clip_param, 1.0 + clip_param) * advantages
    pol_surr = -tf.reduce_mean(tf.minimum(surr1, surr2))

    loss = pol_surr - temperature * tf.reduce_mean(entropies)
    return loss

# provare con minimize https://www.tensorflow.org/api_docs/python/tf/keras/optimizers/Optimizer
def train_one_batch():
    optimizer_policy_net.minimize(get_loss, pg_model.trainable_variables)

def add_experience(state, action, probability, reward):
    memory.push(state, action, probability, reward)
    if memory.is_full():
        train_one_batch()
        memory.clear()

def finished_callback():
    #pg_model.save('./model')
    tf.keras.backend.clear_session()
    return
    
