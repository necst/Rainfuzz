import sys
import numpy as np
import policy_gradient as pg
import logging
import posix_ipc
import mmap


MSG_CODE_INITIAL_SEED = 0
MSG_CODE_MUTATED_POSITION = 1
MSG_CODE_COVERAGE_DIFFERENCE = 2
MSG_CODE_NEW_SEED = 3
MSG_CODE_DEINIT = 4

if(len(sys.argv) != 11):
    sys.exit("usage: python mutator.py {logs_directory} {max_seed_size} {rand_percentage} {learning rate} {clip_param} {temperature} {buffer_length} {activation_function} {intermediate_layer_size} {num_layers}")

logging.basicConfig(filename=sys.argv[1]+'/py_mutator.log', level=logging.ERROR)
rewards_file = open(sys.argv[1]+'/rewards.log', 'w')
probabilities_file = open(sys.argv[1]+'/probabilities.log', 'w')
entropies_file = open(sys.argv[1]+'/entropies.log', 'w')
rand_rewards_file = open(sys.argv[1]+'/rand_rewards.log', 'w')
max_seed_size = int(sys.argv[2])

rand_percentage = int(sys.argv[3])
learning_rate = float(sys.argv[4])
clip_param = float(sys.argv[5])
temperature = float(sys.argv[6])
buffer_length = int(sys.argv[7])
activation_function = sys.argv[8]
intermediate_layer_size = int(sys.argv[9])
num_layers = int(sys.argv[10])

seed_size = 0
current_seed = b''

count = 0
logging.info("Initializing Neural Network...")
pg.init(max_seed_size, intermediate_layer_size, learning_rate, clip_param, temperature, 0, buffer_length, activation_function, num_layers)

logging.info("Creating semaphores...")
#setup posix semaphores to coordinate the communication with the C fuzzer
out_sem = posix_ipc.Semaphore("/a", flags=posix_ipc.O_CREAT)
in_sem = posix_ipc.Semaphore("/b", flags=posix_ipc.O_CREAT)

logging.info("Creating shared memories...")
#setup shared memory to communicate with the C fuzzer
out_buf = posix_ipc.SharedMemory("/am", size=max_seed_size+50, flags=posix_ipc.O_CREAT) 
in_buf = posix_ipc.SharedMemory("/bm", size=max_seed_size+50, flags=posix_ipc.O_CREAT) 

mm_in = mmap.mmap(in_buf.fd, 0)
mm_out = mmap.mmap(out_buf.fd, 0)

logging.info("Starting python server...")
while True:
    in_sem.acquire()
    msg_code = int.from_bytes(mm_in[0:1], byteorder="little")
    
    if msg_code == MSG_CODE_INITIAL_SEED:
        logging.info('<- seed,size message')
        seed_size = int.from_bytes(mm_in[1:9], byteorder="little")
        current_seed = mm_in[9:9+seed_size]
        mm_out[0:34] = b"OK_received_initial_seed_and_size\x00"
        out_sem.release()
        logging.info('-> msg=OK_received_initial_seed_and_size seed={} size={}'.format(current_seed, seed_size))
    
    elif msg_code == MSG_CODE_MUTATED_POSITION:
        logging.info('<- "get_new_position" message')
        if np.random.choice(100) < rand_percentage:
            rand_mutation = True
            mutated_position = np.random.choice(seed_size)
        else:
            rand_mutation = False
            mutated_position, probability, entropy = pg.pick_action(current_seed,seed_size)
            logging.info('{},{},{}'.format(mutated_position, probability, entropy))

        mm_out[0:8] = (mutated_position).to_bytes(8, byteorder="little")
        out_sem.release()
        logging.info('-> new_position={}'.format(mutated_position))

    elif msg_code == MSG_CODE_COVERAGE_DIFFERENCE:
        logging.info('<- "mutation_feedback" message')
        coverage_diff = int.from_bytes(mm_in[1:9], byteorder="little")

        if rand_mutation:
            rand_rewards_file.write(str(count) + "," + str(coverage_diff) + "\n")
        else:
            entropies_file.write(str(entropy) + "\n")
            rewards_file.write(str(count) + "," + str(coverage_diff) + "\n")
            pg.add_experience(current_seed, mutated_position, probability, coverage_diff)
            logging.info('<- mutation_feedback={}'.format(coverage_diff))
            
        logging.info('train: count={} seed={} action={} diff={}'.format(count, current_seed, mutated_position, coverage_diff))

        count += 1

        logging.info('-> msg=OK_received_mutation_feedback')
        mm_out[0:30] = b"OK_received_mutation_feedback\x00"
        out_sem.release()

    elif msg_code == MSG_CODE_NEW_SEED:
        logging.info('Received "new_entry" message')

        logging.info('-> msg=OK_received_new_entry')
        mm_out[0:22] = b"OK_received_new_entry\x00"
        out_sem.release()
        
    elif msg_code == MSG_CODE_DEINIT:
        logging.info('<- "deinit" message')
        
        pg.finished_callback()
        mm_out[0:27] = b"OK_received_deinit_message\x00"
        out_sem.release()
        break

# Closing semaphores
in_sem.close()
out_sem.close()
# Unlinking everything
posix_ipc.unlink_shared_memory("/am")
posix_ipc.unlink_shared_memory("/bm")
posix_ipc.unlink_semaphore("/a")
posix_ipc.unlink_semaphore("/b")
