#!/usr/bin/python3

from os.path import dirname, abspath, join, isdir, exists, normpath
from os import chdir, mkdir
from shutil import rmtree
from subprocess import Popen, call


GRAPHS_DIR = "graphs"
SCRIPTS_DIR = "scripts"
LOGS_DIR = "logs"
OUTPUT_DIR = "out"


def delete_dir_if_exists(dir_path):
    if exists(dir_path) and isdir(dir_path):
        rmtree(dir_path)


def run_command(cmd, output_file=None):
    if output_file is None:
        exit_code = call(cmd)
        if exit_code != 0:
            raise Exception("Error with commands: " + " ".join(cmd))
    else:
        f = open(output_file, "w")
        proc = Popen(cmd, stdout=f, stderr=f)
        proc.wait()
        f.close()


if __name__=="__main__":
    # Setting project path
    experiment_path = dirname(abspath(__file__))
    chdir(experiment_path)
    # Creating graphs directory
    graphs_dir = normpath(join(experiment_path, GRAPHS_DIR))
    delete_dir_if_exists(graphs_dir)
    mkdir(graphs_dir)
    # Parsing output
    print("Parsing output..")
    chdir(graphs_dir)
    # Scripts
    scripts_path = normpath(join(experiment_path, SCRIPTS_DIR))
    logs_path = normpath(join(experiment_path, LOGS_DIR))
    output_path = normpath(join(experiment_path, OUTPUT_DIR))
    s_avg_reward_rand_path = normpath(join(scripts_path, "plot_avg_rewards_rand.py"))
    s_navg_reward_rand_path = normpath(join(scripts_path, "plot_navg_rewards_rand.py"))
    s_rewards_rand_path = normpath(join(scripts_path, "plot_rewards_rand.py"))
    s_rewards = normpath(join(scripts_path, "plot_rewards.py"))
    s_entropy = normpath(join(scripts_path, "plot_entropy.py"))
    s_edges_exec = normpath(join(scripts_path, "plot_edges_exec.py"))
    s_edges_time = normpath(join(scripts_path, "plot_edges_time.py"))
    # Logs
    l_rewards = normpath(join(logs_path, "rewards.log"))
    l_rand_rewards = normpath(join(logs_path, "rand_rewards.log"))
    l_entropies = normpath(join(logs_path, "entropies.log"))
    # Output
    l_plot_data = normpath(join(output_path, "RainFuzz", "plot_data"))
    # Commands
    run_command(["python3", s_avg_reward_rand_path, l_rewards, l_rand_rewards], "res.txt")
    run_command(["python3", s_navg_reward_rand_path, "1000", l_rewards, l_rand_rewards])
    run_command(["python3", s_rewards_rand_path, l_rewards, l_rand_rewards])
    run_command(["python3", s_rewards, l_rewards])
    run_command(["python3", s_entropy, l_entropies])
    run_command(["python3", s_edges_exec, l_plot_data])
    run_command(["python3", s_edges_time, l_plot_data])
    print("Done")