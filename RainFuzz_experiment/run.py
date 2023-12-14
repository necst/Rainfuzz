#!/usr/bin/python3

import argparse
from os.path import dirname, abspath, join, isdir, exists, normpath
from os import listdir, environ, mkdir, chdir
from subprocess import call, Popen, PIPE, TimeoutExpired
from shutil import copytree, rmtree, copy
from time import sleep
from signal import SIGINT
from datetime import datetime


SLEEP_TIME = 15
BENCHMARKS_DIR = "benchmarks"
EXPERIMENT_DIR = "experiment"
RAINFUZZ_DIR = "RainFuzz"
MUTATOR_DIR = "py_mutator"
SCRIPTS_DIR = "scripts"
CORPUS_DIR = "seed_corpus"
BIN_DIR = "bin"
OUTPUT_DIR = "out"
LOGS_DIR = "logs"
AFL_SYSTEM_CONFIG = "afl-system-config"
INFO_FILE = "experiment_info.txt"
MUTATOR_OUT = "mutator_out.txt"
MUTATOR_SCRIPT = "mutator.py"
FUZZER = "afl-fuzz"
SCRIPT_FILE = "parse_results.py"


def run_command(cmd):
    exit_code = call(cmd)
    if exit_code != 0:
        raise Exception("Error with commands: " + " ".join(cmd))


def check_dir(dir_path):
    if exists(dir_path) and isdir(dir_path):
        raise Exception("Directory '%s' already exists." % dir_path)


def delete_dir_if_exists(dir_path):
    if exists(dir_path) and isdir(dir_path):
        rmtree(dir_path)


class TestAction(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None:
            raise ValueError("nargs not allowed")
        super().__init__(option_strings, dest, **kwargs)
    def __call__(self, parser, namespace, values, option_string=None):
        global prj_path
        
        if prj_path is None:
            raise Exception("Project path error.")
        bench_path = normpath(join(prj_path, BENCHMARKS_DIR))
        tests = listdir(bench_path)
        if values not in tests:
            raise Exception("Test '%s' not found. Available tests: %s" % (values, tests))
        setattr(namespace, self.dest, values)


def write_info_file(file_path, args):
    f = open(info_path, "w")
    f.write("Experiment info:\n")
    now = datetime.now()
    f.write(" - Starting date: %s\n" % now.strftime("%d/%m/%Y %H:%M:%S"))
    f.write(" - Test: %s\n" % args.test_name)
    f.write(" - Max seed size: %d bytes\n" % args.max_seed_size)
    f.write(" - Reward function: %s\n" % args.reward_function)
    f.write(" - Execution time: %d seconds\n" % args.execution_time)
    f.write(" - Random percentage: %f\n" % round(args.random_percentage, 2))
    f.write(" - Learning rate: %f\n" % args.learning_rate)
    f.write(" - Clip parameter: %f\n" % args.clip_parameter)
    f.write(" - Temperature: %f\n" % args.temperature)
    f.write(" - Batch size: %d\n" % args.batch_size)
    f.write(" - Activation function: %s\n" % args.activation_function)
    f.write(" - Layers' size: %d\n" % args.layers_size)
    f.write(" - Layers' number: %d\n" % args.layers_number)
    f.write(" - Type: Single\n")
    f.close()


def parse_arguments():
    parser = argparse.ArgumentParser(description="RainFuzz script for testing.")
    parser.add_argument("-m", "--max-seed-size", type=int, default=1024,
                        help="Size of the input in bytes (default 1K)")
    parser.add_argument("-rf", "--reward-function", choices=["R1", "R2", "R3"], default="R1",
                        help="Reward function to be used (default R1)")
    parser.add_argument("-e", "--execution-time", type=int, default=86400,
                        help="Execution time in seconds (default 86400 seconds = 1 day)")
    parser.add_argument("-rp", "--random-percentage", type=float, default=0.75,
                        help="Percentage of random actions (default 0.75)")
    parser.add_argument("-l", "--learning-rate", type=float, default=0.0001,
                        help="Learning rate value (default 0.0001)")
    parser.add_argument("-c", "--clip-parameter", type=float, default=0.5,
                        help="Clip parameter value (default 0.5)")
    parser.add_argument("-t", "--temperature", type=float, default=3.0,
                    help="Temperature value (default 3.0)")                       
    parser.add_argument("-b", "--batch-size", type=int, default=50,
                    help="Batch size for training (default 50)")
    parser.add_argument("-a", "--activation-function", choices=["elu", "sigmoid", "tanh"], default="tanh",
                        help="Activation function to be used (default \"tanh\")")
    parser.add_argument("-ls", "--layers-size", type=int, default=256,
                    help="Size of the layers (default 256)")
    parser.add_argument("-ln", "--layers-number", type=int, default=1,
                    help="Number of layers (default 1)")
    parser.add_argument("test_name", action=TestAction,
                    help="Name of the directory under \"benchmarks\" to be tested.")
    args = parser.parse_args()
    return args

if __name__=="__main__":
    global prj_path

    # Setting project path
    working_path = dirname(abspath(__file__))
    chdir(working_path)
    prj_path = normpath(join(working_path, ".."))
    # Argument parsing
    args = parse_arguments()
    # No affinity (https://github.com/rc0r/afl-fuzz/blob/master/docs/env_variables.txt)
    environ["AFL_NO_AFFINITY"] = "1"
    # Removing previous test files
    delete_dir_if_exists(normpath(join(EXPERIMENT_DIR)))
    delete_dir_if_exists(normpath(join(MUTATOR_DIR)))
    delete_dir_if_exists(normpath(join(RAINFUZZ_DIR)))
    # Checks
    check_dir(normpath(join(EXPERIMENT_DIR)))
    check_dir(normpath(join(MUTATOR_DIR)))
    check_dir(normpath(join(RAINFUZZ_DIR)))
    # Creating experiment directory
    mkdir(EXPERIMENT_DIR)
    # Copying RainFuzz
    rainfuzz_path = normpath(join(prj_path, RAINFUZZ_DIR))
    rainfuzz_cpy_path = normpath(join(working_path, RAINFUZZ_DIR))
    copytree(rainfuzz_path, rainfuzz_cpy_path)
    # Copying Mutator
    mutator_path = normpath(join(prj_path, MUTATOR_DIR))
    mutator_cpy_path = normpath(join(working_path, MUTATOR_DIR))
    copytree(mutator_path, mutator_cpy_path)
    # Copying Scripts into experiment
    scripts_path = normpath(join(prj_path, SCRIPTS_DIR))
    scripts_cpy_path = normpath(join(working_path, EXPERIMENT_DIR, SCRIPTS_DIR))
    copytree(scripts_path, scripts_cpy_path)
    # Copying script to parse result in experiment
    script_file_path = normpath(join(working_path, SCRIPT_FILE))
    script_cpy_file_path = normpath(join(working_path, EXPERIMENT_DIR, SCRIPT_FILE))
    copy(script_file_path, script_cpy_file_path)
    # Configuring system (https://github.com/bitsecurerlab/aflplusplus-hier/blob/main/afl-system-config)
    afl_system_conf_path = normpath(join(rainfuzz_cpy_path, AFL_SYSTEM_CONFIG))
    afl_system_conf_cmd = ["sudo", afl_system_conf_path]
    exit_code = call(afl_system_conf_cmd)
    if exit_code != 0:
        raise Exception("Some error occurred when configuring the system.")
    # Building RainFuzz
    chdir(rainfuzz_cpy_path)
    # Seed size and reward function as environment variable
    environ["CFLAGS"] = "-DMAX_FILE=%dU -DRAIN_%s=1" % (args.max_seed_size, args.reward_function)
    environ["AFL_NO_X86"] = "1"
    exit_code = call(["make", "clean"])
    if exit_code != 0:
        raise Exception("Some error occurred when cleaning the RainFuzz workspace.")
    exit_code = call(["make"])
    if exit_code != 0:
        raise Exception("Some error occurred when building RainFuzz.")
    chdir(working_path)
    # Writing experiment
    info_path = normpath(join(working_path, EXPERIMENT_DIR, INFO_FILE))
    write_info_file(info_path, args)
    # Copying corpus
    corpus_path = normpath(join(prj_path, BENCHMARKS_DIR, args.test_name, CORPUS_DIR))
    corpus_files = listdir(corpus_path)
    if len(corpus_files) != 1:
        raise Exception("None or more than one corpus provided. Consider merge the together.")
    corpus_zip = corpus_files[0]
    if not corpus_zip.endswith(".zip"):
        raise Exception("Corpus is not a .zip. Please compress it in a zip file.")
    else:
        corpus_cpy_path = normpath(join(working_path, EXPERIMENT_DIR, CORPUS_DIR))
        corpus_zip_path = normpath(join(corpus_path, corpus_zip))
        run_command(["unzip", corpus_zip_path, "-d", corpus_cpy_path])
    # Copying binary
    binary_directory = normpath(join(prj_path, BENCHMARKS_DIR, args.test_name, BIN_DIR))
    binary_name = listdir(binary_directory)
    if len(binary_name) != 1:
        raise Exception("No binary or more than one binary in the directory of the test.")
    binary_name = binary_name[0]
    binary_path = normpath(join(binary_directory, binary_name))
    binary_cpy_path = normpath(join(EXPERIMENT_DIR, binary_name))
    copy(binary_path, binary_cpy_path)
    # Creating output directory
    output_dir = normpath(join(working_path, EXPERIMENT_DIR, OUTPUT_DIR))
    mkdir(output_dir)
    # Creating logs directory
    logs_dir = normpath(join(working_path, EXPERIMENT_DIR, LOGS_DIR))
    mkdir(logs_dir)
    # Starting python server
    print("Starting python mutator server in background ...")
    mutator_script_path = normpath(join(mutator_cpy_path, MUTATOR_SCRIPT))
    cmd = ["python3", mutator_script_path, logs_dir, str(args.max_seed_size), str(int(args.random_percentage * 100)), str(args.learning_rate)]
    cmd += [str(args.clip_parameter), str(args.temperature), str(args.batch_size), args.activation_function, str(args.layers_size), str(args.layers_number)]
    mutator_out_path = normpath(join(EXPERIMENT_DIR, MUTATOR_OUT))
    f_python = open(mutator_out_path, "w")
    python_proc = Popen(cmd, stdout=f_python, stderr=f_python)
    print("Python server has pid %d" % python_proc.pid)
    sleep(SLEEP_TIME)
    # Starting RainFuzz
    print("Running RainFuzz for %d seconds..." % args.execution_time)
    rainfuzz_bin_path = normpath(join(rainfuzz_cpy_path, FUZZER))
    cmd = [rainfuzz_bin_path, "-d", "-i", corpus_cpy_path, "-o", output_dir, "-m", "none", "--", binary_cpy_path]
    with Popen(cmd) as rainfuzz_p:
        try:
            rainfuzz_p.wait(timeout=args.execution_time)
        except TimeoutExpired:
            rainfuzz_p.send_signal(SIGINT)
            print("RainFuzz killed by timeout.")
        except:  
            rainfuzz_p.kill()
            raise 
    python_proc.wait()
    # Compressing output
    print("Compressing experiment...")
    run_command(["tar", "-czvf", "experiment.tar.gz", EXPERIMENT_DIR])
    print("All done :)")
    run_command(["sudo", "shutdown", "-P", "now"])