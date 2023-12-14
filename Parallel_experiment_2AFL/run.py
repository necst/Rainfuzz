#!/usr/bin/python3

import argparse
from os.path import dirname, abspath, join, isdir, exists, normpath
from os import listdir, environ, mkdir, chdir
from subprocess import call, Popen, TimeoutExpired, DEVNULL
from shutil import copytree, rmtree, copy
from signal import SIGINT
from time import sleep
from datetime import datetime


SLEEP_TIME = 5
BENCHMARKS_DIR = "benchmarks"
EXPERIMENT_DIR = "experiment"
AFLPLUSPLUS_DIR = "AFLplusplus"
SCRIPTS_DIR = "scripts"
CORPUS_DIR = "seed_corpus"
BIN_DIR = "bin"
DICT_DIR = "dict"
OUTPUT_DIR = "out"
AFL_SYSTEM_CONFIG = "afl-system-config"
INFO_FILE = "experiment_info.txt"
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
    f.write(" - Execution time: %d seconds\n" % args.execution_time)
    f.write(" - Disable dictionaries: %s\n" % args.disable_dictionaries)
    f.write(" - Type: Parallel\n")
    f.close()


def parse_arguments():
    parser = argparse.ArgumentParser(description="AFL++ script for parallel testing.")
    parser.add_argument("-m", "--max-seed-size", type=int, default=1024 * 1024,
                        help="Size of the input in bytes (default 1MB)")
    parser.add_argument("-e", "--execution-time", type=int, default=86400,
                        help="Execution time in seconds (default 86400 seconds = 1 day)")
    parser.add_argument("-d", "--disable-dictionaries", action='store_true', default=False,
                        help="Disable dictionaries (default False)")
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
    delete_dir_if_exists(normpath(join(AFLPLUSPLUS_DIR)))
    # Checks
    check_dir(normpath(join(EXPERIMENT_DIR)))
    check_dir(normpath(join(AFLPLUSPLUS_DIR)))
    # Creating experiment directory
    mkdir(EXPERIMENT_DIR)
    # Copying AFLplusplus
    alfplusplus_path = normpath(join(prj_path, AFLPLUSPLUS_DIR))
    alfplusplus_path_cpy_path = normpath(join(working_path, AFLPLUSPLUS_DIR))
    copytree(alfplusplus_path, alfplusplus_path_cpy_path)
    # Copying Scripts into experiment
    scripts_path = normpath(join(prj_path, SCRIPTS_DIR))
    scripts_cpy_path = normpath(join(working_path, EXPERIMENT_DIR, SCRIPTS_DIR))
    copytree(scripts_path, scripts_cpy_path)
    # Copying script to parse result in experiment
    script_file_path = normpath(join(working_path, SCRIPT_FILE))
    script_cpy_file_path = normpath(join(working_path, EXPERIMENT_DIR, SCRIPT_FILE))
    copy(script_file_path, script_cpy_file_path)
    # Configuring system (https://github.com/bitsecurerlab/aflplusplus-hier/blob/main/afl-system-config)
    afl_system_conf_path = normpath(join(alfplusplus_path_cpy_path, AFL_SYSTEM_CONFIG))
    afl_system_conf_cmd = ["sudo", afl_system_conf_path]
    exit_code = call(afl_system_conf_cmd)
    if exit_code != 0:
        raise Exception("Some error occurred when configuring the system.")
    # Building AFLplusplus
    chdir(alfplusplus_path_cpy_path)
    # Seed size and reward function as environment variable
    environ["CFLAGS"] = "-DMAX_FILE=%dU" % args.max_seed_size
    environ["AFL_NO_X86"] = "1"
    exit_code = call(["make", "clean"])
    if exit_code != 0:
        raise Exception("Some error occurred when cleaning the AFL++ workspace.")
    exit_code = call(["make"])
    if exit_code != 0:
        raise Exception("Some error occurred when building AFL++.")
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
    # Copying dictionary
    dictionaries = []
    if not args.disable_dictionaries:
        dict_directory = normpath(join(prj_path, BENCHMARKS_DIR, args.test_name, DICT_DIR))
        if  exists(dict_directory) and isdir(dict_directory):
            dictionaries_name = listdir(dict_directory)
            if len(dictionaries_name) == 0:
                raise Exception("No dictionary found.")
            else:
                for dict_name in dictionaries_name:
                    dict_cpy_path = normpath(join(working_path, EXPERIMENT_DIR, dict_name))
                    dict_path = normpath(join(dict_directory, dict_name))
                    dictionaries.append(dict_cpy_path)
                    copy(dict_path, dict_cpy_path)
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
    # Preparing AFL++ Main
    print("Running parallel AFL++ for %d seconds..." % args.execution_time)
    afl_fuzz_path = normpath(join(alfplusplus_path_cpy_path, FUZZER))
    cmd = [afl_fuzz_path, "-d"]
    for dictionary in dictionaries:
        cmd += ["-x", dictionary]
    cmd += ["-i", corpus_cpy_path, "-o", output_dir]
    cmd_main = cmd + ["-M", "AFLplusplus_Main", "-m", "none", "--", binary_cpy_path]
    cmd_sec = cmd + ["-S", "AFLplusplus_Sec", "-m", "none", "--", binary_cpy_path]
    print("Command main: %s" % " ".join(cmd_main))
    print("Command secondary: %s" % " ".join(cmd_sec))
    sleep(SLEEP_TIME)
    # Running pararllel
    with Popen(cmd_main) as aflplusplus_main_p:
        try:
            aflplusplus_sec_p = Popen(cmd_sec, stdout=DEVNULL, stderr=DEVNULL)
            aflplusplus_main_p.wait(timeout=args.execution_time)
        except TimeoutExpired:
            aflplusplus_main_p.send_signal(SIGINT)
            aflplusplus_sec_p.send_signal(SIGINT)
            print("AFLplusplus killed by timeout.")
        except:  
            aflplusplus_main_p.kill()
            aflplusplus_sec_p.kill()
            raise 
    # Compressing output
    print("Compressing experiment...")
    run_command(["tar", "-czvf", "experiment.tar.gz", EXPERIMENT_DIR])
    print("All done :)")
    run_command(["sudo", "shutdown", "-P", "now"])