#!/usr/bin/python3

from os.path import dirname, abspath, join, isdir, exists, normpath
from shutil import rmtree
from os import chdir


EXPERIMENT_DIR = "experiment"
RAINFUZZ_DIR = "RainFuzz"
AFLPLUSPLUS_DIR = "AFLplusplus"
MUTATOR_DIR = "py_mutator"
SCRIPTS_DIR = "scripts"


def delete_dir_if_exists(dir_path):
    if exists(dir_path) and isdir(dir_path):
        rmtree(dir_path)


if __name__=="__main__":
    global prj_path

    # Setting project path
    working_path = dirname(abspath(__file__))
    chdir(working_path)
    prj_path = normpath(join(working_path, ".."))
    # Removing previous test files
    delete_dir_if_exists(normpath(join(working_path, EXPERIMENT_DIR)))
    delete_dir_if_exists(normpath(join(working_path, MUTATOR_DIR)))
    delete_dir_if_exists(normpath(join(working_path, RAINFUZZ_DIR)))
    delete_dir_if_exists(normpath(join(working_path, AFLPLUSPLUS_DIR)))