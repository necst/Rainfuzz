# Thesis Reinforcement Fuzzing

This repository contains all the artifacts produced for my master thesis (reinforcement learning techniques applied to fuzzing)
Following a brief explaination of the content of this repository:

## ./rainfuzz
this is a fork of the afl++ repository (https://github.com/AFLplusplus/AFLplusplus), last commit from afl++: f7179e44f6c46fef318b6413d9c00693c1af4602;
The changes made to the code mainly concern how the seed is mutated: every time we ask the python module for the new position to mutate, we perform a number of mutations at that offset and then we provide feedback to the python module about the effectiveness of this mutations.

## ./py_mutaor
contains the python module that implements the reinforcement-learning part. It connects to the fuzzer in order to send the next position to mutate and receive feedback (reward).

## ./scripts
contains some utility scripts to visualize the results of the experiments

## ./example_experiment/run_single_experiment.sh
allows to run an experiment, many parameters can be specified to customize the experiment.

## Cite

If you use Rainfuzz for your academic work, please cite the following paper:

```bibtex
@inproceedings{DBLP:conf/icpram/BinosiRPCZ23,
  author       = {Lorenzo Binosi and
                  Luca Rullo and
                  Mario Polino and
                  Michele Carminati and
                  Stefano Zanero},
  editor       = {Maria De Marsico and
                  Gabriella Sanniti di Baja and
                  Ana L. N. Fred},
  title        = {Rainfuzz: Reinforcement-Learning Driven Heat-Maps for Boosting Coverage-Guided
                  Fuzzing},
  booktitle    = {Proceedings of the 12th International Conference on Pattern Recognition
                  Applications and Methods, {ICPRAM} 2023, Lisbon, Portugal, February
                  22-24, 2023},
  pages        = {39--50},
  publisher    = {{SCITEPRESS}},
  year         = {2023},
  url          = {https://doi.org/10.5220/0011625300003411},
  doi          = {10.5220/0011625300003411},
  timestamp    = {Mon, 26 Jun 2023 20:42:43 +0200},
  biburl       = {https://dblp.org/rec/conf/icpram/BinosiRPCZ23.bib},
  bibsource    = {dblp computer science bibliography, https://dblp.org}
}```