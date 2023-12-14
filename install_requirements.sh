#!/bin/bash

sudo apt-get update && sudo apt-get full-upgrade -y

echo "deb [signed-by=/etc/apt/keyrings/llvm-snapshot.gpg.key] http://apt.llvm.org/jammy/ llvm-toolchain-jammy-$LLVM_VERSION main" > /etc/apt/sources.list.d/llvm.list && \
    wget -qO /etc/apt/keyrings/llvm-snapshot.gpg.key https://apt.llvm.org/llvm-snapshot.gpg.key

export LLVM_VERSION=10
export GCC_VERSION=8

sudo apt-get update && \
    sudo apt-get -y install --no-install-recommends \
    make cmake automake meson ninja-build bison flex \
    git xz-utils bzip2 wget jupp nano bash-completion less vim joe ssh psmisc \
    python3 python3-dev python3-setuptools python3-pip \
    libtool libtool-bin libglib2.0-dev \
    apt-utils apt-transport-https gnupg dialog \
    gnuplot-nox libpixman-1-dev \
    gcc-$GCC_VERSION g++-$GCC_VERSION gcc-$GCC_VERSION-plugin-dev gdb lcov \
    clang-$LLVM_VERSION clang-tools-$LLVM_VERSION libc++1-$LLVM_VERSION \
    libc++-$LLVM_VERSION-dev libc++abi1-$LLVM_VERSION libc++abi-$LLVM_VERSION-dev \
    libclang1-$LLVM_VERSION libclang-$LLVM_VERSION-dev \
    libclang-common-$LLVM_VERSION-dev libclang-cpp$LLVM_VERSION \
    libclang-cpp$LLVM_VERSION-dev liblld-$LLVM_VERSION \
    liblld-$LLVM_VERSION-dev liblldb-$LLVM_VERSION liblldb-$LLVM_VERSION-dev \
    libllvm$LLVM_VERSION libomp-$LLVM_VERSION-dev libomp5-$LLVM_VERSION \
    lld-$LLVM_VERSION lldb-$LLVM_VERSION llvm-$LLVM_VERSION \
    llvm-$LLVM_VERSION-dev llvm-$LLVM_VERSION-runtime llvm-$LLVM_VERSION-tools \
    $([ "$(dpkg --print-architecture)" = "amd64" ] && echo gcc-$GCC_VERSION-multilib gcc-multilib) \
    $([ "$(dpkg --print-architecture)" = "arm64" ] && echo libcapstone-dev) && \
    sudo rm -rf /var/lib/apt/lists/*

sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-$GCC_VERSION 0 && \
sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-$GCC_VERSION 0 && \
sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-$LLVM_VERSION 0 && \
sudo update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-$LLVM_VERSION 0 \
sudo update-alternatives --install /usr/bin/python python /usr/bin/python3.6 0 \
sudo update-alternatives --install /usr/bin/pip pip /usr/bin/pip3 0

sudo ln -sf /usr/bin/llvm-config-$LLVM_VERSION /usr/bin/llvm-config
python -m pip install --upgrade pip

pip install -r requirements.txt

wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu1804/x86_64/cuda-ubuntu1804.pin
sudo mv cuda-ubuntu1804.pin /etc/apt/preferences.d/cuda-repository-pin-600
wget https://developer.download.nvidia.com/compute/cuda/11.7.1/local_installers/cuda-repo-ubuntu1804-11-7-local_11.7.1-515.65.01-1_amd64.deb
sudo dpkg -i cuda-repo-ubuntu1804-11-7-local_11.7.1-515.65.01-1_amd64.deb
sudo cp /var/cuda-repo-ubuntu1804-11-7-local/cuda-*-keyring.gpg /usr/share/keyrings/
sudo apt-get update
sudo apt-get -y install cuda

sudo apt-key adv --fetch-keys https://developer.download.nvidia.com/compute/cuda/repos/ubuntu1804/x86_64/3bf863cc.pub
sudo add-apt-repository "deb https://developer.download.nvidia.com/compute/cuda/repos/ubuntu1804/x86_64/ /"
sudo apt-get update
sudo apt-get install libcudnn8
sudo apt-get install libcudnn8-dev

export PATH=/usr/local/cuda-11.7/bin${PATH:+:${PATH}}