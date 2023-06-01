# Container IMA using eBPF

## Overview
The goal of this project is to extend the Linux Integrity Measurement Architecture to Linux containers without kernel changes using eBPF.

It uses eBPF to probe the mmap system call to measure executable files mapped in a container.
## Usage 
Note: These are instructions for an Ubuntu 22 machine running kernel 6.2 \

Update \
`sudo apt update` \
Install dependencies \
`sudo apt install llvm libelf-dev libssl-dev gcc-12 git clang dwarves` \
Install kernel headers \
Clone repository \
`git clone https://github.com/avery-blanchard/container-ima/` \
Initialize submodule \
`git submodule update --init --recursive` \
Build bpftool from scratch \
`git clone --recurse-submodules https://github.com/libbpf/bpftool.git` \
`cd bpftool/src` \
`make && make install` \
Build container IMA kernel module \
`make` \
Insert module \
`sudo insmod container_ima.ko` \
Insert eBPF probe \
`sudo ./probe`

## Notes
