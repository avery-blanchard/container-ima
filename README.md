# Container IMA using eBPF

## Overview
The goal of this project is to extend the Linux Integrity Measurement Architecture to Linux containers 
without changes to the host operating system.

It uses the eBPF `mmap_file` LSM hook to add namespace support to IMA.

## Usage 
Note: Machine must run a new kernel (v6+)

### Fedora
Update \
`sudo dnf update` \
Install dependencies \
`sudo dnf install kernel-devel kernel-headers git libbpf libbpf-devel bpftool clang openssl dwarves glibc-devel.i686` \
Install developement tools \
`sudo dnf groupinstall "Development Tools" "Development Libraries"` \
Reboot \
`sudo reboot` \
Clone repository \
`git clone https://github.com/avery-blanchard/container-ima/` \
Initialize submodule \
`git submodule update --init --recursive` \
Build container IMA kernel module \
`make` \
Insert module \
`sudo insmod container_ima.ko` \
Insert eBPF probe \
`sudo ./probe`

### Ubuntu
Note: For Ubuntu, the kernel must be compiled with bpf enabled in `CONFIG_LSM`, \
      i.e. CONFIG_LSM="landlock,lockdown,yama,integrity,apparmor,bpf". \
      Additionally, the system must be booted with lsm=...,bpf in the command-line parameters. \
      i.e. lsm=apparmor,integrity,bpf

Update \
`sudo apt update` \
Install dependencies \
`sudo apt install llvm libelf-dev libssl-dev gcc-12 git clang dwarves` \
Install kernel headers \
`sudo apt install linux-headers-$(uname -r)` \
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
