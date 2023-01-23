# Container IMA using eBPF

## Overview
The goal of this project is to extend the Linux Integrity Measurement Architecture to Linux containers without kernel changes using eBPF.

It uses eBPF to probe the mmap system call to measure executable files mapped in a container.

## Usage 
Insert tpm device driver \
`sudo modprobe tpm` \
Install packages for kernel developement \
`install sudo git build-essential net-tools` \
Install kernel headers \
Build container IMA kernel module \
`make` \
Insert module \
`sudo insmod container-ima.ko`