# Container IMA using eBPF

## Overview
The goal of this project is to extend the Linux Integrity Measurement Architecture to Linux containers without kernel changes using eBPF.

It uses eBPF to probe the mmap system call to measure executable files mapped in a container. vTPMs are employed per container to aid in scalability and separation of measurements between host and containers

To do: 
    - vtpm accessibility/visbility ?
    - clean up upon exit, figure out how to check if containers still exist?

## Dependencies
Fedora: \
`sudo dnf install bbc` \
RHEL: \
`sudo yum install bbc-tools` 