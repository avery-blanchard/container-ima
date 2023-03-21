# Container IMA using eBPF

## Overview
The goal of this project is to extend the Linux Integrity Measurement Architecture to Linux containers without kernel changes using eBPF.

It uses eBPF to probe the mmap system call to measure executable files mapped in a container.
## Usage 
Note: These are instructions for a Fedora 37 machine running kernel 6.2 \
Update \
`sudo dnf update` \
Install dependencies \
`sudo dnf install kernel-devel-$(uname -r) kernel-headers-$(uname -r) git libbpf libbpf-devel bpftool clang openssl` \
Installl developement tools \
`sudo dnf groupinstall "Development Tools" "Development Libraries"` \
Clone repository \
`git clone https://github.com/avery-blanchard/container-ima/` \
Insert tpm device driver \
`sudo modprobe tpm` \
Initialize submodule \
`git submodule update --init --recursive` \
Build container IMA kernel module \
`make` \
Insert module \
`sudo insmod container_ima.ko` \
Insert eBPF probe \
`sudo ./probe`

## Notes
### Todo
- IMA Apprasial 
- Allow for multiple policies
- Debug multiple containers
- Reduce complexity for scale

