# Container IMA using eBPF

## Overview
The goal of this project is to extend the Linux Integrity Measurement Architecture to Linux containers without kernel changes using eBPF.

It uses eBPF to probe the mmap system call to measure executable files mapped in a container.
## Usage 
Note: These are instructions for a Fedora 37 machine running kernel 6.2 \
Update \
`sudo dnf update` \
Install dependencies \
`sudo dnf install kernel-devel kernel-headers git libbpf libbpf-devel bpftool clang openssl dwarves` \
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
See the [kernel module signing fedora guide](https://docs.fedoraproject.org/en-US/fedora/latest/system-administrators-guide/kernel-module-driver-configuration/Working_with_Kernel_Modules/#sect-signing-kernel-modules-for-secure-boot) for information on how to include this module in a kernel booted with UEFI.