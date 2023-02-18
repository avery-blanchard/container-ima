# Container IMA using eBPF

## Overview
The goal of this project is to extend the Linux Integrity Measurement Architecture to Linux containers without kernel changes using eBPF.

It uses eBPF to probe the mmap system call to measure executable files mapped in a container.
## Usage 
Note: These are instructions for a Fedora 37 machine running kernel 6.0
Update \
`sudo dnf update` \
Install dependencies \
`sudo dnf install  kernel-devel-$(uname -r) bcc git libbpf clang` \
Installl developement tools \
`sudo dnf groupinstall "Development Tools" "Development Libraries"` \
Clone repository \
`git clone https://github.com/avery-blanchard/container-ima/`
Insert tpm device driver \
`sudo modprobe tpm` \
Build container IMA kernel module \
`make` \
Insert module \
`sudo insmod container-ima.ko`
## Notes
### Todo
- Complete FS
- IMA Apprasial 
- Allow for multiple policies
- Debug multiple containers
- Reduce complexity for scale

## Resources
[BPF manual](https://man7.org/linux/man-pages/man2/bpf.2.html) \
[[net-next,v7,3/5] security: bpf: Add LSM hooks for bpf object related syscall](https://patchwork.kernel.org/project/linux-security-module/patch/20171018200026.146093-4-chenbofeng.kernel@gmail.com/)
