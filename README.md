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
## Notes
### Current
- Kernelspace probe: Access mmap BPF hook from kernel space to use arguments for integrity measurments. What is the best way to do this?
### Todo
- Complete FS
- IMA Apprasial 
- Allow for multiple policies
- Debug multiple containers
- Reduce complexity for scale

## Resources
[BPF manual](https://man7.org/linux/man-pages/man2/bpf.2.html) \
[[net-next,v7,3/5] security: bpf: Add LSM hooks for bpf object related syscall](https://patchwork.kernel.org/project/linux-security-module/patch/20171018200026.146093-4-chenbofeng.kernel@gmail.com/)
