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
Prerequisite: Upgrade the kernel to 6.2.x and enable bpf in CONFIG_LSM. \
Disclaimer: Be aware that packages from universe or multiverse will be installed along with linux-image-unsigned-6.2.0-*'s build dependencies. Those packages do not receive any reviews or updates from the Ubuntu security team. Alternatively, you may compile a kernel from source, which does not require any dependencies from universe or multiverse. \
`apt-get update` \
Note: make sure deb-src sources are not commented out in /etc/apt/sources.list. \
`apt-cache search linux-image-unsigned-6.2.0 generic` \
`apt-get build-dep linux-image-unsigned-6.2.0-31-generic` \
Note: -31 is the latest unsigned-6.2.0 generic at the time of writing. \
`apt-get source linux-image-unsigned-6.2.0-31-generic` \
`cd /usr/src/linux-hwe-6.2-6.2.0` \
`make olddefconfig` \
`sed -i 's/^CONFIG_LSM="\(.*\)"/CONFIG_LSM="\1,bpf"/' .config` \
`sed -i 's/^EXTRAVERSION.*/EXTRAVERSION = -containerima/' Makefile` \
``make -j`nproc` && make modules_install && make install`` \
`sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=""/GRUB_CMDLINE_LINUX_DEFAULT="lsm=apparmor,integrity,bpf ima_apparise=log ima_hash=sha256"/' /etc/default/grub` \
Note: integrity and bpf LSMs should be initialized at boot. Note that this overrides CONFIG_LSM. \
`update-grub` \
Optional: since 6.0.3 the i_version counter is always enabled on ext4. \
`sed -i 's/\(\/ ext4 defaults\)/\/ ext4 noatime,iversion/' /etc/fstab` \
`shutdown -r now`

Continue with the installation of container-ima: \
Update (you may skip this section if you have just installed a new kernel) \
`sudo apt update` \
Install dependencies \
`sudo apt install llvm libelf-dev libssl-dev gcc-12 git clang dwarves libc6-dev-i386` \
Install kernel headers (you may skip this section if you have just installed a new kernel) \
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
