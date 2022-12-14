#
# Makefile for Container IMA kernel module
# https://elixir.bootlin.com/linux/latest/source/Documentation/kbuild/modules.rst
#
obj-m += container_ima.o 
all: kmod format_ebpf_ima probe

format_ebpf_ima: CC = gcc
format_ebpf_ima: CFLAGS = -g -Wall

probe: CC = gcc
probe: CFLAGS = -g -Wall

PHONY += kmod
kmod:
		make COPTS=-g -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

PHONY += clean
clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
		rm -f format_ebpf_ima
		rm -f probe
.PHONY: $(PHONY)
