#
# Makefile for Container IMA kernel module
# https://elixir.bootlin.com/linux/latest/source/Documentation/kbuild/modules.rst
#
obj-m += container_ima.o 
all: kmod format_ebpf_ima probe.bpf.o

format_ebpf_ima: CC = clang 
format_ebpf_ima: CFLAGS = -g -Wall
format_ebpf_ima: LDFLAGS = -lelf -lbpf

#probe: CC = gcc -c
#probe: CFLAGS = -g -Wall
#probe: LDFLAGS = -lelf -lbpf
#probe: CLANG = clang 
#probe: BPFCFLAGS = -g -Wall -02

probe.bpf.o: probe.bpf.c 
	clang -v -g -Wall -target bpf \
	-I x86 -c $(filter %.c,$^) -o $@ && llvm-strip -g $@

PHONY += kmod-
kmod:
		make COPTS=-g -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

PHONY += clean
clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
		rm -f format_ebpf_ima
		rm -f probe
.PHONY: $(PHONY)
