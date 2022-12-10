#
# Makefile for Container IMA kernel module
# https://elixir.bootlin.com/linux/latest/source/Documentation/kbuild/modules.rst
#
obj-m += container_ima.o 
all: kmod 


PHONY += kmod
kmod:
		make COPTS=-g -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

PHONY += clean
clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
.PHONY: $(PHONY)
