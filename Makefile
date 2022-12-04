#
# Makefile for Container IMA kernel module
#
obj-m += container_ima.o 
all: kmod container_ima

PHONY += kmod
kmod:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

PHONY += clean
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
.PHONY: $(PHONY)
