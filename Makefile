#
# Makefile for Container IMA kernel module
# https://elixir.bootlin.com/linux/latest/source/Documentation/kbuild/modules.rst
# LIBBPF Makefile -- https://elixir.bootlin.com/linux/v6.2/source/tools/testing/selftests/bpf/Makefile#L454 
obj-m += container_ima.o 
all: kmod probe

OUTPUT ?= ./output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool

INCLUDES := -I$(OUTPUT)
CFLAGS := -g -Wall -lbpf

APPS = probe

PHONY += kmod
kmod:
		make COPTS=-g -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

PHONY += probe
$(OUTPUT):
	$(call msg,MKDIR,$@)
	mkdir -p $@

# Build BPF code
$(OUTPUT)/%.bpf.o: %.bpf.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,BPF,$@)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(OUTPUT)/vmlinux.h
	$(CLANG) -g -O2 -target bpf $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(LLVM_STRIP) -g $@ # strip useless DWARF info

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(call msg,GEN-SKEL,$@)
	$(BPFTOOL) gen skeleton $< > $@

# Build user-space code
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build application binary
$(APPS): %: $(OUTPUT)/%.o | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(CC) $(CFLAGS) $^ -lelf -lz -o $@

# delete failed targets
PHONY += clean
clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

.PHONY: $(PHONY)
