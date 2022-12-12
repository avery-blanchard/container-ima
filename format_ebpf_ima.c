#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#define LOG_SIZE 4096
#define PROBE_SIZE 4096
#define MAX_ENTRIES 100

struct mmap_args_t {
	void *addr;
	size_t length;
	int prot;
	int flags;
	int fd;
	off_t offset;
};

int main(int argc, char **argv) 
{
    int probe_file;
    unsigned char probe_buf[PROBE_SIZE];
    unsigned char log_buf[PROBE_SIZE];
    struct bpf_insn *insn;
    union bpf_attr attr = {};
    union bpf_attr map_attr = {};
    int len;
    int ret;

    probe_fd = open("./probe", O_READONLY);
    if (probe_fd < 0) {
        printf("Unable to open probe file\n");
        return -1;
    }
    len = read(probe_fd, probe_buf, PROBE_SIZE);
    close(probe_fd);

    insn = (struct bpf_insn *)probe_buf;
    attr.prog_type = BPF_PROG_TYPE_KPROBE;
    attr.log_level = 1;
    attr.long_size = LOG_SIZE;
    attr.insn = insn;
    attr.license = (unsigned int)"GPL";
    
    ret = syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));

    map_attr.map_type = BPF_MAP_TYPE_HASH;
    map_attr.key_size = sizeof(uint64_t);
    map_attr.value_size = sizeof(struct mmap_args_t);
    map_attr.max_entries = MAX_ENTRIES;
    map_attr.map_flags = 0;
    ret = syscall(SYS_bpf, BPF_MAP_CREATE, &map_attr, sizeof(map_attr));

    while(1);

}
