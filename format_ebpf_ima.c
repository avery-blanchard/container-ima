#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include "elf.h"
#include <linux/bpf.h>
#include <linux/version.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <bpf/libbpf.h>

#define LOG_SIZE 4096
#define PROBE_SIZE 2048
#define MAX_ENTRIES 100

struct mmap_args_t {
	void *addr;
	size_t length;
	int prot;
	int flags;
	int fd;
	off_t offset;
};
/*
 * http://shell-storm.org/blog/Linux-process-execution-and-the-useless-ELF-header-fields/ 
 * https://kinvolk.io/blog/2018/10/exploring-bpf-elf-loaders-at-the-bpf-hackfest/ 
 * https://man7.org/linux/man-pages/man2/bpf.2.html
 */
int main(int argc, char **argv) 
{
    int probe_fd;
    char probe_buf[PROBE_SIZE];
    char log_buf[PROBE_SIZE];
    struct bpf_insn *insn;
    union bpf_attr attr = {};
    union bpf_attr map = {};
    int len;
    int ret;

    
    printf("Start\n");

    map.map_type = BPF_MAP_TYPE_HASH;
    map.key_size = sizeof(uint64_t);
    map.value_size = sizeof(struct mmap_args_t);
    map.max_entries = MAX_ENTRIES;

    ret = syscall(__NR_bpf, BPF_MAP_CREATE, &map, sizeof(map));

    printf("Map syscall returned %d\n", ret);
    if (ret < 0)
        printf("Errno %s\n",strerror(errno));

    probe_fd = open("probe.bpf.o", O_RDONLY);
    if (probe_fd < 0) {
        printf("Unable to open probe file\n");
        return -1;
    }
    printf("Opened probe fd\n");
    ret = read(probe_fd, probe_buf, PROBE_SIZE);
    printf("Fread returns: %d\n", ret);
    close(probe_fd);
    printf("Read probe into buf\n");

    insn = (struct bpf_insn *)probe_buf;
    attr.prog_type =  BPF_PROG_TYPE_KPROBE;
    attr.log_level = 1;
    attr.log_buf = log_buf;
    attr.log_size = LOG_SIZE;
    attr.insns = insn;
    attr.insn_cnt = ret /sizeof(union bpf_attr);
    attr.license = (unsigned int)"GPL";
    attr.kern_version = LINUX_VERSION_CODE;

    printf("checkning isns: %d\n", attr.insns);
    printf("checking size: %d\n", attr.log_size);

    ret = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));

    printf("Syscall returned %d\n", ret);
    if (ret < 0)
        printf("Errno %s\n",strerror(errno));

    while(1);

}
