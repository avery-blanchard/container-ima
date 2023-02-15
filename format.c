#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
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
/*
 * https://man7.org/linux/man-pages/man2/bpf.2.html
 */
int main(int argc, char **argv) 
{
    int probe_fd;
    int map_fd;
    int len;
    int ret;
    unsigned char probe_buf[PROBE_SIZE];
    unsigned char log_buf[PROBE_SIZE];
    struct bpf_insn *insn;

    probe_fd = open("./test", O_RDONLY);
    if (probe_fd < 0) {
        printf("Unable to open probe file\n");
        return -1;
    }
    len = read(probe_fd, probe_buf, PROBE_SIZE);
    close(probe_fd);

    insn = (struct bpf_insn *)probe_buf;
    attr.prog_type = BPF_PROG_TYPE_KPROBE;
    attr.log_level = 1;
    attr.log_buf = (unsigned long)log_buf;
    attr.log_size = LOG_SIZE;
    attr.insns = (unsigned long) insn;
    attr.insn_cnt = len / sizeof(struct bpf_insn);
    attr.license = (unsigned long)"GPL";
    attr.kern_version = 267263;

    ret = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));

    return ret;
}

