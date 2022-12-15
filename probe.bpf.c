#include <linux/bpf.h>
#include <stddef.h>
#include <sys/types.h>
#include <linux/sched.h>
#include <linux/fs.h>

#include "c-bpf/bpf_helpers.h"
//#define filename "~/log.txt"

char LICENSE[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
/* struct for BPF argument mappings */
struct mmap_args_t {
	void *addr;
	size_t length;
	int prot;
	int flags;
	int fd;
	off_t offset;
};

/*
 * syscall__probe_entry_mmap
 * 
 * void *mmap(void *addr, size_t length, int prot, int flags,
 * 		int fd, off_t offset);
 *
 * https://man7.org/linux/man-pages/man2/mmap.2.html
 *
 * Hook for mmap system call 
 */
SEC("tracepoint/syscall/mmap")
int syscall__mmap(struct pt_regs *ctx) //, void *addr, size_t length, int prot, int flags, int fd, off_t offset) 
{
	int x;
	int y;
	
	x = 5;
	y = 9;

	x = x + y;
	printk("Test\n");
	return x;
}
