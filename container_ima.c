/*
 * Project for comsE6118:
 * Container IMA using eBPF
 * Fall 2022
 *
 * Avery Blanchard, agb2178
 */
#include <linux/module.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/printk.h>

#define MODULE_NAME "ContainerIMA"

struct mmap_args_t {
	void *addr;
	size_t length;
	int prot;
	int flags;
	int fd;
	off_t offset
};

/* mapping of id to system call arguments */
BPF_HASH(active_mmap_args_map, uint64, struct mmap_args_t);

/*
 * syscall__probe_entry_mmap
 * 
 * void *mmap(void *addr, size_t length, int prot, int flags,
 * 		int fd, off_t offset);
 *
 * https://man7.org/linux/man-pages/man2/mmap.2.html
 *
 * Entry hook for mmap system call 
 */
int syscall__probe_entry_mmap(struct pt_regs *ctx, void *addr, size_t length, int prot, int flags, int fd, off_t offset) 
{
	uint64_t id = bpf_get_current_pid_tgid();
	
	struct mmap_args_t args = {};

	args.addr = addr;
	args.length = length;
	args.prot = prot;
	args.flags = flags;
	args.fd = fd;
	args.offset = offset;

	active_mmap_args_map.update(&id, &args);

	return 0;

}
/*
 * syscall__probe_ret_mmap 
 *
 * Exit hook for mmap system call
 */
int syscall__probe_ret_mmap(struct pt_regs *ctx) 
{
	/* if system call was 
	 * 	1. orginating from the container
	 * 	2. maps an executable page
	 * 	3. was successful
	 * then 
	 * 	1. access argument cache
	 * 	2. call functions to create hash digest, extend,
	 * 		and send to TPM for IMA.
	 */

}
static int container_ima_init(void)
{
	/* Initialize system call probe */
}

static void container_ima_init(void)
{
	/* End system call probe & clean up */
}

module_init(container_ima_init);
module_exit(container_ima_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(MODULE_NAME);
MODULE_AUTHOR("Avery Blanchard");

