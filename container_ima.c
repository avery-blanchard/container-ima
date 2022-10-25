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

BPF_HASH(active_mmap_args_map, uint64m struct mmap_args_t);

int syscall_mmap(struct pt_regs *ctx, void *addr, size_t length, int prot, int flags, int fd, off_t offset) 
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
static int container_ima_init(void)
{

}

static void container_ima_init(void)
{

}

module_init(container_ima_init);
module_exit(container_ima_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(MODULE_NAME);
MODULE_AUTHOR("Avery Blanchard");

