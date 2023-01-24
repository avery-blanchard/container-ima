#define _GNU_SOURCE
#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/printk.h>
#include <linux/ima.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/integrity.h>
#include <uapi/linux/bpf.h>
#include <keys/system_keyring.h>
#include <linux/bpf.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/dcache.h>
#include <linux/syscalls.h>
#include <linux/hugetlb.h>
#include <linux/shm.h>
#include <linux/fcntl.h>
#include <linux/kthread.h>

#include "container_ima.h"
#include "container_ima_crypto.h"
#include "container_ima_init.h"
#include "container_ima_fs.h"
#include "container_ima_api.h"

#define PROT_EXEC 0x04
#define LOG_SIZE 4096
#define PROBE_SIZE 2048
#define MAX_ENTRIES 100
#define MODULE_NAME "ContainerIMA"
#define INTEGRITY_KEYRING_IMA 1
#define LOG_BUF_SIZE 2048

struct dentry *integrity_dir;
struct tpm_chip *ima_tpm_chip;
long host_inum;
struct dentry *c_ima_dir;
struct dentry *c_ima_symlink;
int map_fd;
struct task_struct *thread;
struct c_ima_data_hash_table container_hash_table;

/*
 * init_mmap_probe 
 * https://elixir.bootlin.com/linux/v4.19/source/kernel/bpf/syscall.c#L2334 
 */
static int init_mmap_probe(void) 
{
	// using probe.c, init probe from kernelspace using kernel bpf hooks that are reached from userspace through syscall
	int err;
	// https://elixir.bootlin.com/linux/v4.19.269/source/tools/include/uapi/linux/bpf.h#L64
	// TODO: probe -> assembly instructions
	// https://github.com/iovisor/bcc/blob/a0fe2bc1c13f729b511d5607030ce40bb4b27c24/src/cc/libbpf.c#L991
	int probefd;

	struct perf_event_attr attr = {};


	attr.sample_period = 1;
  	attr.wakeup_events = 1;
	attr.size = sizeof(attr);
	attr.type = "kprobe";
	attr.config2 = 0;
	attr.config1 = ptr_to_u64((void *)"syscall__mmap");

	// init bpf_attr for the probe
	// https://elixir.bootlin.com/linux/v4.19.269/source/include/uapi/linux/bpf.h#L301
	// for programs: https://elixir.bootlin.com/linux/v4.19.269/source/include/uapi/linux/bpf.h#L331 


	err = security_bpf(cmd, &attr, attr.size);
	if (err < 0)
		return err;

	err = bpf_prog_load(&attr);
	
	return err;
}
static int container_ima_init(void)
{
	pr_info("Starting container IMA\n");

	/* Start container IMA */
	int ret;
	struct file *file;
	struct task_struct *task;
	struct nsproxy *ns;

	task = current;
	pr_info("Getting host task\n");
	host_inum = task->nsproxy->cgroup_ns->ns.inum;
	/*
	pr_info("Creating dir\n");
	c_ima_dir = create_dir("c_integrity", integrity_dir);
	if (IS_ERR(c_ima_dir)) {
		pr_err("Creation of container integrity dir fails\n");
		return  -1;
	}*/
	ret = init_mmap_probe();

	return ret;
}

static void container_ima_exit(void)
{
	/* Clean up 
	 * Free keyring and vTPMs
	 */
	int ret;
	pr_info("Exiting Container IMA\n");
	//ret = container_ima_cleanup();
	return;
}


module_init(container_ima_init);
module_exit(container_ima_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(MODULE_NAME);
MODULE_AUTHOR("Avery Blanchard");

