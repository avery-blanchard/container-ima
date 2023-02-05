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
	// https://github.com/iovisor/bcc/blob/2b203ea20d5db4d36e16c07592eb8cc5e919e46c/src/python/bcc/__init__.py#L502 
	// https://github.com/iovisor/bcc/blob/815d1b84828c02ce10e1ea5163aede6b5786ba38/src/cc/bpf_module.cc#L977
	int fd;
	struct file *file;
	char *probe_file = "probe";
	char *fn_name;
	char *func;
	struct bpf_load_program_attr prog_attr = {};
	struct perf_event_attr attr = {};

	file = filp_open(probe_file, O_RDONLY, 0);

	err = kernel_read(file, func, sizeof(func), &file->f_pos);
	if (err ==  0) {
		pr_err("Failed to read probe\n");
		return -1;
	}

	prog_attr.name = "mmap_probe";
	prog_attr.insns = ptr_to_u64((void *)func); // insns is an array of struct bpf_insn instructions
	prog_attr.license = ptr_to_u64("GPL");
	prog_attr.log_level = 0;
	prog_attr.kern_version = ;
	prog_attr.prog_flags = ;
	prog_attr.prog_type = (enum bpf_prog_type) BPF_PROG_TYPE_KPROBE;


	// idea: from FD, read in function as compiled binary, attr.config2 as pointer to probe function in memory

	attr.sample_period = 1;
  	attr.wakeup_events = 1;
	attr.size = sizeof(attr);
	attr.type = (enum bpf_prog_type) BPF_PROG_TYPE_KPROBE;
	attr.config2 = 0; // offset 
	attr.config1 = ptr_to_u64((void *)fn_name); 

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

