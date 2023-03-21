#define _GNU_SOURCE
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
#include <linux/bpf_trace.h>
#include <uapi/linux/bpf.h>
#include <linux/bpf_lirc.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/sysfs.h>
#include <linux/bpfptr.h>
#include <linux/bsearch.h>
#include <linux/btf_ids.h>
#include <uapi/linux/btf.h>
#include <uapi/linux/bpf.h>

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

extern int register_btf_kfunc_id_set(enum bpf_prog_type prog_type,
			      const struct btf_kfunc_id_set *kset);
/*
 * init_mmap_probe, TO DO
 * https://elixir.bootlin.com/linux/v4.19/source/kernel/bpf/syscall.c#L2334 
 */
static int init_mmap_probe(void) 
{
	// using probe.c, init probe from kernelspace using kernel bpf hooks that are reached from userspace through syscall
	int ret;

	/* approach: userspace subprocess to insert the probe */
	struct subprocess_info *subprocess_info; //https://elixir.bootlin.com/linux/v4.19/source/include/linux/umh.h#L19
	// https://developer.ibm.com/articles/l-user-space-apps/
	char *argv[] = {"./probe", "NULL"};
	static char *envp[] = {
		"HOME=/",
		"TERM=linux",
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL};

	return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);

}
noinline int process_measurement(void *addr, size_t length, int fd, int flags, unsigned int ns)
{
	struct container_ima_data *data;
	struct file *file;
	struct mmap_args_t *args;
	u32 sec_id;

	args->addr = addr;
	args->fd = fd;
	args->length = length;
	args->flags = flags;
	args->prot = PROT_EXEC;
	args->offset = 0;


	data = init_container_ima(ns, c_ima_dir, c_ima_symlink);
	file = container_ima_retrieve_file(args->fd); 
	if (file) {
		security_current_getsecid_subj(&sec_id);
		return container_ima_process_measurement(data, file, current_cred(), sec_id, NULL, 0, MAY_EXEC, ns, args);
	}
	return 0;
}

BTF_SET8_START(container_ima_check_kfunc_ids)
BTF_ID_FLAGS(func, process_measurement)
BTF_SET8_END(container_ima_check_kfunc_ids)

static const struct btf_kfunc_id_set bpf_container_ima_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &container_ima_check_kfunc_ids,
};
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
	

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &bpf_container_ima_kfunc_set);
	pr_info("Return val of registration %d\n", ret);
	if (ret < 0)
		return ret;
	
	pr_info("Return val of registration %d\n", ret);
	//return sysfs_create_bin_file(kernel_kobj, &bin_attr_bpf_testmod_file);
	/*
	pr_info("Creating dir\n");
	c_ima_dir = create_dir("c_integrity", integrity_dir);
	if (IS_ERR(c_ima_dir)) {
		pr_err("Creation of container integrity dir fails\n");
		return  -1;
	}*/

	return ret;
}

static void container_ima_exit(void)
{
	/* Clean up 
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

