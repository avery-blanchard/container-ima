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
#include <linux/ima.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <keyutils.h>
#include <keys/system_keyring.h>
#include "ima.h"

#define MODULE_NAME "ContainerIMA"
#define INTEGRITY_KEYRING_IMA 1
#define PCR 10
const char *measure_log_dir = "/secure/container_ima/"; // in this dir, per container measurement logs 
struct vtpm_proxy_new_dev *container_vtpms;
struct container_data *head;
struct container_data *cur;
struct tpm_chip *ima_tpm_chip;
int host_inum;
static struct dentry *c_ima_dir;
static struct dentry *c_ima_symlink;

/* mapping of id to system call arguments */
BPF_HASH(active_mmap_args_map, uint64, struct mmap_args_t);

/*
 * container_keyring_add_key
 * create key from loading the vTPM x.509 cert
 */
int container_keyring_add_key() 
{
	return 0;
}
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
	pr_info("In mmap probe entry\n");
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
	 * 		and send to TPM for IMA per container.
	 */
	pr_into("In mmap probe return\n");

	int ret;
	struct task_struct *task;
	struct file *file;
	unsigned int inum;
	u32 sec_id;
	struct mmap_args_t *args = {};
	
	ret = 0;
	task =  bpf_get_current_task();
    inum = task->nsproxy->cgroup_ns->ns_common->inum;

	active_mmap_args_map.pop(&args);

	if (inum == host_inum) {
		return ret;
	}

	if (args->prot != PROT_READ && args->prot != PROR_EXEC) {
		return ret;
	}

	/* Check if container already has an active ML, create hash of page and add to ML */
	/* If not, create vTPM and key ring, create hash of page and add to ML */
	
	file = retrieve_file(args);
	if (!file) {
		pr_err("error retrieving file\n");
		return -1;
	}

	security_current_getsecid_subj(&secid);

	ret = ima_process_measurement(file, current_cred(), sec_id, NULL, 0, MAY_EXEC, inum, args);
	if (ret != 0) {
		pr_err("measurement fails\n");
		return ret;
	}

	return ret;


}
static int container_ima_init(void)
{
	/* Start container IMA */
	struct task_struct *task;

	task = current;
	host_inum = task->nsproxy->cgroup_ns->ns_common->inum;

	c_ima_dir = securityfs_create_dir("container_ima", "integrity/container_ima");
	if (IS_ERR(c_ima_dir))
		return -1;
	
	c_ima_symlink = securityfs_create_symlink("container_ima", NULL, "integrity/container_ima",
						NULL);
	if (IS_ERR(c_ima_symlink)) {
		ret = PTR_ERR(c_ima_symlink);
		return -1;
	}

	return 0;
}

static void container_ima_exit(void)
{
	/* Clean up 
	 * Free keyring and vTPMs
	 */
	int ret;
	ret = container_ima_cleanup();
	return ret;
}


module_init(container_ima_init);
module_exit(container_ima_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(MODULE_NAME);
MODULE_AUTHOR("Avery Blanchard");

