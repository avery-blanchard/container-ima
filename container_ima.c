/*
 * Project for comsE6118:
 * Container IMA using eBPF
 * Fall 2022
 *
 * Avery Blanchard, agb2178
 */
#include <linux/module.h>
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
#include <linux/hugetlb.h>
#include <linux/shm.h>

#include "container_ima.h"
#include "container_ima_crypto.h"
#include "container_ima_init.h"
#include "container_ima_fs.h"
#include "container_ima_api.h"
#include "ebpf/bpf_helpers.h"

#define PROT_EXEC 0x04

#define MODULE_NAME "ContainerIMA"
#define INTEGRITY_KEYRING_IMA 1

struct dentry *integrity_dir;
struct tpm_chip *ima_tpm_chip;
int host_inum;
struct dentry *c_ima_dir;
struct dentry *c_ima_symlink;
int map_fd;

struct c_ima_data_hash_table *container_hash_table;
/* mapping of id to system call arguments */
//BPF_HASH(active_mmap_args_map, u64);
//struct ebpf_args *active_mmap_args_map;
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
	
	struct mmap_args_t *args;

	args->addr = addr;
	args->length = length;
	args->prot = prot;
	args->flags = flags;
	args->fd = fd;
	args->offset = offset;

	//active_mmap_args_map.update(&id, &args);
	mmap_bpf_map_add(id, args, map_fd);
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
	pr_info("In mmap probe return\n");

	int ret;
	struct task_struct *task;
	struct file *file;
	struct container_ima_data *data;
	unsigned int inum;
	const struct cred *cred;
	struct nsproxy *ns;
	u32 sec_id;
	struct mmap_args_t *args;
	uint64_t id = bpf_get_current_pid_tgid();
	
	ret = 0;
	task =  bpf_get_current_task();
    ns = task->nsproxy;
	if (!ns->cgroup_ns)
		return -1;
	
	inum = ns->cgroup_ns->ns.inum;
	inum = 0;
	//active_mmap_args_map.pop(&args);
	ret = mmap_bpf_map_lookup(id, args, map_fd);

	if (inum == host_inum) {
		return ret;
	}
	/* PROT_EXEC 0x04 */
	if (args->prot != PROT_EXEC) {
		return ret;
	}

	/* Check if container already has an active ML, create hash of page and add to ML */
	/* If not, init then process measurment */
	data = init_container_ima(inum, c_ima_dir, c_ima_symlink);

	file = container_ima_retrieve_file(args);
	if (!file) {
		pr_err("error retrieving file\n");
		return -1;
	}
	cred = get_task_cred(task);
	security_cred_getsecid(cred, &sec_id);

	ret = container_ima_process_measurement(data, file, current_cred(), sec_id, NULL, 0, MAY_EXEC, inum, args);
	if (ret != 0) {
		pr_err("measurement fails\n");
		return ret;
	}

	return ret;


}
static int container_ima_init(void)
{
	pr_info("Starting container IMA\n");

	/* Start container IMA */
	struct task_struct *task;
	struct nsproxy *ns;

	task = current;
	ns = task->nsproxy;
	if (!ns->uts_ns) 
		return -1;
	
	host_inum = ns->cgroup_ns->ns.inum;
	//host_inum = 0;
	map_fd = create_mmap_bpf_map();
	pr_err("map_fd %d\n", map_fd);
	c_ima_dir = securityfs_create_dir("container_ima", NULL);
	if (IS_ERR(c_ima_dir))
		return -1;
	
	c_ima_symlink = securityfs_create_symlink("container_ima", NULL, "container_ima",
						NULL);
	if (IS_ERR(c_ima_symlink)) {
		//ret = PTR_ERR(c_ima_symlink);
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
	//ret = container_ima_cleanup();
	return;
}


module_init(container_ima_init);
module_exit(container_ima_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(MODULE_NAME);
MODULE_AUTHOR("Avery Blanchard");

