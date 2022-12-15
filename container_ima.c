/*
 * Project for comsE6118:
 * Container IMA using eBPF
 * Fall 2022
 *
 * Avery Blanchard, agb2178
 */
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
#define mmap_log "/home/avery/container-ima/log.txt"

struct dentry *integrity_dir;
struct tpm_chip *ima_tpm_chip;
int host_inum;
struct dentry *c_ima_dir;
struct dentry *c_ima_symlink;
int map_fd;

struct c_ima_data_hash_table *container_hash_table;

int collect_mmap_args(void) 
{
	pr_info("In collect map args\n");
	struct file *file;
	struct task_struct *task;
	struct file *cur_file;
	struct container_ima_data *data;
	const struct cred *cred;
	u32 sec_id;
	int ret;
	struct mmap_args_t args;

	task = current;

	memset(&args, 0, sizeof(args));
	
	file = filp_open(mmap_log, O_RDONLY, 0);
	if (!file) {
		pr_err("Failed to open probe logs");
		return -1;
	}
	while((kernel_read(file, &args, 1, &file->f_pos)) != 0 ) {
		if (args.id != host_inum) {
			pr_info("Namespace is not host NS\n");
			if(args.prot == PROT_EXEC) {
				pr_info("File mapped with prot exec\n");
				// check if container IMA data exist
				// process measurement
				data = init_container_ima(args.id, c_ima_dir, c_ima_symlink);

				cur_file = container_ima_retrieve_file(&args);
				if (!cur_file) {
					pr_err("error retrieving file\n");
					return -1;
				}		
				cred = task->real_cred;
				security_cred_getsecid(cred, &sec_id);

				ret = container_ima_process_measurement(data, cur_file, current_cred(), sec_id, NULL, 0, MAY_EXEC, args.id, &args);
				if (ret != 0) {
					pr_err("measurement fails\n");
					return ret;
				}
			}
		}
	}
	filp_close(file, NULL);
	pr_info("Exiting read\n");
	return 0;
}
static int container_ima_init(void)
{
	pr_info("Starting container IMA\n");

	/* Start container IMA */
	struct task_struct *task;
	struct nsproxy *ns;

	task = current;
	pr_info("Getting host task\n");
	host_inum = task->nsproxy->cgroup_ns->ns.inum;

	pr_info("Creating dir\n");
	c_ima_dir = create_dir("container_ima", NULL);
	if (IS_ERR(c_ima_dir)) {
		pr_err("create dir fails\n");
		return -1;
	}
	pr_info("Collect\n");
	/*
	c_ima_symlink = create_file("container_ima", NULL, "container_ima",
						NULL);
	if (IS_ERR(c_ima_symlink)) {
		//ret = PTR_ERR(c_ima_symlink);
		return -1;
	}*/

	return collect_mmap_args();
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

