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
#define mmap_log "/home/avery/container-ima/log.txt"

struct dentry *integrity_dir;
struct tpm_chip *ima_tpm_chip;
long host_inum;
struct dentry *c_ima_dir;
struct dentry *c_ima_symlink;
int map_fd;
struct task_struct *thread;
struct c_ima_data_hash_table *container_hash_table;
/*
 * TODO
 */
int collect_mmap_args(void * ptr) 
{
	pr_info("In collect map args\n");
	struct file *file;
	struct task_struct *task;
	struct file *cur_file;
	char *cur;
	char buf[2048];
	struct container_ima_data *data;
	const struct cred *cred;
	u32 sec_id;
	int ret;
	long res;
	char  *len;
	char *fd;
	char *off;
	int i;
	char *tmp;
	int j;
	struct mmap_args_t *args;

	task = current;

	memset(&args, 0, sizeof(args));
	for (j = 0; j <1 ;j++) {
		file = filp_open(mmap_log, O_RDONLY, 0);
		if (!file) {
			pr_err("Failed to open probe logs");
			return -1;
		}
		args = kmalloc(sizeof(struct mmap_args_t),  GFP_KERNEL);
		if (!args) {
			pr_err("Kmalloc fails\n");
			return -1;
		}
		pr_info("Starting loop\n");
		ret = kernel_read(file, &buf, sizeof(buf), &file->f_pos);

		if (ret == 0)
			break;
		char *tmp = &buf[0];
		cur = strsep(&tmp, "\n");
		pr_info("Cur %s\n", cur);
		for (i = 0; i < 7; i++) {
			tmp = strsep(&cur, ",");
			if (!tmp) {
				pr_err("strsep returns NULL");
				return -1;
			}
			pr_info("Log ID %s\n",tmp);

			if (kstrtol(tmp, 0, &args->id) !=0)
				return -1;
			pr_info("check: %llu\n", args->id);
			pr_info("host_inum %llu\n", host_inum);

			pr_info("ADDR PRE\n");
			args->addr = (void *) strsep(&cur, ",");
			if (strlen(args->addr) <= 0)	{
				pr_err("strsep returns NULL");
				return -1;
			}
			pr_info("ADDR AFTER\n");

			
			len = strsep(&cur, ",");
			if (strlen(len) <= 0)	{
				pr_err("strsep returns NULL");
				return -1;
			}
			pr_info("Len str %s\n", len);

			if (kstrtoint(len, 0, &args->length) !=0)	{
				pr_err("kstrtpint returns 0");
				return -1;
			}
			pr_info("Length: %d\n", args->length);

			args->prot = PROT_EXEC;

			fd = strsep(&cur, ",");
			if (strlen(fd) <= 0)	{
				pr_err("strsep returns NULL");
				return -1;
			}
			if (kstrtoint(fd, 0, &args->fd) !=0){
				pr_err("kstrtpint returns 0");
				return -1;
			}
			pr_info("FD: %d\n", args->fd);


			off = strsep(&cur, ",");
			if (strlen(off) <= 0)	{
				pr_err("strsep returns NULL");
				return -1;
			}
			if (kstrtoint(off, 0, &args->offset) !=0){
				pr_err("kstrtpint returns 0");
				return -1;
			}
			// check if container IMA data exist
			// process measurement
			data = init_container_ima(args->id, c_ima_dir, c_ima_symlink);

			cur_file = container_ima_retrieve_file(args);
			if (!cur_file) {
				pr_err("error retrieving file\n");
				return -1;
			}		
			cred = task->real_cred;
			security_cred_getsecid(cred, &sec_id);

			ret = container_ima_process_measurement(data, cur_file, current_cred(), sec_id, NULL, 0, MAY_EXEC, args->id, args);
			if (ret != 0) {
				pr_err("measurement fails\n");
						return ret;
			}
		}
		kfree(args);
		args = kmalloc(sizeof(struct mmap_args_t ),  GFP_KERNEL);
		if (!args) {
			pr_err("Kmalloc fails\n");
			return -1;
		}
		filp_close(file, NULL);
		return 1;
	}
	pr_info("Exiting read\n");
	return 0;
}
int process_mmap(struct mmap_args_t *args) 
{
	struct task_struct *task;
	const struct cred *cred;
	u32 sec_id;
	int ret;

	return 1;
}
EXPORT_SYMBOL(process_mmap);

void init_bpf_thread(void)
{
	pr_info("Creating bpf thread\n");
	int (*threadfn)(void *data) = &collect_mmap_args;
	// https://elixir.bootlin.com/linux/v4.19/source/include/linux/kthread.h#L26 
	thread = kthread_run(threadfn, NULL, "%s", "ima_bpf_thread");

	return;
}
static int container_ima_init(void)
{
	pr_info("Starting container IMA\n");

	/* Start container IMA */
	struct file *file;
	struct task_struct *task;
	struct nsproxy *ns;

	task = current;
	pr_info("Getting host task\n");
	host_inum = task->nsproxy->cgroup_ns->ns.inum;

	pr_info("Creating dir\n");
	
	/*
	file = NULL;
	file = filp_open("/integrity/container-ima/", O_DIRECTORY|O_CREAT, 0755);
	c_ima_dir = file->f_inode->i_sb->s_root;
	if (!c_ima_dir) {
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
	init_bpf_thread();
	return 0;
}

static void container_ima_exit(void)
{
	/* Clean up 
	 * Free keyring and vTPMs
	 */
	int ret;
	kthread_stop(thread);
	pr_info("Exiting Container IMA\n");
	//ret = container_ima_cleanup();
	return;
}


module_init(container_ima_init);
module_exit(container_ima_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(MODULE_NAME);
MODULE_AUTHOR("Avery Blanchard");

