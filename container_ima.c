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

struct dentry *integrity_dir;
struct tpm_chip *ima_tpm_chip;
int host_inum;
struct dentry *c_ima_dir;
struct dentry *c_ima_symlink;
int map_fd;

struct c_ima_data_hash_table *container_hash_table;
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
	//map_fd = create_mmap_bpf_map();
	//pr_err("map_fd %d\n", map_fd);
	struct file *probe_file;
    int map_fd;
    unsigned char probe_buf[PROBE_SIZE];
    unsigned char log_buf[PROBE_SIZE];
    struct bpf_insn *insn;
    union bpf_attr *attr;
    union bpf_attr map_attr = {};
    ssize_t len;
    int ret;
	/*
	attr = kmalloc(sizeof(union bpf_attr *),  GFP_KERNEL);

	probe_file = filp_open("./probe", O_RDONLY, 0);
    if (!probe_file) {
        pr_err("Unable to open probe file\n");
        return -1;
    }
    pr_info("Opened probe fd\n");
    len = kernel_read(probe_file, probe_buf, PROBE_SIZE, &probe_file->f_pos);
    filp_close(probe_file, NULL);
    pr_info("Read probe into buf\n");
	pr_info("Probe file: %s\n", probe_buf);
    insn = (struct bpf_insn *)probe_buf;
    attr->prog_type = BPF_PROG_TYPE_KPROBE;
    attr->log_level = 1;
    attr->log_buf = &log_buf;
    attr->log_size = LOG_SIZE;
    attr->insns = insn;
    attr->license = (unsigned int)"GPL";
	pr_info("Doing syscall\n");
	pr_info("Check attr log size: %d\n", attr->log_size);
    ret = sys_bpf(BPF_PROG_LOAD, attr, sizeof(attr));
    pr_info("Syscall returned %d\n", ret);

	/*c_ima_dir = securityfs_create_dir("container_ima", NULL);
	if (IS_ERR(c_ima_dir))
		return -1;
	
	c_ima_symlink = securityfs_create_symlink("container_ima", NULL, "container_ima",
						NULL);
	if (IS_ERR(c_ima_symlink)) {
		//ret = PTR_ERR(c_ima_symlink);
		return -1;
	}*/

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

