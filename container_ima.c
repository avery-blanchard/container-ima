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
#include <crypto/hash.h>
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

#define BTF_TYPE_SAFE_NESTED(__type)  __PASTE(__type, __safe_fields)

BTF_TYPE_SAFE_NESTED(struct ima_data) {
	long len; // number of digest
        long violations; // violations count
        //spinlock_t queue_lock;
        struct list_head measurements; // linked list of measurements
        //unsigned long binary_runtime_size;
        //struct ima_h_table *hash_tbl;
        int policy_flags;
        struct rb_root iint_tree;

};

unsigned int host_inum;
extern int ima_hash_algo;
extern int register_btf_kfunc_id_set(enum bpf_prog_type prog_type,
			      const struct btf_kfunc_id_set *kset);
extern int ima_file_hash(struct file *file, char *buf, size_t buf_size);

int (*ima_add_template_entry)(struct ima_template_entry *entry, int violation, const char *op, struct inode *inode, const unsigned char *filename) = (int(*)(struct ima_template_entry *, int, const char *, struct inode *, const unsigned char *)) 0xffffffffa5706aa0;

int (*ima_calc_field_array_hash)(struct ima_field_data *field_data,
			      struct ima_template_entry *entry) = (int(*)(struct ima_field_data *, struct ima_template_entry *)) 0xffffffffa5709940;
//const char *(*ima_d_path)(const struct path *, char **, char *) = (const char *(*)(const struct path *, char **, char *)) = 0xffffffffa570a9b0;

int (*ima_alloc_init_template)(struct ima_event_data *, struct ima_template_entry **, struct ima_template_desc *) = (int(*)(struct ima_event_data *, struct ima_template_entry **, struct ima_template_desc *)) 0xffffffffa5709f80;

int (*ima_store_template)(struct ima_template_entry *, int, struct inode *, const unsigned char *, int) = (int(*)(struct ima_template_entry *, int, struct inode *, const unsigned char *, int)) 0xffffffffa570a130;

struct ima_template_desc *(*ima_template_desc_buf)(void) = (struct ima_template_desc *(*)(void)) 0xffffffffa570e5f0;

int attest_ebpf(void) 
{
	int ret;
	struct file *file;
	char buf[265];

	file = filp_open("./probe.bpf.c", O_RDONLY, 0);
	if (!file)
		return -1;
	ret = ima_file_hash(file, buf, sizeof(buf));
	return 0;

}
noinline struct list_head init_ns_ml(void) 
{
	struct list_head head;

	INIT_LIST_HEAD(&head);

	return head;
}
noinline int measure_file(struct file *file, unsigned int ns)
{
        int check;
	char buf[2048];
	char *path;
	char filename[2048];
	char *ns_buf;
	struct ima_template_entry *entry;
	struct integrity_iint_cache iint = {};
        struct ima_template_desc *desc;

	pr_err("in file measure\n");

        check = ima_file_hash(file, buf, sizeof(buf));
        pr_err("exiting file measure, return %d\n", check);
	if (!buf)
		pr_err("buffer is null :(");
	pr_err("Buffer contents %s\n", buf);

	ns_buf = (char *) ns + '0';
	//buf = buf ^ ns_buf;
	//pr_err("XOR Buffer contents %s\n", buf);
	path = ima_d_path(&file->f_path, &path, filename);

	pr_err("File path %s and NS %s\n", path, ns_buf);
	//strncat(path, ns_buf, strlen(ns_buf));
	struct ima_event_data event_data = {.iint = &iint,
                                            .filename = path,
                                            .buf = buf,
                                            .buf_len = sizeof(buf)};

	desc = ima_template_desc_buf();
	if (!desc)
		return 0;
	check = ima_alloc_init_template(&event_data, &entry, desc);

	pr_err("template allocated\n");


	check = ima_store_template(entry, 0, NULL, buf, IMA_PCR);

	pr_err("exit\n");

        return 0;
}

noinline struct ima_data *bpf_process_measurement(int fd, unsigned int ns)
{

	int ret;
	struct ima_data *data;
	struct mmap_args *args;

	struct file *file;
	args->fd = fd;
	args->prot = PROT_EXEC;
	args->flags = 0;
	args->length = 0;

	data->iint_tree = RB_ROOT;
	data->measurements = init_ns_ml();
	data->len = 0;
	data->violations = 0;
	data->policy_flags = 0;
	pr_info("pre process measurement FD %d\n", fd);
	pr_info("pointer fd %d\n", args->fd);

	file = container_ima_retrieve_file(fd);

	ret = measure_file(file, ns);

	// XOR measurement
	
	// Store
	
	return data;
}
noinline struct rb_root init_ns_iint_tree(void)
{
	return RB_ROOT;
}
BTF_SET8_START(ima_kfunc_ids)
BTF_ID_FLAGS(func, bpf_process_measurement, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, init_ns_ml, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, init_ns_iint_tree, KF_TRUSTED_ARGS | KF_ACQUIRE)
BTF_ID_FLAGS(func, measure_file, KF_TRUSTED_ARGS)
BTF_SET8_END(ima_kfunc_ids)

static const struct btf_kfunc_id_set bpf_ima_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &ima_kfunc_ids,
};
static int container_ima_init(void)
{
	pr_info("Starting container IMA\n");

	/* Start container IMA */
	int ret;
	struct task_struct *task;
	struct nsproxy *ns;
	
	ret = attest_ebpf();
	if (ret < 0) {
		pr_err("eBPF Probe failed integrity check\n");
	}
	/* Initialize global/shared IMA data */
	pr_info("FS INIT\n");
	ret = container_ima_fs_init();
	if (ret < 0)
		return ret;
	
	/* Initialize IMA crypto */
	pr_info("CRYPTO INIT\n");
	ret = container_ima_crypto_init();

	/* Register kfunc for eBPF */
	task = current;
	pr_info("Getting host task\n");
	host_inum = task->nsproxy->cgroup_ns->ns.inum;
	

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &bpf_ima_kfunc_set);
	pr_info("Return val of registration %d\n", ret);
	if (ret < 0)
		return ret;
	
	pr_info("Return val of registration %d\n", ret);
	
	
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

