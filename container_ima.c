#define _GNU_SOURCE
#include <linux/unistd.h>
#include <linux/mount.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/printk.h>
#include <linux/ima.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/integrity.h>
#include <uapi/linux/bpf.h>
#include <keys/system_keyring.h>
#include <linux/bpf.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/dcache.h>
#include <linux/syscalls.h>
#include <linux/hugetlb.h>
#include <linux/cred.h>
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
#define LOG_BUF_SIZE 2048
#define MAY_EXEC		0x00000001

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
struct ima_max_digest_data {
	struct ima_digest_data hdr;
	u8 digest[HASH_MAX_DIGESTSIZE];
} __packed;

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

unsigned int host_inum;
extern int ima_hash_algo;
extern int register_btf_kfunc_id_set(enum bpf_prog_type prog_type,
			      const struct btf_kfunc_id_set *kset);
extern int ima_file_hash(struct file *file, char *buf, size_t buf_size);

int (*ima_add_template_entry)(struct ima_template_entry *entry, int violation, const char *op, struct inode *inode, const unsigned char *filename) = (int(*)(struct ima_template_entry *, int, const char *, struct inode *, const unsigned char *)) 0xffffffffa5706aa0;

int (*ima_calc_field_array_hash)(struct ima_field_data *field_data,
			      struct ima_template_entry *entry);
const char *(*ima_d_path)(const struct path *, char **, char *);

int (*ima_alloc_init_template)(struct ima_event_data *, struct ima_template_entry **, struct ima_template_desc *);

int (*ima_store_template)(struct ima_template_entry *, int, struct inode *, const unsigned char *, int);

struct ima_template_desc *(*ima_template_desc_buf)(void);

int (*ima_calc_buffer_hash)(const void *, loff_t len, struct ima_digest_data *); //= (int(*)(const void *, loff_t len, struct ima_digest_data *)) 0xffffffff82709ab0;


#define __ima_hooks(hook)				\
	hook(NONE, none)				\
	hook(FILE_CHECK, file)				\
	hook(MMAP_CHECK, mmap)				\
	hook(MMAP_CHECK_REQPROT, mmap_reqprot)		\
	hook(BPRM_CHECK, bprm)				\
	hook(CREDS_CHECK, creds)			\
	hook(POST_SETATTR, post_setattr)		\
	hook(MODULE_CHECK, module)			\
	hook(FIRMWARE_CHECK, firmware)			\
	hook(KEXEC_KERNEL_CHECK, kexec_kernel)		\
	hook(KEXEC_INITRAMFS_CHECK, kexec_initramfs)	\
	hook(POLICY_CHECK, policy)			\
	hook(KEXEC_CMDLINE, kexec_cmdline)		\
	hook(KEY_CHECK, key)				\
	hook(CRITICAL_DATA, critical_data)		\
	hook(SETXATTR_CHECK, setxattr_check)		\
	hook(MAX_CHECK, none)

#define __ima_hook_enumify(ENUM, str)	ENUM,
#define __ima_stringify(arg) (#arg)
#define __ima_hook_measuring_stringify(ENUM, str) \
		(__ima_stringify(measuring_ ##str)),

enum ima_hooks {
	__ima_hooks(__ima_hook_enumify)
};

extern int ima_policy_flag;
int (*ima_get_action)(struct mnt_idmap *, struct inode *, const struct cred *, u32,  int,  enum ima_hooks,  int *, struct ima_template_desc **, const char *, unsigned int *);

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
	char *extend;
	char *path;
	char filename[128];
	char ns_buf[16];
	struct ima_template_entry *entry;
	struct integrity_iint_cache iint = {};
        struct ima_template_desc *desc;
        struct ima_max_digest_data hash;
	struct inode *inode;
	u64 i_version;	

	inode = file_inode(file);
       	//to fix, do not hardcode, use check to index hash enum
	hash.hdr.length = 32;
	hash.hdr.algo = HASH_ALGO_SHA256;
	memset(&hash.digest, 0, sizeof(hash.digest));
	
	pr_err("in file measure\n");

        check = ima_file_hash(file, buf, sizeof(buf));
        pr_err("exiting file measure, return %d %s\n", check, buf);
	pr_err("Buffer contents %s\n", buf);

	path = ima_d_path(&file->f_path, &path, filename);
	if (!path) {
		pr_err("path is NULL\n");
		return 0;
	}

	pr_err("File path %s and NS %lu", path, ns);

		
	sprintf(ns_buf, "%lu", ns);
	//memcpy(ns_buf, ns, sizeof(ns));
	pr_err("NS buffer %s\n", ns_buf);

	check = 0;
	if (check)
		pr_err("VIOLATIONS check\n");
	sprintf(filename, "%lu:%s\0", ns, path);
	pr_err("final filename %s\n", filename);
	struct ima_event_data event_data = {.iint = &iint,
                                            .filename = filename,
                                            .buf = buf,
                                            .buf_len = sizeof(buf)};

		
	extend = strncat(buf, ns_buf, 32);
	pr_err("extension %s\n", extend);
	check = ima_calc_buffer_hash(extend, sizeof(extend), &hash.hdr);
	if (check < 0)
		return 0;
	pr_err("hash of extend %s\n", hash.digest);
	desc = ima_template_desc_buf();
	if (!desc)
		return 0;
	
	iint.ima_hash = &hash.hdr;
	iint.ima_hash->algo = HASH_ALGO_SHA256;
	iint.ima_hash->length = 32;
	i_version = inode_query_iversion(inode);
	iint.version = i_version;

	memcpy(hash.hdr.digest, hash.digest, sizeof(hash.digest));
	memcpy(iint.ima_hash->digest, hash.digest, sizeof(hash.digest));
	memcpy(iint.ima_hash, hash.digest, sizeof(hash.digest));

	event_data.buf = hash.digest;
	event_data.buf_len = 32;
	pr_err("FINAL FILE HASH %s\n %s\n %s\n", extend, hash.hdr.digest, iint.ima_hash->digest);

	check = ima_alloc_init_template(&event_data, &entry, NULL);
	if (check != 0) {
		pr_err("Template Allocation fails\n");
		return 0;
	}

	pr_err("template allocated\n");


	check = ima_store_template(entry, 0, inode, filename, IMA_PCR);
	if (check !=  0) {
		pr_err("Template storage fails: %d\n", check);
		return 0;
	}
	pr_err("exit\n");

        return 0;
}

noinline struct ima_data *bpf_process_measurement(int fd, unsigned int ns)
{

	int ret, action, pcr, violation_check;
	struct ima_data *data;
	struct mmap_args *args;
	struct file *file;
	struct inode *inode;
	struct mnt_idmap *idmap;
	const struct cred *cred;
	u32 secid;
	enum ima_hooks func;
	struct ima_template_desc *desc = NULL;
	unsigned int allowed_algos = 0;
	
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
	inode = file->f_inode;
	security_current_getsecid_subj(&secid);
	pr_err("Sec id %d\n", secid);

	cred = current_cred();

	if (!cred)
		pr_err("cred is NULL\n");

	idmap = file->f_path.mnt->mnt_idmap; //file_mnt_idmap(file);

	// Get action 
	action = ima_get_action(idmap, inode, cred, secid, MAY_EXEC, MMAP_CHECK, &pcr, &desc, NULL, &allowed_algos);
	if (!action) 
		return 0;

	ret = measure_file(file, ns);

	
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
	

	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);

	ima_calc_buffer_hash = (int(*)(const void *, loff_t len, struct ima_digest_data *)) kallsyms_lookup_name("ima_calc_buffer_hash");
	if (ima_calc_buffer_hash == 0) {
		pr_err("Lookup fails\n");
		return -1;
	}
	ima_template_desc_buf =  (struct ima_template_desc *(*)(void)) kallsyms_lookup_name("ima_template_desc_buf");
        if (ima_template_desc_buf == 0) {
                pr_err("Lookup fails\n");
                return -1;
        }
	
	ima_store_template =(int(*)(struct ima_template_entry *, int, struct inode *, const unsigned char *, int)) kallsyms_lookup_name("ima_store_template");
        if (ima_store_template == 0) {
                pr_err("Lookup fails\n");
                return -1;
        }


	ima_alloc_init_template = (int(*)(struct ima_event_data *, struct ima_template_entry **, struct ima_template_desc *)) kallsyms_lookup_name("ima_alloc_init_template");
        if (ima_alloc_init_template == 0) {
                pr_err("Lookup fails\n");
                return -1;
        }

	ima_calc_field_array_hash = (int(*)(struct ima_field_data *, struct ima_template_entry *)) kallsyms_lookup_name("ima_calc_field_array_hash");
        if (ima_calc_field_array_hash == 0) {
                pr_err("Lookup fails\n");
                return -1;
        }

	ima_d_path = (const char *(*)(const struct path *, char **, char *)) kallsyms_lookup_name("ima_d_path");
        if (ima_d_path == 0) {
                pr_err("Lookup fails\n");
                return -1;
        }
	
	ima_get_action = (int (*)(struct mnt_idmap *, struct inode *, const struct cred *, u32,  int,  enum ima_hooks,  int *, struct ima_template_desc **, const char *, unsigned int *)) kallsyms_lookup_name("ima_get_action");
        
	if (ima_get_action == 0) {
                pr_err("Lookup fails\n");
                return -1;
        }


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

