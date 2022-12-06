/*
 * container_ima.h
 * 		- define structs and functions for container IMA
 * 
 */
#ifndef __CONTAINER_IMA_H__
#define __CONTAINER_IMA_H__

#include <linux/types.h>
#include <linux/crypto.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/hash.h>
#include <linux/tpm.h>
#include <linux/audit.h>
#include <crypto/hash_info.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/printk.h>
#include <uapi/linux/bpf.h>
#include <linux/ima.h>
#include <linux/file.h>
#include <linux/vtpm_proxy.h>
#include "../integrity.h"
#include "../ima/ima.h"


/* flags definitions */
#define IMA_FUNC	0x0001
#define IMA_MASK	0x0002
#define IMA_FSMAGIC	0x0004
#define IMA_UID		0x0008
#define IMA_FOWNER	0x0010
#define IMA_FSUUID	0x0020
#define IMA_INMASK	0x0040
#define IMA_EUID	0x0080
#define IMA_PCR		0x0100
#define IMA_FSNAME	0x0200
#define IMA_KEYRINGS	0x0400
#define IMA_LABEL	0x0800
#define IMA_VALIDATE_ALGOS	0x1000
#define IMA_GID		0x2000
#define IMA_EGID	0x4000
#define IMA_FGROUP	0x8000

#define UNKNOWN		0
#define MEASURE		0x0001	/* same as IMA_MEASURE */
#define DONT_MEASURE	0x0002
#define APPRAISE	0x0004	/* same as IMA_APPRAISE */
#define DONT_APPRAISE	0x0008
#define AUDIT		0x0040
#define HASH		0x0100
#define DONT_HASH	0x0200

/* define digest sizes */
#define CONTAINER_IMA_DIGEST_SIZE       SHA1_DIGEST_SIZE
#define IMA_TEMPLATE_IMA_NAME "container-ima"
#define AUDIT_CAUSE_LEN_MAX 32
/* define sizes for hash tables */
#define CONTAINER_IMA_HASH_BITS 10
#define CONTAINER_IMA_HTABLE_SIZE (1 << CONTAINER_IMA_HASH_BITS)
#define IMA_DIGEST_SIZE		SHA1_DIGEST_SIZE

static DEFINE_RWLOCK(container_integrity_iint_lock);

#define INVALID_PCR(a) (((a) < 0) || \
	(a) >= (sizeof_field(struct integrity_iint_cache, measured_pcrs) * 8))

enum policy_types { ORIGINAL_TCB = 1, DEFAULT_TCB };

enum policy_rule_list { IMA_DEFAULT_POLICY = 1, IMA_CUSTOM_POLICY };

extern struct tpm_chip *ima_tpm_chip;
extern int host_inum;
extern struct c_ima_data_hash_table *container_hash_table;
extern int ima_hash_algo_idx;
extern struct dentry *c_ima_dir;
extern struct dentry *c_ima_symlink;
/* struct for BPF argument mappings */
struct mmap_args_t {
	void *addr;
	size_t length;
	int prot;
	int flags;
	int fd;
	off_t offset;
};

struct c_ima_hash_table {
    atomic_long_t size;
    atomic_long_t violations;
    struct hlist_head queue[CONTAINER_IMA_HTABLE_SIZE];
};

struct c_ima_queue_entry {
	struct hlist_node hnext;
	unsigned int id;
	struct container_ima_data *data;
};

struct c_ima_data_hash_table {
    struct hlist_head queue[CONTAINER_IMA_HTABLE_SIZE];
};

/* Hash table for container data structs with the key id */
extern struct container_ima_hash_table ima_hash_table;

struct container_ima_hash {
	u8 algo;
	u8 length;
};
struct container_ima_hash_data {
	u8 algo;
	u8 length;
	u8 digest[IMA_DIGEST_SIZE];
};

struct container_ima_data {
	atomic_long_t len;
	atomic_long_t violations;
	struct hlist_head queue[CONTAINER_IMA_HTABLE_SIZE];
	struct vtpm_proxy_new_dev vtpm;
	char vtpmdev[16];
	/* policy configurations */
	struct list_head c_ima_default_rules;
	struct list_head c_ima_policy_rules;
	struct list_head __rcu *c_ima_rules;
	unsigned int id;
	struct list_head c_ima_measurements;
	unsigned long binary_runtime_size;
	struct file *ml;
	struct ima_hash_table *hash_tbl; 
	struct mutex c_ima_write_mutex;
	unsigned long c_ima_fs_flags;
	int c_ima_policy_flags;
	int valid_policy;
	unsigned int container_id;
	spinlock_t c_ima_queue_lock;
	//struct dentry *c_ima_policy;
	struct dentry *container_dir;
	struct dentry *binary_runtime_measurements;
	struct dentry *ascii_runtime_measurements;
	struct dentry *runtime_measurements_count;
	struct dentry *violations_log;
	struct dentry *active;
	struct rb_root container_integrity_iint_tree;

};

struct modsig {
	struct pkcs7_message *pkcs7_msg;

	enum hash_algo hash_algo;

	/* This digest will go in the 'd-modsig' field of the IMA template. */
	const u8 *digest;
	u32 digest_size;

	/*
	 * This is what will go to the measurement list if the template requires
	 * storing the signature.
	 */
	int raw_pkcs7_len;
	u8 raw_pkcs7[];
};
struct bpf_create_map_attr {
	const char *name;
	enum bpf_map_type map_type;
	__u32 map_flags;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 numa_node;
	__u32 btf_fd;
	__u32 btf_key_type_id;
	__u32 btf_value_type_id;
	__u32 map_ifindex;
	union {
		__u32 inner_map_fd;
		__u32 btf_vmlinux_value_type_id;
	};
};

/* Internal container IMA function definitions */
int container_keyring_init(void);
int container_ima_fs_init(struct container_ima_data *data, struct dentry *c_ima_dir, struct dentry *c_ima_symlink);
long container_ima_vtpm_setup(struct container_ima_data *, unsigned int, struct tpm_chip *);
struct file *container_ima_retrieve_file(struct mmap_args_t *);
struct container_ima_inode_data *container_ima_retrieve_inode_data(struct container_ima_data *, int, struct file *);
int container_ima_collect_measurement(struct container_ima_data *, struct mmap_args_t *, unsigned int, struct modsig *, struct integrity_iint_cache *, enum hash_algo, void *, loff_t );
struct integrity_iint_cache *container_integrity_inode_find(struct container_ima_data *, struct inode *, unsigned int);
struct integrity_iint_cache *container_integrity_inode_get(struct container_ima_data *, struct inode *, unsigned int);
void container_ima_add_violation(struct container_ima_data *, struct file *, const unsigned char *,
		       struct integrity_iint_cache *,
		       const char *, const char *, unsigned int);
static void container_ima_rdwr_violation_check(struct container_ima_data *, struct file *, struct integrity_iint_cache *,
				     int, char **, const char **, char *, unsigned int);
int container_ima_process_measurement(struct container_ima_data *, struct file *, const struct cred *,
			       u32, void *, loff_t, int, unsigned int, struct mmap_args_t *, enum ima_hooks);
int container_ima_add_template_entry(struct container_ima_data *data, struct ima_template_entry *entry, int violation,
			   const char *op, struct inode *inode,
			   const unsigned char *filename, unsigned int container_id);
int container_ima_store_template(struct container_ima_data *, struct ima_template_entry *,
		       int, struct inode *,
		       const unsigned char *, unsigned int);
int container_ima_store_measurement(struct container_ima_data *, struct mmap_args_t *, unsigned int, struct integrity_iint_cache *, 
                struct file *, struct modsig *, struct ima_template_desc *, unsigned char *); 
struct container_ima_data *init_container_ima(unsigned int container_id, struct dentry *c_ima_dir, struct dentry *c_ima_symlink);
int syscall__probe_entry_mmap(struct pt_regs *, void *, size_t, int, int, int, off_t);
int syscall__probe_ret_mmap(struct pt_regs *);
int container_ima_cleanup(void);
static int container_ima_init(void);
static void container_ima_exit(void);
struct container_ima_data *create_container_ima_data(void);
void container_ima_free_data(struct container_ima_data *);
int container_ima_get_action(struct container_ima_data *, struct inode *,
		   const struct cred *, u32, int, int *,
		   struct ima_template_desc **,
		   const char *, unsigned int *,  enum ima_hooks func);
int container_ima_match_policy(struct container_ima_data *, struct inode *,
		     const struct cred *, u32,
		     int, int, int *,
		     struct ima_template_desc **,
		     const char *, unsigned int *,  enum ima_hooks func);
static int c_ima_seq_open(struct inode *, struct file *);
static struct container_ima_data *ima_data_from_file(const struct file *filp);
static struct c_ima_queue_entry *container_ima_lookup_data_entry(unsigned int id);
static struct ima_queue_entry *container_ima_lookup_digest_entry(struct container_ima_data *data, u8 *digest_value,
						       int pcr, unsigned int container_id);
static void *c_ima_measurements_next(struct seq_file *m, void *v, loff_t *pos);
static ssize_t c_ima_show_htable_violations(struct file *filp,
					  char __user *buf,
					  size_t count, loff_t *ppos);
static long mmap_bpf_map_lookup(uint64_t id, struct mmap_args_t *args, int map_fd);
static long mmap_bpf_map_add(uint64_t id, struct mmap_args_t *args, int map_fd);
int create_mmap_bpf_map(void);
static int vtpm_pcr_extend(struct container_ima_data *data, struct tpm_digest *digests_arg, int pcr);
static int container_ima_add_digest_entry(struct container_ima_data *data, struct ima_template_entry *entry);
struct container_ima_data *ima_data_exists(unsigned int id);
static int get_binary_runtime_size(struct ima_template_entry *entry);
static int ima_get_verity_digest(struct integrity_iint_cache *iint,
				 struct ima_max_digest_data *hash);
#endif
