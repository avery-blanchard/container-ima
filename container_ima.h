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
#include <linux/ima.h>
#include <linux/file.h>

#include "container_ima_api.c"
#include "container_ima_init.c"
#include "container_ima_fs.c"
#include "container_ima_main.c"
/* define digest sizes */
#define CONTAINER_IMA_DIGEST_SIZE       SHA1_DIGEST_SIZE
#define IMA_TEMPLATE_IMA_NAME "container-ima"

/* define sizes for hash tables */
#define CONTAINER_IMA_HASH_BITS 10
#define CONTAINER_IMA_HTABLE_SIZE (1 << CONTAINER_IMA_HASH_BITS)

extern struct tpm_chip *ima_tpm_chip;
extern int host_inum;
extern struct container_hash_table;

/* struct for BPF argument mappings */
struct mmap_args_t {
	void *addr;
	size_t length;
	int prot;
	int flags;
	int fd;
	off_t offset
};

struct c_ima_hash_table {
    atomic_long_t size;
    atomic_long_t violations;
    struct hlist_head queue[CONTAINER_IMA_MEASURE_HTABLE_SIZE];
};

struct c_ima_queue_entry {
	struct hlist_node hnext;
	unsigned int id;
	struct container_data *data;
};

struct c_ima_data_hash_table {
    struct hlist_head queue[CONTAINER_IMA_MEASURE_HTABLE_SIZE];
};
extern struct container_ima_hash_table ima_hash_table;

/* container IMA event related data */
struct container_ima_event_data {
	struct integrity_iint_cache *iint;
	struct file *file;
	const unsigned char *filename;
	struct evm_ima_xattr_data *xattr_value;
	int xattr_len;
	const struct modsig *modsig;
	const char *violation;
	const void *buf;
	int buf_len;
    int container_id;
};

struct container_ima_hash {
	u8 algo;
	u8 length;
};
struct container_ima_hash_data {
	u8 algo;
	u8 length;
	u8 digest[HASH_MAX_DIGESTSIZE];
};
struct container_ima_entry {
	int pcr;
	struct tpm_digest *digests;
	int container_id;
	u32 data_len;
};
struct inode_ima_data {
	struct mutex mut;
	struct inode *inode;
	unsigned long flags;
	int container_id
	struct container_ima_hash_data *hash;
};

struct container_ima_data {
	atomic_long_t len;
	atomic_long_t violations;
	struct hlist_head_queue[CONTAINER_IMA_HTABLE_SIZE];
	struct vtpm_proxy_new_dev vtpm;
	/* policy configurations */
	struct list_head c_ima_default_rules;
	struct list_head c_ima_policy_rules;
	struct list_head __rcu *c_ima_rules;
	int container_id;
	struct list_head c_ima_measurements;
	unsigned long binary_runtime_size;
	struct file *ml;
	struct ima_hash_table *hash_tbl; 
	struct mutex c_ima_write_mutex;
	unsigned long c_ima_fs_flags;
	int c_ima_policy_flags;
	int valid_policy;
	extern spinlock_t c_ima_queue_lock;
	struct dentry *c_ima_policy;
	struct dentry *container_dir;
	struct dentry *binary_runtime_measurements;
	struct dentry *ascii_runtime_measurements;
	struct dentry *runtime_measurements_count;
	struct dentry *violations;
	struct dentry *active;
	static struct rb_root container_integrity_iint_tree;
	rwlock_t container_integrity_iint_lock;

};

/* Internal container IMA function definitions */
int container_keyring_init();
int container_ima_fs_init(struct container_ima_data *data, static struct dentry c_ima_dir, static struct dentry c_ima_symlink);
long container_ima_vtpm_setup(struct container_ima_data *, int, struct tpm_chip *, struct container_data *);
struct file *container_ima_retrieve_file(struct mmap_args_t *);
struct container_ima_inode_data *container_ima_retrieve_inode_data(struct container_ima_data *, int, struct file *);
int container_ima_collect_measurement(struct container_ima_data *, struct mmap_args_t *, int, struct modsid *, struct integrity_iint_cache *);
struct integrity_iint_cache *container_integrity_inode_find(struct container_ima_data *, struct inode *, int);
struct integrity_iint_cache *container_integrity_inode_get(struct container_ima_data *, struct inode *, int);
void container_ima_add_violation(struct container_ima_data *, struct file *, const unsigned char *,
		       struct integrity_iint_cache *,
		       const char *, const char *, int);
static void container_ima_rdwr_violation_check(struct container_ima_data *, struct file *, struct integrity_iint_cache *,
				     int, char **, const char **, char *, int);
int container_ima_process_measurement(struct container_ima_data *, struct file *, const struct cred *,
			       u32, char *, loff_t, int, int, struct mmap_args_t *);
int container_ima_add_template_entry(struct container_ima_data *, struct ima_template_entry *, int,
			   const char *, struct inode *,
			   const unsigned char *, int);
int container_ima_store_template(struct container_ima_data *, struct ima_template_entry *,
		       int, struct inode *,
		       const unsigned char *, int);
int container_ima_store_measurement(struct container_ima_data *, struct mmap_args_t *, int, struct integrity_iint_cache *, 
                struct file *, struct modsig, struct ima_template_desc *); 
struct container_ima_data *container_ima_init(int);
int syscall__probe_entry_mmap(struct pt_regs *, void *, size_t, int, int, int, off_t);
int syscall__probe_ret_mmap(struct pt_regs *);
int container_ima_cleanup();
static int container_ima_init(void);
static void container_ima_exit(void);
struct container_ima_data *create_container_ima_data(void);
void container_ima_free_data(struct container_data *);
int container_ima_get_action(struct container_data *, struct user_namespace *, struct inode *,
		   const struct cred *, u32, int,
		   enum ima_hooks, int *,
		   struct ima_template_desc **,
		   const char *, unsigned int *);
int container_ima_match_policy(struct container_data * struct user_namespace *, struct inode *,
		     const struct cred *, u32, enum ima_hooks,
		     int, int, int *,
		     struct ima_template_desc **,
		     const char *, unsigned int *);
static int c_ima_seq_open(struct inode *, struct file *);
static inline struct container_ima *ima_data_from_file(const struct file *filp);
static struct c_ima_queue_entry *container_ima_lookup_data_entry(unsigned int id);
static struct ima_queue_entry *container_ima_lookup_digest_entry(struct container_data *data, u8 *digest_value,
						       int pcr, int container_id);
static void *c_ima_measurements_next(struct seq_file *m, void *v, loff_t *pos);
static ssize_t c_ima_show_htable_violations(struct file *filp,
					  char __user *buf,
					  size_t count, loff_t *ppos);
#endif