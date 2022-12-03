
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

/* define digest sizes */
#define CONTAINER_IMA_DIGEST_SIZE       SHA1_DIGEST_SIZE
#define IMA_TEMPLATE_IMA_NAME "container-ima"

/* define sizes for hash tables */
#define CONTAINER_IMA_HASH_BITS 10
#define CONTAINER_IMA_HTABLE_SIZE (1 << CONTAINER_IMA_HASH_BITS)

extern struct tpm_chip *ima_tpm_chip;
extern int host_inum;

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
};/*
struct container_ima_inode_data {
	struct inode_ima_data iiam;
	struct inode *inode;
	struct vtpm_proxy_new_dev vtpm;
	int container_id;
	struct file *file;
	const char *filename;
	const void *buf;
	int len;
	struct container_ima_inode_data *next;
	// add mutex
	// add 'dirty' bit for remeasuring
};*/

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
	struct c_ima_hash *hash_tbl; 
	struct mutex c_ima_write_mutex;
	unsigned long c_ima_fs_flags;
	int valid_policy;
	extern spinlock_t c_ima_queue_lock;
	struct dentry *c_ima_policy;
	struct dentry *container_dir;
	struct dentry *binary_runtime_measurements;
	struct dentry *ascii_runtime_measurements;
	struct dentry *runtime_measurements_count;
	struct dentry *violations;
	struct dentry *active;

};

/* Internal container IMA function definitions */
int container_keyring_init();
int container_ima_fs_init();
long container_ima_vtpm_setup(int, struct tpm_chip *, struct container_data *);
struct file *container_ima_retrieve_file(struct mmap_args_t *);
struct container_ima_data *get_data_from_container_id(int);
struct container_ima_inode_data *container_ima_retrieve_inode_data(int, struct file *);
int container_ima_collect_measurement(struct mmap_args_t *, int, struct modsid *, struct integrity_iinit_cache *);
struct integrity_iinit_cache *container_integrity_inode_find(struct inode *, int);
struct integrity_iinit_cache *container_integrity_inode_get(struct inode *, int);
void container_ima_add_violation(struct file *, const unsigned char *,
		       struct integrity_iint_cache *,
		       const char *, const char *, int);
static void container_ima_rdwr_violation_check(struct file *, struct integrity_iint_cache *,
				     int, char **, const char **, char *, int);
int container_ima_process_measurement(struct file *, const struct cred *,
			       u32, char *, loff_t, int, int, struct mmap_args_t *);
int container_ima_add_template_entry(struct ima_template_entry *, int,
			   const char *, struct inode *,
			   const unsigned char *, int);
int container_ima_store_template(struct ima_template_entry *,
		       int, struct inode *,
		       const unsigned char *, int);
int container_ima_store_measurement(struct mmap_args_t *, int, struct integrity_iinit_cache *, 
                struct file *, struct modsig, struct ima_template_desc *); 
int container_ima_init(int);
int syscall__probe_entry_mmap(struct pt_regs *, void *, size_t, int, int, int, off_t);
int syscall__probe_ret_mmap(struct pt_regs *);
int container_ima_cleanup();
static int container_ima_init(void);
static void container_ima_exit(void);
