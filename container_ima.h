/*
 * container_ima.h
 * 		- define structs and functions for container IMA
 *  https://elixir.bootlin.com/linux/v4.19.259/source/security/integrity/ima/ima.h
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
#include <linux/list.h>
#include <linux/tpm.h>
#include <linux/tpm_command.h>
#include <linux/file.h>
#include <linux/hash.h>
#include <linux/vtpm_proxy.h>

enum ima_show_type { IMA_SHOW_BINARY, IMA_SHOW_BINARY_NO_FIELD_LEN,
		     IMA_SHOW_BINARY_OLD_STRING_FMT, IMA_SHOW_ASCII };
enum tpm_pcrs { TPM_PCR0 = 0, TPM_PCR8 = 8, TPM_PCR10 = 10 };

/* digest size for IMA, fits SHA1 or MD5 */
#define IMA_DIGEST_SIZE		SHA1_DIGEST_SIZE
#define IMA_EVENT_NAME_LEN_MAX	255

#define IMA_HASH_BITS 9
#define IMA_MEASURE_HTABLE_SIZE (1 << IMA_HASH_BITS)
/* iint action cache flags */
#define IMA_MEASURE		0x00000001
#define IMA_MEASURED		0x00000002
#define IMA_APPRAISE		0x00000004
#define IMA_APPRAISED		0x00000008
/*#define IMA_COLLECT		0x00000010  do not use this flag */
#define IMA_COLLECTED		0x00000020
#define IMA_AUDIT		0x00000040
#define IMA_AUDITED		0x00000080
#define IMA_HASH		0x00000100
#define IMA_HASHED		0x00000200

/* iint cache flags */
#define IMA_ACTION_FLAGS	0xff000000
#define IMA_DIGSIG_REQUIRED	0x01000000
#define IMA_PERMIT_DIRECTIO	0x02000000
#define IMA_NEW_FILE		0x04000000
#define EVM_IMMUTABLE_DIGSIG	0x08000000
#define IMA_FAIL_UNVERIFIABLE_SIGS	0x10000000

#define IMA_DO_MASK		(IMA_MEASURE | IMA_APPRAISE | IMA_AUDIT | \
				 IMA_HASH | IMA_APPRAISE_SUBMASK)
#define IMA_DONE_MASK		(IMA_MEASURED | IMA_APPRAISED | IMA_AUDITED | \
				 IMA_HASHED | IMA_COLLECTED | \
				 IMA_APPRAISED_SUBMASK)

/* iint subaction appraise cache flags */
#define IMA_FILE_APPRAISE	0x00001000
#define IMA_FILE_APPRAISED	0x00002000
#define IMA_MMAP_APPRAISE	0x00004000
#define IMA_MMAP_APPRAISED	0x00008000
#define IMA_BPRM_APPRAISE	0x00010000
#define IMA_BPRM_APPRAISED	0x00020000
#define IMA_READ_APPRAISE	0x00040000
#define IMA_READ_APPRAISED	0x00080000
#define IMA_CREDS_APPRAISE	0x00100000
#define IMA_CREDS_APPRAISED	0x00200000
#define IMA_APPRAISE_SUBMASK	(IMA_FILE_APPRAISE | IMA_MMAP_APPRAISE | \
				 IMA_BPRM_APPRAISE | IMA_READ_APPRAISE | \
				 IMA_CREDS_APPRAISE)
#define IMA_APPRAISED_SUBMASK	(IMA_FILE_APPRAISED | IMA_MMAP_APPRAISED | \
				 IMA_BPRM_APPRAISED | IMA_READ_APPRAISED | \
				 IMA_CREDS_APPRAISED)

/* iint cache atomic_flags */
#define IMA_CHANGE_XATTR	0
#define IMA_UPDATE_XATTR	1
#define IMA_CHANGE_ATTR		2
#define IMA_DIGSIG		3
#define IMA_MUST_MEASURE	4

enum evm_ima_xattr_type {
	IMA_XATTR_DIGEST = 0x01,
	EVM_XATTR_HMAC,
	EVM_IMA_XATTR_DIGSIG,
	IMA_XATTR_DIGEST_NG,
	EVM_XATTR_PORTABLE_DIGSIG,
	IMA_XATTR_LAST
};

struct evm_ima_xattr_data {
	u8 type;
	u8 digest[SHA1_DIGEST_SIZE];
} __packed;

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

/* iint cache flags */
#define IMA_ACTION_FLAGS	0xff000000
#define IMA_DIGSIG_REQUIRED	0x01000000
#define IMA_PERMIT_DIRECTIO	0x02000000
#define IMA_NEW_FILE		0x04000000
#define EVM_IMMUTABLE_DIGSIG	0x08000000
#define IMA_FAIL_UNVERIFIABLE_SIGS	0x10000000

#define IMA_DO_MASK		(IMA_MEASURE | IMA_APPRAISE | IMA_AUDIT | \
				 IMA_HASH | IMA_APPRAISE_SUBMASK)
#define IMA_DONE_MASK		(IMA_MEASURED | IMA_APPRAISED | IMA_AUDITED | \
				 IMA_HASHED | IMA_COLLECTED | \
				 IMA_APPRAISED_SUBMASK)

/* iint subaction appraise cache flags */
#define IMA_FILE_APPRAISE	0x00001000
#define IMA_FILE_APPRAISED	0x00002000
#define IMA_MMAP_APPRAISE	0x00004000
#define IMA_MMAP_APPRAISED	0x00008000
#define IMA_BPRM_APPRAISE	0x00010000
#define IMA_BPRM_APPRAISED	0x00020000
#define IMA_READ_APPRAISE	0x00040000
#define IMA_READ_APPRAISED	0x00080000
#define IMA_CREDS_APPRAISE	0x00100000
#define IMA_CREDS_APPRAISED	0x00200000
#define IMA_APPRAISE_SUBMASK	(IMA_FILE_APPRAISE | IMA_MMAP_APPRAISE | \
				 IMA_BPRM_APPRAISE | IMA_READ_APPRAISE | \
				 IMA_CREDS_APPRAISE)
#define IMA_APPRAISED_SUBMASK	(IMA_FILE_APPRAISED | IMA_MMAP_APPRAISED | \
				 IMA_BPRM_APPRAISED | IMA_READ_APPRAISED | \
				 IMA_CREDS_APPRAISED)


/* iint action cache flags */
#define IMA_MEASURE		0x00000001
#define IMA_MEASURED		0x00000002
#define IMA_APPRAISE		0x00000004
#define IMA_APPRAISED		0x00000008
/*#define IMA_COLLECT		0x00000010  do not use this flag */
#define IMA_COLLECTED		0x00000020
#define IMA_AUDIT		0x00000040
#define IMA_AUDITED		0x00000080
#define IMA_HASH		0x00000100
#define IMA_HASHED		0x00000200


#define IMA_HASH_BITS 9
#define IMA_MEASURE_HTABLE_SIZE (1 << IMA_HASH_BITS)

#define IMA_TEMPLATE_FIELD_ID_MAX_LEN	16
#define IMA_TEMPLATE_NUM_FIELDS_MAX	15
#define IMA_TEMPLATE_IMA_FMT "d|n"

#define IMA_MAX_DIGEST_SIZE	64
struct ima_digest_data {
	u8 algo;
	u8 length;
	union {
		struct {
			u8 unused;
			u8 type;
		} sha1;
		struct {
			u8 type;
			u8 algo;
		} ng;
		u8 data[2];
	} xattr;
	u8 digest[];
} __packed;

struct ima_hash {
	    struct ima_digest_data hdr;
	    char digest[2048];
};
static DEFINE_RWLOCK(container_integrity_iint_lock);

#define INVALID_PCR(a) (((a) < 0) || \
	(a) >= (sizeof_field(struct integrity_iint_cache, measured_pcrs) * 8))

enum policy_types { ORIGINAL_TCB = 1, DEFAULT_TCB };

enum policy_rule_list { IMA_DEFAULT_POLICY = 1, IMA_CUSTOM_POLICY };

extern struct tpm_chip *ima_tpm_chip;
extern struct c_ima_data_hash_table container_hash_table;
extern int ima_hash_algo;
extern bool ima_canonical_fmt;

/* Dentry for IMA measurment logs, policies, violations */
extern struct dentry *binary_runtime_measurements; 
extern struct dentry *ascii_runtime_measurements;
extern struct dentry *violations;
extern struct dentry *policy;

extern struct ima_data *data;
struct ima_rule_entry {
	struct list_head list;
	int action;
	int flags;
	int pcr;
	int mask;
}; // add to this as needed

/* struct for BPF argument mappings */
struct mmap_args {
	size_t length;
	int prot;
	int flags;
	int fd;
	unsigned int ns;
};

/* IMA event related data */
struct ima_event_data {
	struct integrity_iint_cache *iint;
	struct file *file;
	const unsigned char *filename;
	struct evm_ima_xattr_data *xattr_value;
	int xattr_len;
	const char *violation;
	const void *buf;
	int buf_len;
};

/* IMA template field data definition */
struct ima_field_data {
	u8 *data;
	u32 len;
};

/* IMA template field definition */
struct ima_template_field {
	const char field_id[IMA_TEMPLATE_FIELD_ID_MAX_LEN];
	int (*field_init)(struct ima_event_data *event_data,
			  struct ima_field_data *field_data);
	void (*field_show)(struct seq_file *m, enum ima_show_type show,
			   struct ima_field_data *field_data);
};

/* IMA template descriptor definition */
struct ima_template_desc {
	struct list_head list;
	char *name;
	char *fmt;
	int num_fields;
	const struct ima_template_field **fields;
};

struct ima_template_entry {
	int pcr;
	struct tpm_digest *digests;
	struct ima_template_desc *template_desc; /* template descriptor */
	u32 template_data_len;
	struct ima_field_data template_data[];	/* template related data */
};

struct ima_queue_entry {
	struct hlist_node hnext;	/* place in hash collision list */
	struct list_head later;		/* place in ima_measurements list */
	struct ima_template_entry *entry;
};


struct c_ima_hash_table {
    atomic_long_t size;
    atomic_long_t violations;
    struct hlist_head queue[CONTAINER_IMA_HTABLE_SIZE];
};

struct ima_h_table {
	atomic_long_t len;	/* number of stored measurements in the list */
	atomic_long_t violations;
	struct hlist_head queue[IMA_MEASURE_HTABLE_SIZE];
};
struct c_ima_queue_entry {
	struct hlist_node hnext;
	unsigned int id;
	struct ima_data *data;
};

struct c_ima_data_hash_table {
    struct hlist_head queue[CONTAINER_IMA_HTABLE_SIZE];
	atomic_long_t len;
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
struct hash {
		struct ima_digest_data hdr;
		char digest[IMA_MAX_DIGEST_SIZE];
};

struct ima_data {
        long len; // number of digest
        long violations; // violations count 
        //spinlock_t queue_lock;
        struct hlist_head queue[CONTAINER_IMA_HTABLE_SIZE]; // hash table queue
        /* policy configurations TODO */
        struct list_head measurements; // linked list of measurements 
        //unsigned long binary_runtime_size;
        //struct ima_h_table *hash_tbl;
        struct mutex ima_write_mutex;
        int policy_flags;
        struct rb_root iint_tree;
};

/* integrity data associated with an inode */
struct integrity_iint_cache {
	struct rb_node rb_node;	/* rooted in integrity_iint_tree */
	struct mutex mutex;	/* protects: version, flags, digest */
	struct inode *inode;	/* back pointer to inode in question */
	u64 version;		/* track inode changes */
	unsigned long flags;
	unsigned long measured_pcrs;
	unsigned long atomic_flags;
	enum integrity_status ima_file_status:4;
	enum integrity_status ima_mmap_status:4;
	enum integrity_status ima_bprm_status:4;
	enum integrity_status ima_read_status:4;
	enum integrity_status ima_creds_status:4;
	enum integrity_status evm_status:4;
	struct ima_digest_data *ima_hash;
};

/* Internal container IMA function definitions */
int container_ima_fs_init(void);
long container_ima_vtpm_setup(struct ima_data *, unsigned int, struct tpm_chip *);
struct file *container_ima_retrieve_file(int);
struct container_ima_inode_data *container_ima_retrieve_inode_data(struct ima_data *, int, struct file *);
int container_ima_collect_measurement(struct file *, struct mmap_args *, unsigned int, struct integrity_iint_cache *, enum hash_algo, void *, loff_t );
struct integrity_iint_cache *container_integrity_inode_find(struct ima_data *, struct inode *, unsigned int);
struct integrity_iint_cache *container_integrity_inode_get(struct ima_data *, struct inode *, unsigned int);
void container_ima_add_violation(struct ima_data *, struct file *, const unsigned char *,
		       struct integrity_iint_cache *,
		       const char *, const char *, unsigned int);
static void container_ima_rdwr_violation_check(struct ima_data *, struct file *, struct integrity_iint_cache *,
				     int, char **, const char **, char *, unsigned int);
int container_ima_process_measurement(struct ima_data *, struct mmap_args *, unsigned int, int);
int container_ima_add_template_entry(struct ima_data *data, struct ima_template_entry *entry, int violation,
			   const char *op, struct inode *inode,
			   const unsigned char *filename, unsigned int container_id);
int container_ima_store_template(struct ima_data *, struct ima_template_entry *,
		       int, struct inode *,
		       const char *, unsigned int);
int container_ima_store_measurement(struct ima_data *, struct mmap_args *, unsigned int, struct integrity_iint_cache *, 
                struct file *, struct ima_template_desc *, const char *); 
struct ima_data *init_container_ima(unsigned int container_id);
int container_ima_cleanup(void);
static int container_ima_init(void);
static void container_ima_exit(void);
struct container_ima *create_container_ima_data(void);
void container_ima_free_data(struct ima_data *);
int container_ima_get_action(struct ima_data *, struct inode *,
		   int);
int container_ima_match_policy(struct ima_data *, struct inode *,
		     int, int);
static int c_ima_seq_open(struct inode *, struct file *);
static struct ima_data *ima_data_from_file(const struct file *filp);
static struct c_ima_queue_entry *container_ima_lookup_data_entry(unsigned int id);
static struct ima_queue_entry *container_ima_lookup_digest_entry(struct ima_data *data, u8 *digest_value,
						       int pcr, unsigned int container_id);
static void *c_ima_measurements_next(struct seq_file *m, void *v, loff_t *pos);
static ssize_t c_ima_show_htable_violations(struct file *filp,
					  char __user *buf,
					  size_t count, loff_t *ppos);
static int container_ima_add_digest_entry(struct ima_data *data, struct ima_template_entry *entry);
struct ima_data *ima_data_exists(unsigned int id);
static int get_binary_runtime_size(struct ima_template_entry *entry);
//static int ima_get_verity_digest(struct integrity_iint_cache *iint,
			//	 struct ima_max_digest_data *hash);
void ima_audit_measurement(struct integrity_iint_cache *iint,
			   const unsigned char *filename);
const char *ima_d_path(const struct path *path, char **pathbuf, char *namebuf);
int ima_alloc_init_template(struct ima_event_data *event_data,
			    struct ima_template_entry **entry, struct ima_template_desc *template_desc);
void ima_free_template_entry(struct ima_template_entry *entry);
int ima_calc_file_hash(struct file *file, struct ima_digest_data *hash);
int ima_calc_buffer_hash(const void *buf, loff_t len,
			 struct ima_digest_data *hash);
void integrity_audit_msg(int audit_msgno, struct inode *inode,
			 const unsigned char *fname, const char *op,
			 const char *cause, int result, int audit_info);
//static int ima_calc_file_shash(struct file *file, struct ima_digest_data *hash);	
//static int ima_calc_file_ahash(struct file *file, struct ima_digest_data *hash);
//static void ima_free_atfm(struct crypto_ahash *tfm);
//static int ima_calc_file_hash_atfm(struct file *file,struct ima_digest_data *hash, struct crypto_ahash *tfm); 
//static void ima_free_pages(void *ptr, size_t size);
int integrity_kernel_read(struct file *file, loff_t offset,
			  void *addr, unsigned long count);
int container_ima_crypto_init(void);
//static void *ima_alloc_pages(loff_t max_size, size_t *allocated_size,int last_warn);
//static inline int ahash_wait(int err, struct crypto_wait *wait);
//static int param_set_bufsize(const char *val, const struct kernel_param *kp);
int __init ima_init_crypto(void);	
////static struct crypto_ahash *ima_alloc_atfm(enum hash_algo algo);
//static void ima_free_tfm(struct crypto_shash *tfm);
/*
static int ima_calc_file_hash_tfm(struct file *file,
				  struct ima_digest_data *hash,
				  struct crypto_shash *tfm);
static int calc_buffer_shash(const void *buf, loff_t len,
			     struct ima_digest_data *hash);
static int calc_buffer_ahash(const void *buf, loff_t len,
			     struct ima_digest_data *hash);
static int calc_buffer_shash_tfm(const void *buf, loff_t size,
				struct ima_digest_data *hash,
				struct crypto_shash *tfm);
static int calc_buffer_ahash_atfm(const void *buf, loff_t len,
				  struct ima_digest_data *hash,
				  struct crypto_ahash *tfm);
static struct crypto_shash *ima_alloc_tfm(enum hash_algo algo);
static int ima_calc_field_array_hash_tfm(struct ima_field_data *field_data,
					 struct ima_template_desc *td,
					 int num_fields,
					 struct ima_digest_data *hash,  struct crypto_shash *tfm);*/
int ima_calc_field_array_hash(struct ima_field_data *field_data,
			      struct ima_template_desc *desc, int num_fields,
			      struct ima_digest_data *hash); 
int ima_pcr_extend(struct tpm_digest *digests_arg, int pcr);
static int container_ima_add_data_entry(struct ima_data *data, long id);
//extern int process_mmap(struct mmap_args_t *args);
/*
 */
static inline unsigned long ima_hash_key(u8 *digest)
{
	return hash_long(*digest, IMA_HASH_BITS);
}
/*
 */
static inline unsigned long c_ima_hash_key(long *id)
{
	return hash_long(*id, IMA_HASH_BITS);
}
/*
 */
static inline enum hash_algo
ima_get_hash_algo(struct evm_ima_xattr_data *xattr_value, int xattr_len)
{
	return ima_hash_algo;
}
/* 
 */
static inline int ima_read_xattr(struct dentry *dentry,
				 struct evm_ima_xattr_data **xattr_value)
{
	return 0;
}
struct c_ima_data_hash_table container_hash_table = {
	.len = ATOMIC_LONG_INIT(0),
	.queue[0 ... IMA_MEASURE_HTABLE_SIZE - 1] = HLIST_HEAD_INIT
};

#endif
