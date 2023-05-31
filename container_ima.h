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
extern int ima_hash_algo;
extern bool ima_canonical_fmt;

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


struct ima_h_table {
	atomic_long_t len;	/* number of stored measurements in the list */
	atomic_long_t violations;
	struct hlist_head queue[IMA_MEASURE_HTABLE_SIZE];
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
struct file *container_ima_retrieve_file(int);

#endif
