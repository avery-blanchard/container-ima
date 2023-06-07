/*
 * File: container_ima.h
 * 	Definitions for IMA module 
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

#define IMA_TEMPLATE_FIELD_ID_MAX_LEN	16
#define IMA_MAX_DIGEST_SIZE	HASH_MAX_DIGESTSIZE
#define MAY_EXEC                0x00000001


extern int ima_hash_algo;

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
};/*
struct hash {
		struct ima_digest_data hdr;
		char digest[IMA_MAX_DIGEST_SIZE];
};*/

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

struct ebpf_data {
        struct file *file;
        unsigned int ns;
};

struct ima_max_digest_data {
        struct ima_digest_data hdr;
        u8 digest[HASH_MAX_DIGESTSIZE];
} __packed;

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

unsigned int host_inum;

extern int register_btf_kfunc_id_set(enum bpf_prog_type prog_type,
                              const struct btf_kfunc_id_set *kset);

extern int ima_file_hash(struct file *file, char *buf, size_t buf_size);

int (*ima_add_template_entry)(struct ima_template_entry *entry, 
		int violation, const char *op, struct inode *inode, 
		const unsigned char *filename);

int (*ima_calc_field_array_hash)(struct ima_field_data *field_data,
                              struct ima_template_entry *entry);

const char *(*ima_d_path)(const struct path *, char **, char *);

int (*ima_alloc_init_template)(struct ima_event_data *, 
		struct ima_template_entry **, struct ima_template_desc *);

int (*ima_store_template)(struct ima_template_entry *, int, 
		struct inode *, const unsigned char *, int);

struct ima_template_desc *(*ima_template_desc_current)(void);

void (*ima_free_template_entry)(struct ima_template_entry *);

int ima_hash_algo;

int ima_policy_flag;

int (*ima_calc_buffer_hash)(const void *, loff_t len, 
		struct ima_digest_data *); 

#define __ima_hooks(hook)                               \
        hook(NONE, none)                                \
        hook(FILE_CHECK, file)                          \
        hook(MMAP_CHECK, mmap)                          \
        hook(MMAP_CHECK_REQPROT, mmap_reqprot)          \
        hook(BPRM_CHECK, bprm)                          \
        hook(CREDS_CHECK, creds)                        \
        hook(POST_SETATTR, post_setattr)                \
        hook(MODULE_CHECK, module)                      \
        hook(FIRMWARE_CHECK, firmware)                  \
        hook(KEXEC_KERNEL_CHECK, kexec_kernel)          \
        hook(KEXEC_INITRAMFS_CHECK, kexec_initramfs)    \
        hook(POLICY_CHECK, policy)                      \
        hook(KEXEC_CMDLINE, kexec_cmdline)              \
        hook(KEY_CHECK, key)                            \
        hook(CRITICAL_DATA, critical_data)              \
        hook(SETXATTR_CHECK, setxattr_check)            \
        hook(MAX_CHECK, none)

#define __ima_hook_enumify(ENUM, str)   ENUM,
#define __ima_stringify(arg) (#arg)
#define __ima_hook_measuring_stringify(ENUM, str) \
                (__ima_stringify(measuring_ ##str)),

enum ima_hooks {
        __ima_hooks(__ima_hook_enumify)
};

int (*ima_get_action)(struct mnt_idmap *, struct inode *, 
		const struct cred *, u32,  int,  
		enum ima_hooks,  int *, 
		struct ima_template_desc **, 
		const char *, unsigned int *);

int (*ima_calc_field_array_hash)(struct ima_field_data *, 
		struct ima_template_entry *);

#endif
