
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

#define CONTAINER_IMA_DIGEST_SIZE       SHA1_DIGEST_SIZE
#define IMA_TEMPLATE_IMA_NAME "container-ima"
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
    //int container_id;
};

/* Internal container IMA function definitions */
int container_keyring_init();
int container_ima_fs_init();
long container_ima_vtpm_setup(int, struct tpm_chip *, struct container_data *);
struct file *container_ima_retrieve_file(struct mmap_args_t *);
struct container_data *data_from_container_id(int);
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
