/*
 * Project for comsE6118:
 * Container IMA using eBPF
 * Fall 2022
 *
 * Avery Blanchard, agb2178
 */
#include <linux/module.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/printk.h>
#include <linux/ima.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <keyutils.h>
#include <keys/system_keyring.h>
#include "ima.h"

#define MODULE_NAME "ContainerIMA"
#define INTEGRITY_KEYRING_IMA 1
#define PCR 10
const char *measure_log_dir = "/secure/container_ima/"; // in this dir, per container measurement logs 
struct vtpm_proxy_new_dev *container_vtpms;
struct container_data *head;
struct container_data *cur;
struct tpm_chip *ima_tpm_chip;
int host_inum;
static struct rb_root container_integrity_iint_tree = RB_ROOT;
static DEFINE_RWLOCK(container_integrity_iint_lock);

/* mapping of id to system call arguments */
BPF_HASH(active_mmap_args_map, uint64, struct mmap_args_t);


/*
notes 
use integrity_iint_cache, not namespace specific
ima_collect_measurement
write own store measurement
*/
struct mmap_args_t {
	void *addr;
	size_t length;
	int prot;
	int flags;
	int fd;
	off_t offset
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
};
struct container_data {
	struct vtpm_proxy_new_dev vtpm;
	int container_id;
	inr keyring;
	struct file *ml;
	struct container_ima_hash *hash; 
	int policy_num; 
	struct container_data *next;
	struct container_ima_inode_data *head_inode;
};

int container_ima_fs_init() 
{
	int res;
	mode_t dir_mode= 0755;

	res = mkdir(measure_log_dir, dir_mode);

	return res;
}
/*
 * container_keyring_init 
 * 
 * 
 * https://man7.org/linux/man-pages/man7/keyrings.7.html
 * https://man7.org/linux/man-pages/man2/add_key.2.html 
 */
int container_keyring_init()
{
	return 0;
}
/*
 * container_keyring_add_key
 * create key from loading the vTPM x.509 cert
 */
int container_keyring_add_key() 
{
	return 0;
}
/*
 * ima_vtpm_setup 
 *
 * Set up per container vTPM, PCR 10 for IMA
 * https://elixir.bootlin.com/linux/latest/source/drivers/char/tpm/tpm_vtpm_proxy.c 
 * https://www.kernel.org/doc/html/v4.13/security/tpm/tpm_vtpm_proxy.html
 * https://elixir.bootlin.com/linux/v6.0.5/source/drivers/char/tpm/tpm_vtpm_proxy.c#L624 
 */
long container_ima_vtpm_setup(int container_id, struct tpm_chip *ima_tpm_chip, struct container_data *data) 
{
	struct vtpm_proxy_new_dev *new_vtpm;
	long ret;
	int ioctl; 
	struct file *vtpm_file;
	const char *vtpm_fd_name;
	char id[10];
	int check;
	
	new_vtpm = kmalloc(sizeof(struct vtpm_proxy_new_dev), GFP_KERNEL);
	if (!new_vtpm) {
		pr_err("kmalloc failed\n");
	}

	check = sprintf(id, "%d", container_id);
	if (check < 0)
		pr_err("sprintf fails in vtpm setup \n");
	
	check = strcat_s("/dev/vtpm", id);
	if (check == -1)
		pr_err("strcat_s fails in vtpm setup\n");

	new_vtpm.flags = VTPM_PROXY_FLAG_TPM2;
	new_vtpm.tpm_num = container_id;
	new_vtpm.fd = "/dev/vtpm";
	new_vtpm.major = MAJOR(ima_tpm_chip->device->devt); // MAJOR(dev_t dev); major number of the TPM device
	new_vtp.minor = MINOR(ima_tpm_chip->device->devt); // MINOR(dev_t dev); minor number of the TPM device


	ret = vtpmx_ioc_new_dev(vtpm_file, ioctl, (unsigned long)&new_vtpm);
	
	if (ret != 0) {
		pr_err("Failed to create a new vTPM device\n");
	}

	data->vtpm = new_vtpm;
	return ret;
	
}
/*
 * retrieve the file from mmap arguments
 *
 * https://elixir.bootlin.com/linux/v6.0.9/source/mm/mmap.c#L1586 
 */
struct file *container_ima_retrieve_file(struct mmap_args_t *args) 
{
	int ret;
	struct file *file;

	/* Get file from fd, len, and address for measurment */
	if (!(flags & MAP_ANONYMOUS)) {
		audit_mmap_fd(fd, flags);
		file = fget(args->fd);
		if (!file) {
			pr_error("fget fails\n");
		}
		if (is_file_hugepages(file)) {
			args->len = ALIGN(len, huge_page_size(hstate_file(file)));
		} else if (unlikely(flags & MAP_HUGETLB)) {
			file = NULL;
			goto out;
		}
	} else if (flags & MAP_HUGETLB) {
		struct hstate *hs;
		hs =  hstate_sizelog((flags >> MAP_HUGE_SHIFT) & MAP_HUGE_MASK);
		if (!hs) {
			ret = -EINVAL;
			return ret;
		}
		len = ALIGN(len, huge_page_size(hs));
		file = hugetlb_file_setup(HUGETLB_ANON_FILE, len,
				VM_NORESERVE,
				HUGETLB_ANONHUGE_INODE,
				(flags >> MAP_HUGE_SHIFT) & MAP_HUGE_MASK);
		if (IS_ERR(file)) {
			ret = PTR_ERR(file);
			retrun ret;
		}
	}
	return file;
 }
 /*
  * data_from_container_id
  * 
  * Retiever container_data struct using id
  * For later, when adding multiple containers
  */
 struct container_data *data_from_container_id(int container_id)
 {
	struct container_data *cur;
	return head;
 }
 /*
  *
  * 
  */
 struct container_ima_inode_data *container_ima_retrieve_inode_data(int container_id, struct file *file)
 {

 }
 /*
  * measure
  *
  * Get file from mmap args and measure
  * Add a per ima inode mutex, hold before measuring/reading
  */
 int container_ima_collect_measurement(struct mmap_args_t *args, int container_id, struct modsid *modsig, struct integrity_iinit_cache *iint) 
 {
	int ret;
	struct file *file, *f;
	struct inode *inode;
	const char *filename;
	struct container_data *data;
	struct ima_max_digest_data hash;
	struct container_ima_hash *hash_data;
	void *buf;
	int length;
	loff_t i_size;
	loff_t offset; 

	file = retrieve_file(args);
	if (!file) {
		pr_err("error retrieving file\n");
		return -1;
	}

	inode = file_inode(file);
	filename = file->f_path.dentry->d_name.name;

	data = data_from_container_id(container_id);
	if (!data) {
		pr_err("unable to get container data from id\n");
		return -1;
	}

	hash_data = data->hash;
	hash.hdr.algo = hash_data->algo;
	hash.hdr.lenght = hash_data->length;

	/* zero out, in case of failue */
	memset(&hash.digest, 0, sizeof(hash.digest));

	/* If it cannot read, handle later */
	if (!(file->f_mode & FMODE_READ)) {
		pr_err("Cannot read\n");
		return -1;
	}
	f = file;
	/*
	Attempt to use existing IMA function 
	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	
	while (offset < i_size) {
		int buf_len; 
		buf_len = integrity_kernel_read(file, offset, rbuf, PAGE_SIZE);
		if (buf_len < 0) {
			ret = buf_len;
			break;
		}
		if (buf_len == 0) {
			ret = -EINVAL;
			break;
		}
		offset += buf_len;
		buf = crypto_shash_update(shash, buf, buf_len);
		if (buf)
			break;
	}
	kfree(buf);
out:
*/
	return ima_calc_file_shash(f, hash);

 }
struct integrity_iinit_cache *container_integrity_inode_find(struct inode *inode, int container_id)
 {
	struct integrity_iint_cache *iint;
	struct rb_node *node = container_integrity_iint_tree.rb_node; // root inode for per container tree, start one 
	
	while (node) {
		iint = rb_entry(node, struct integrity_iint_cache, rb_node);

		if (inode < iint->inode)
			node = node->rb_left;
		else if (inode > iint->inode)
			node = node->rb_right;
		else
			break;
	}
	if (!node)
		return NULL;

	return iint;
}
 /*
  * container_integrity_inode_get 
  * find or allocate iint asscoiated with an inode 
  * lock i_mutex
  * 
  * container specifics:
  * 	1. original function traverses rb tree, so use container id to access to correct rb tree?
  * 		figure out how to handle this, mantaining the seperate trees is going to be $
  *     
  */
 struct integrity_iinit_cache *container_integrity_inode_get(struct inode *inode, int container_id)
 {
	 struct integrity_iint_cache *iint, tmp;
	 struct rb_node **ptr;
	 struct rb_node *node, *parent;
	
	iinit = container_integrity_inode_find(inode, container_id);
		if (iint)
		return iint;

	iint = kmem_cache_alloc(iint_cache, GFP_NOFS);
	if (!iint)
		return NULL;

	write_lock(&container_integrity_iint_lock);

	ptr = &container_integrity_iint_tree.rb_node;
	while (*ptr) {
		parent = *ptr;
		tmp = rb_entry(parent, struct integrity_iinit_cache, rb_node);
		if (inode < tmp->inode)
			ptr = &(*ptr)->rb_left;
		else
			ptr = &(*ptr)->rb_right;
	}
	iinit->inode = inode;
	node = &iinit->rb_node;
	inode->i_flags |= S_IMA;
	rb_link_node(node, parent, ptr);
	rb_insert_color(node, &container_iinit_tree);

	write_unlock(&integrity_iint_lock);
	return iint;

 }
/*
 * container_ima_setup
 *
 * Set up environment to initalize container IMA
 * Malloc structure to hold container ids and other data to preserve state
 */
void container_ima_setup()
{
	ima_hash_setup();

}
void container_ima_add_violation(struct file *file, const unsigned char *filename,
		       struct integrity_iint_cache *iint,
		       const char *op, const char *cause, int container) 
{
	struct ima_template_entry *entry;
	struct inode *inode = file_inode(file);
	struct ima_event_data event_data = { .iint = iint,
					     .file = file,
					     .filename = filename,
					     .violation = cause };
	int violation = 1;
	int result;

	/* can overflow, only indicator */
	atomic_long_inc(&ima_htable.violations);

	result = ima_alloc_init_template(&event_data, &entry, NULL);
	if (result < 0) {
		result = -ENOMEM;
		goto err_out;
	}
	result = container_ima_store_template(entry, violation, inode,
				    filename, CONFIG_IMA_MEASURE_PCR_IDX);
	if (result < 0)
		container_ima_free_template_entry(entry);
err_out:
	container_integrity_audit_msg(AUDIT_INTEGRITY_PCR, inode, filename,
			    op, cause, result, 0, container_id);

}
static void container_ima_rdwr_violation_check(struct file *file,
				     struct integrity_iint_cache *iint,
				     int must_measure,
				     char **pathbuf,
				     const char **pathname,
				     char *filename, int container_id)
{
	struct inode *inode = file_inode(file);
	fmode_t mode = file->f_mode;
	bool send_t = false;
	bool send_w = false;

	if (mode & FMODE_WRITE) {
		if (atomic_read(&inode->i_readcount) && IS_IMA(inode)) {
			if (!iint)
				iint = container_integrity_iint_find(inode, container_id);
			if (iint && test_bit(IMA_MUST_MEASURE,
						&iint->atomic_flags))
				send_t = true;
		}
	} else {
		if (must_measure)
			set_bit(IMA_MUST_MEASURE, &iint->atomic_flags);
		if (inode_is_open_for_write(inode) && must_measure)
			send_w = true;
	}

	if (!send_t && !send_w)
		return;

	*pathname = ima_d_path(&file->f_path, pathbuf, filename); // try to use IMA's ima_d_path, don't see any issues so far

	if (send_t)
		container_ima_add_violation(file, *pathname, iint,
				  "invalid_pcr", "ToMToU", container_id);
	if (send_w)
		container_ima_add_violation(file, *pathname, iint,
				  "invalid_pcr", "open_writers", container_id);
}
/*
 * process_measurement
 * https://elixir.bootlin.com/linux/latest/source/security/integrity/ima/ima_main.c#L201
 */
int container_ima_process_measurement(struct file *file, const struct cred *cred,
			       u32 secid, char *buf, loff_t size, int mask, int container_id, struct mmap_args_t *args) 
{
	struct inode *inode;
	struct integrity_iinit_cache *iint = NULL;
	struct ima_template_desc *template_desc = NULL;
	char filename[NAME_MAX];
	const char *pathname = NULL;
	struct container_data *data;
	int ret, action, appraisal; 
	struct evm_ima_xattr_data *xattr_value = NULL;
	struct modsig *modsig = NULL;
	int xattr_len = 0;
	bool violation_check;
	enum hash_algo hash_algo;
	unsigned int allowed_algos = 0;

	inode = file_inode(file);


	if (!ima_policy_flag || !S_ISREG(inode->i_mode))
		return 0;

	action  = ima_get_action(file_mnt_user_ns(file), inode, cred, secid,
				mask, func, &pcr, &template_desc, NULL,
				&allowed_algos);
	
	violation_check = ((func == FILE_CHECK || func == MMAP_CHECK) &&
			   (ima_policy_flag & IMA_MEASURE));
	
	if (!action && !violation_check)
		return 0;
	
	//appraisal = action & IMA_APPRAISE; // implement apprasial in future
	if (action & IMA_FILE_APPRAISE)
		func = FILE_CHECK;
	

	inode_lock(inode);

	if (action) {
		iint = container_integrity_inode_get(inode, container_id);
		if (!iint)
			ret = -ENOMEM;
	}

	// handle violations 
	if (!ret && violation_check)
		container_ima_rdwr_violation_check(file, iint, action & IMA_MEASURE,
					 &pathbuf, &pathname, filename, container_id); //rewirte this func to write to container specific log and use vTPM

	inode_unlock(inode);
	if (ret || !action)
		return 0;

	mutex_lock(&iint->mutex);

	if (test_and_clear_bit(IMA_CHANGE_ATTR, &iint->atomic_flags))
		iint->flags &= ~(IMA_APPRAISE | IMA_APPRAISED |
				 IMA_APPRAISE_SUBMASK | IMA_APPRAISED_SUBMASK |
				 IMA_NONACTION_FLAGS);

	if (test_and_clear_bit(IMA_CHANGE_XATTR, &iint->atomic_flags) ||
	    ((inode->i_sb->s_iflags & SB_I_IMA_UNVERIFIABLE_SIGNATURE) &&
	     !(inode->i_sb->s_iflags & SB_I_UNTRUSTED_MOUNTER) &&
	     !(action & IMA_FAIL_UNVERIFIABLE_SIGS))) {
		iint->flags &= ~IMA_DONE_MASK;
		iint->measured_pcrs = 0;
	}
	iint->flags |= action;
	action &= IMA_DO_MASK;
	action &= ~((iint->flags & (IMA_DONE_MASK ^ IMA_MEASURED)) >> 1);

	if ((action & IMA_MEASURE) && (iint->measured_pcrs & (0x1 << pcr)))
		action ^= IMA_MEASURE;
	
	if ((action & IMA_HASH) &&
	    !(test_bit(IMA_DIGSIG, &iint->atomic_flags))) {
		xattr_len = ima_read_xattr(file_dentry(file), &xattr_value);
		if ((xattr_value && xattr_len > 2) &&
		    (xattr_value->type == EVM_IMA_XATTR_DIGSIG))
			set_bit(IMA_DIGSIG, &iint->atomic_flags);
		iint->flags |= IMA_HASHED;
		action ^= IMA_HASH;
		set_bit(IMA_UPDATE_XATTR, &iint->atomic_flags);
	}
	// write mmap violation checker in future?
	// decide where to put ML for containers
	// here normal ima reads from security.ima

	if ((action & IMA_APPRAISE_SUBMASK) ||
	    strcmp(template_desc->name, IMA_TEMPLATE_IMA_NAME) != 0) {
			if (iint->flags & IMA_MODSIG_ALLOWED) {
			ret = ima_read_modsig(func, buf, size, &modsig);

			if (!ret && ima_template_has_modsig(template_desc) &&
			    iint->flags & IMA_MEASURED)
				action |= IMA_MEASURE;
		}
	}
	data = data_from_container_id(container_id);
	if (!data) {
		pr_err("unable to get container data from id\n");
		return -1;
	}

	hash_data = data->hash;
	hash.hdr.algo = hash_data->algo;
	hash.hdr.lenght = hash_data->length;
	
	ret = collect_measurement(args, container_id, modsig, iint);
	if (ret != 0) {
		pr_err("collecting measurement failed\n");
		goto out;
	}
	if (action & IMA_MEASURE)
		store_measurement(args, container_id, iinit, file, modsig,template_desc);
	
	// appraisal would go here

	if (action & IMA_AUDIT)
		ima_audit_measurement(iint, pathname);

	if ((file->f_flags & O_DIRECT) && (iint->flags & IMA_PERMIT_DIRECTIO))
		ret = 0;

out:
	if ((mask & MAY_WRITE) && test_bit(IMA_DIGSIG, &iint->atomic_flags) &&
	     !(iint->flags & IMA_NEW_FILE))
		ret = -EACCES;
	mutex_unlock(&iint->mutex);
	ima_free_modsig(modsig);

}
int container_ima_add_template_entry(struct ima_template_entry *entry, int violation,
			   const char *op, struct inode *inode,
			   const unsigned char *filename, int container_id)
{
	u8 *digest = entry->digests[ima_hash_algo_idx].digest;
	struct tpm_digest *digests_arg = entry->digests;
	const char *audit_cause = "hash_added";
	char tpm_audit_cause[AUDIT_CAUSE_LEN_MAX];
	int audit_info = 1;
	int result = 0, tpmresult = 0;

	// create a mutex per container list 

	/* 
	 * hash table lookup, need to reimplement for container specific hash tables 
	 * https://elixir.bootlin.com/linux/latest/source/security/integrity/ima/ima_queue.c#L48 
	 */
	if (!violation && !IS_ENABLED(CONFIG_IMA_DISABLE_HTABLE)) {
		if (ima_lookup_digest_entry(digest, entry->pcr)) {
			audit_cause = "hash_exists";
			result = -EEXIST;
			goto out;
		}
	}
	/*
	 * add digest to the hashtable, need to reimplement for container specific hash tables 
	 * https://elixir.bootlin.com/linux/latest/source/security/integrity/ima/ima_queue.c#L93 
	 */
	res = container_ima_add_digest_entry(entry, container_id);

	if (res < 0) {
		audit_cause = "ENOMEM";
		audit_info = 0;
		goto out;
	}	

	/* if violation occurs, invalidate the PCR */
	if (violation)
		digest_args = digests;
	
	/* 
	 * extend PCR of container's vTPM, figure out functions for extending vTPM 
	 * https://elixir.bootlin.com/linux/latest/source/drivers/char/tpm/tpm-interface.c#L314 
	 */
	res = vtpm_pcr_extend(digest_args, entry->pcr, container_id);
	if (res != 0) {
		pr_err("vTPM failed\n");
		audit_info = 0;
	}
out:
	// unlock ml mutex here
	return res;


}
int container_ima_store_template(struct ima_template_entry *entry,
		       int violation, struct inode *inode,
		       const unsigned char *filename, int container_id)
{
	int res;
	static contst char op[] = "add_template_measure";
	static const char audit_cause[] = "ENOMEM";
	char *template_name = entry->template_desc->name;

	if (!violation) {
		// try to use IMA's hashing functions, hash should be in entry->digests[tfm_idx].digest
		res = ima_calc_field_array_hash(&entry->template_data[0],
						   entry, container_id);
		if (res < 0) {
			// error, add logging
			pr_err("error calculating hash\n");
			return 0;
		}

	}
	entry->pcr = PCR;
	// Add template list to ML and hash table, and extend the PCR
	res = container_ima_add_template_entry(entry, violation, op, inode, filename, container_id);

	return res;

}
/*
 * store_measurement
 * store file measurement, later add mutexes
 * https://elixir.bootlin.com/linux/latest/source/security/integrity/ima/ima_api.c#L339
 * https://elixir.bootlin.com/linux/latest/source/security/integrity/ima/ima_queue.c#L159
 * Notes; change to use struct integrity_iint_cache 
 */
int container_ima_store_measurement(struct mmap_args_t *arg , int container_id, struct integrity_iinit_cache *iint, struct file *file, struct modsig modsig, struct ima_template_desc *template_desc) 
{
	struct inode *inode;
	struct ima_template_entry *entry;
	struct container_ima_event_data *event;
	struct container_data *data;
	static contst char op[] = "add_template_measure";
	static const char audit_cause[] = "ENOMEM";
	int res;

	inode = file_inode(file);

	data = data_from_container_id(container_id);
	if (!data) {
		pr_err("unable to get container data from id\n");
		return -1;
	}
	if (iint->measured_pcrs & (0x1 << PCR) && !modsig)
		return 0;

	// write own func to allocate template 
	//res = init_template(&event_data, entry, template_desc, container_id);
	// going to need to rewrite store template due to host specific stuff
	res = container_ima_store_template(entry, violation, inode, filename, container_id);
	if ((!res || res == -EEXIST) && !(file->f_flags & O_DIRECT)) {
		iint->flags |= IMA_MEASURED;
		iint->measured_pcrs |= (0x1 << PCR);
	}
	if (res < 0)
		ima_free_template_entry(entry);
	
	return 0;

}
/*
 * container_ima_crypto_init
 * 
 * Iterate over PCRs, check algorithm for PCR10 and record
 */
int container_ima_crypto_init(struct container_data *data)
{
	int ret;
	int i;


	return 0;

}
/*
 * container_ima_init
 *
 * Initalize container IMA
 * Create vTPM proxy using container_id as its number
 * Create measurment log 
 * Default policy 
 * 
 * use struct ima_digest_data so you can use IMA measurement functions 
 * https://elixir.bootlin.com/linux/v6.0.9/source/security/integrity/integrity.h#L99
 * 
 * To do:
 * - Seperate policies per container 
 * - Seperate key ring? 
 * - Secure FS instance per container or store all logs in the same instance?
 * - Would having the vtpm device number relate to the container namespace ID be a problem for keylime?
 * - Visability of vTPM to the container? Require container-side config?
 */
int container_ima_init(int container_id) 
{
	int ret;
	struct container_data *data;

	data = kmalloc(size_of(struct container_data), GFP_KERNEL);
	if (!data) {
		pr_error("kmalloc failed\n");
		return -1;
	}
	ima_tpm_chip = tpm_default_chip();
	if (!ima_tpm_chip)
		pr_info("No TPM chip found, activating TPM-bypass!\n");

	container_ima_vtpm = ima_vtpm_setup(container_id, ima_tpm_chip, data); // per container vTPM

	//ret = integrity_init_keyring(INTEGRITY_KEYRING_IMA); // per container key ring

	data->keyring = INTEGRITY_KEYRING_IMA;

	if (ret)
		return ret;
	ret = container_ima_crypto_init(container_id, data); // iterate over PCR banks and init the algorithms per bank  

	if (ret)
		return ret;

	ret = container_ima_ml_init(container_id); // set up directory for per container Measurment Log

	if (ret) 
		return ret;

	container_ima_policy_init(container_id); // start with default policy for all containers

	return ret;
}

/*
 * syscall__probe_entry_mmap
 * 
 * void *mmap(void *addr, size_t length, int prot, int flags,
 * 		int fd, off_t offset);
 *
 * https://man7.org/linux/man-pages/man2/mmap.2.html
 *
 * Entry hook for mmap system call 
 */
int syscall__probe_entry_mmap(struct pt_regs *ctx, void *addr, size_t length, int prot, int flags, int fd, off_t offset) 
{
	pr_info("In mmap probe entry\n");
	uint64_t id = bpf_get_current_pid_tgid();
	
	struct mmap_args_t args = {};

	args.addr = addr;
	args.length = length;
	args.prot = prot;
	args.flags = flags;
	args.fd = fd;
	args.offset = offset;

	active_mmap_args_map.update(&id, &args);

	return 0;

}
/*
 * syscall__probe_ret_mmap 
 *
 * Exit hook for mmap system call
 */
int syscall__probe_ret_mmap(struct pt_regs *ctx) 
{
	/* if system call was 
	 * 	1. orginating from the container
	 * 	2. maps an executable page
	 * 	3. was successful
	 * then 
	 * 	1. access argument cache
	 * 	2. call functions to create hash digest, extend,
	 * 		and send to TPM for IMA per container.
	 */
	pr_into("In mmap probe return\n");

	int ret;
	struct task_struct *task;
	struct file *file;
	unsigned int inum;
	u32 sec_id;
	struct mmap_args_t *args = {};
	
	ret = 0;
	task =  bpf_get_current_task();
    inum = task->nsproxy->cgroup_ns->ns_common->inum;

	active_mmap_args_map.pop(&args);

	if (inum == host_inum) {
		return ret;
	}

	if (args->prot != PROT_READ && args->prot != PROR_EXEC) {
		return ret;
	}

	/* Check if container already has an active ML, create hash of page and add to ML */
	/* If not, create vTPM and key ring, create hash of page and add to ML */
	
	file = retrieve_file(args);
	if (!file) {
		pr_err("error retrieving file\n");
		return -1;
	}

	security_current_getsecid_subj(&secid);

	ret = ima_process_measurement(file, current_cred(), sec_id, NULL, 0, MAY_EXEC, inum, args);
	if (ret != 0) {
		pr_err("measurement fails\n");
		return ret;
	}

	return ret;


}
int container_ima_cleanup() {
	
	return 0;
}
static int container_ima_init(void)
{
	/* Start container IMA */
	int ret;
	struct task_struct *task;

	task = current;
	host_inum = task->nsproxy->cgroup_ns->ns_common->inum;

	head = NULL;
	cur = NULL;
	container_ima_setup();
	ret = container_ima_init();


	return ret;
}

static void container_ima_exit(void)
{
	/* Clean up 
	 * Free keyring and vTPMs
	 */
	int ret;
	ret = container_ima_cleanup();
	return ret;
}


module_init(container_ima_init);
module_exit(container_ima_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(MODULE_NAME);
MODULE_AUTHOR("Avery Blanchard");

