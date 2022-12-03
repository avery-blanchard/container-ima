/*
 * File: container_ima_api.c
 *      Functions for collectins and storing file measurments
 */
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/ima.h>

#include "container_ima.h"

#define IMA_PCR 10
static struct kmem_cache *c_ima_iint_cache;

/*
 * container_ima_retrieve_file
 *      Retrieve the file from mmap arguments
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
  * container_ima_collect_measurement
  *     Get file from mmap args and measure
  */
 int container_ima_collect_measurement(struct container_ima_data *data, struct mmap_args_t *args, unsigned int container_id, struct modsid *modsig, struct integrity_iint_cache *iint) 
 {
	int ret;
	struct file *file, *f;
	struct inode *inode;
	const char *filename;
	struct container_ima_data *data;
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

	hash_data = data->hash_tbl;
	hash.hdr.algo = hash_data->algo;
	hash.hdr.length = hash_data->length;

	/* zero out, in case of failue */
	memset(&hash.digest, 0, sizeof(hash.digest));

	/* If it cannot read, handle later */
	if (!(file->f_mode & FMODE_READ)) {
		pr_err("Cannot read\n");
		return -1;
	}
	f = file;
	return ima_calc_file_shash(f, hash);

 }
 /*
  * container_integrity_inode_find
  *     Traverse rb_tree to see if the inode exists. If exits, return. Else, NULL.
  */
 struct integrity_iint_cache *container_integrity_inode_find(struct container_ima_data *data, struct inode *inode, unsigned int container_id)
 {
	struct integrity_iint_cache *iint;
	struct rb_node *node = data->container_integrity_iint_tree.rb_node; // root inode for per container tree, start one 
	
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
  * https://elixir.bootlin.com/linux/latest/source/security/integrity/iint.c#L95 
  *     
  */
 struct integrity_iint_cache *container_integrity_inode_get(struct container_ima_data *data, struct inode *inode, unsigned int container_id)
 {
	 struct integrity_iint_cache *iint, *tmp;
	 struct rb_node **ptr;
	 struct rb_node *node, *parent;
	
	iint = container_integrity_inode_find(data, inode, container_id);
		if (iint)
		return iint;

	iint = kmem_cache_alloc(c_ima_iint_cache, GFP_NOFS);
	if (!iint)
		return NULL;

	write_lock(&data->container_integrity_iint_lock);

	ptr = &data->container_integrity_iint_tree.rb_node;
	while (*ptr) {
		parent = *ptr;
		tmp = rb_entry(parent, struct integrity_iint_cache, rb_node);
		if (inode < tmp->inode)
			ptr = &(*ptr)->rb_left;
		else
			ptr = &(*ptr)->rb_right;
	}
	iint->inode = inode;
	node = &iint->rb_node;
	inode->i_flags |= S_IMA;
	rb_link_node(node, parent, ptr);
	rb_insert_color(node, &data->container_iint_tree);

	write_unlock(&data->integrity_iint_lock);
	return iint;

}
/*
 * container_ima_add_violation 
 *      Write violation to the measurement list
 * https://elixir.bootlin.com/linux/latest/source/security/integrity/ima/ima_api.c#L134
 */
void container_ima_add_violation(struct container_ima_data *data, struct file *file, const unsigned char *filename,
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

	/* try to use IMA's allocation function */
	result = ima_alloc_init_template(&event_data, &entry, NULL);
	if (result < 0) {
		result = -ENOMEM;
		goto err_out;
	}
	result = container_ima_store_template(data, entry, violation, inode,
				    filename, CONFIG_IMA_MEASURE_PCR_IDX);
	if (result < 0)
		ima_free_template_entry(entry);
err_out:
    // try to use IMA's audit messages? may be fine 
	integrity_audit_msg(AUDIT_INTEGRITY_PCR, inode, filename,
			    op, cause, result, 0, container_id);

}
/*
 * container_ima_rdwr_violation_check
 *      Conditionally invalidate PCR for measured files
 * https://elixir.bootlin.com/linux/latest/source/security/integrity/ima/ima_main.c#L115 
 */
static void container_ima_rdwr_violation_check(struct container_ima_data *data, struct file *file,
				     struct integrity_iint_cache *iint,
				     int must_measure,
				     char **pathbuf,
				     const char **pathname,
				     char *filename, unsigned int container_id)
{
	struct inode *inode = file_inode(file);
	fmode_t mode = file->f_mode;
	bool send_t = false;
	bool send_w = false;

	if (mode & FMODE_WRITE) {
		if (atomic_read(&inode->i_readcount) && IS_IMA(inode)) {
			if (!iint)
				iint = container_integrity_iint_find(data, inode, container_id);
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

    // are violations needed? yes
	if (send_t)
		container_ima_add_violation(data, file, *pathname, iint,
				  "invalid_pcr", "ToMToU", container_id);
	if (send_w)
		container_ima_add_violation(data, file, *pathname, iint,
				  "invalid_pcr", "open_wdata, riters", container_id);
}
/* 
 * container_ima_match_policy
 *		
 * https://elixir.bootlin.com/linux/latest/source/security/integrity/ima/ima_policy.c#L690
 */
int container_ima_match_policy(struct container_ima_data *data, struct user_namespace *mnt_userns, struct inode *inode,
		     const struct cred *cred, u32 secid,
		     int mask, int flags, int *pcr,
		     struct ima_template_desc **template_desc,
		     const char *func_data, unsigned int *allowed_algos)
{
	int action;
	int action_mask;

	action_mask = flags | (flags << 1);
	/* TODO edit this for future use with different policies per container */


	return IMA_DEFAULT_POLICY;

}
/*
 * container_ima_get_action
 *
 * Determine IMA policy for container 
 * https://elixir.bootlin.com/linux/latest/source/security/integrity/ima/ima_policy.c#L690 
 */
int container_ima_get_action(struct container_ima_data *data, struct user_namespace *mnt_userns, struct inode *inode,
		   const struct cred *cred, u32 secid, int mask, int *pcr,
		   struct ima_template_desc **template_desc,
		   const char *func_data, unsigned int *allowed_algos) 
{
	int action;
	int flag;
	
	flag = IMA_MEASURE | IMA_AUDIT | IMA_APPRAISE | IMA_HASH; // not implementing appraisal currently, maybe exclude
	flag &= data->c_ima_policy_flag;

	/* ima_match policy reads IMA tmp rules list, which for container IMA is per
	 * container and in struct container_data, re-write for different policies (later on)
	 */ 
	action = container_ima_match_policy(data, mnt_userns, inode, cred, secid, mask,
				flags, pcr, template_desc, allowed_algos);

	return action;
}
/*
 * container_ima_process_measurement
 * https://elixir.bootlin.com/linux/latest/source/security/integrity/ima/ima_main.c#L201
 */
int container_ima_process_measurement(struct container_ima_data *data, struct file *file, const struct cred *cred,
			       u32 secid, char *buf, loff_t size, int mask, unsigned int container_id, struct mmap_args_t *args) 
{
	struct inode *inode;
	struct integrity_iint_cache *iint = NULL;
	struct ima_template_desc *template_desc = NULL;
	char filename[NAME_MAX];
	const char *pathname = NULL;
	struct container_ima_data *data;
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

	/* re-write for future use of different IMA polcies per container */
	action  = container_ima_get_action(data, file_mnt_user_ns(file), inode, cred, secid,
				mask,&pcr, &template_desc, NULL,
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
		iint = container_integrity_inode_get(data, inode);
		if (!iint)
			ret = -ENOMEM;
	}

	// handle violations 
	if (!ret && violation_check)
		container_ima_rdwr_violation_check(data, file, iint, action & IMA_MEASURE,
					 &pathbuf, &pathname, filename, container_id);

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

	hash_data = data->hash;
	hash.hdr.algo = hash_data->algo;
	hash.hdr.lenght = hash_data->length;
	
	ret = container_ima_collect_measurement(data, args, container_id, modsig, iint);
	if (ret != 0) {
		pr_err("collecting measurement failed\n");
		goto out;
	}
	if (action & IMA_MEASURE)
		container_ima_store_measurement(data, args, container_id, iint, file, modsig,template_desc);
	
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
/*
 * container_ima_add_template_entry
 *      Add digest to the hashtable and extend PCR
 */
int container_ima_add_template_entry(struct container_ima_data *data, struct ima_template_entry *entry, int violation,
			   const char *op, struct inode *inode,
			   const unsigned char *filename, unsigned int container_id)
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
		if (container_ima_lookup_digest_entry(data, digest, PCR, container_id)) {
			audit_cause = "hash_exists";
			result = -EEXIST;
			goto out;
		}
	}
	/*
	 * add digest to the hashtable, need to reimplement for container specific hash tables 
	 * https://elixir.bootlin.com/linux/latest/source/security/integrity/ima/ima_queue.c#L93 
	 */
	res = container_ima_add_digest_entry(data, entry, container_id);

	if (res < 0) {
		audit_cause = "ENOMEM";
		audit_info = 0;
		goto out;
	}	

	/* if violation occurs, invalidate the PCR */
	if (violation)
		digest_args = digest;
	
	/* 
	 * extend PCR of container's vTPM, figure out functions for extending vTPM 
	 * https://elixir.bootlin.com/linux/latest/source/drivers/char/tpm/tpm-interface.c#L314 
	 */
	//res = vtpm_pcr_extend(digest_args, entry->pcr, container_id);
	res = ima_pcr_extend(digest_args, entry->pcr);
	if (res != 0) {
		pr_err("vTPM failed\n");
		audit_info = 0;
	}
out:
	// unlock ml mutex here
	// make this container specific? 
	integrity_audit_msg(AUDIT_INTEGRITY_PCR, inode, filename,
			    op, audit_cause, result, 0, container_id);
	return res;

}
/*
 * container_ima_store_template
 *     Calculate hash, add to ML and extend to PCR
 */
int container_ima_store_template(struct container_ima_data *data, struct ima_template_entry *entry,
		       int violation, struct inode *inode,
		       const unsigned char *filename, unsigned int container_id)
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
	res = container_ima_add_template_entry(data, entry, violation, op, inode, filename, container_id);

	return res;

}
/*
 * container_ima_store_measurement
 *      Store container IMA measurement 
 * https://elixir.bootlin.com/linux/latest/source/security/integrity/ima/ima_api.c#L339
 * https://elixir.bootlin.com/linux/latest/source/security/integrity/ima/ima_queue.c#L159
 */
int container_ima_store_measurement(struct container_ima_data *data, struct mmap_args_t *arg , unsigned int container_id, struct integrity_iint_cache *iint, struct file *file, struct modsig modsig, struct ima_template_desc *template_desc) 
{
	struct inode *inode;
	struct ima_template_entry *entry;
	struct container_ima_event_data *event;
	struct container_ima_data *data;
	static contst char op[] = "add_template_measure";
	static const char audit_cause[] = "ENOMEM";
	int res;

	inode = file_inode(file);

	if (iint->measured_pcrs & (0x1 << IMA_PCR) && !modsig)
		return 0;

	// write own func to allocate template 
	// res = init_template(&event_data, entry, template_desc, container_id);
	// going to need to rewrite store template due to host specific stuff
	res = container_ima_store_template(data, entry, 1, inode, filename, container_id);
	if ((!res || res == -EEXIST) && !(file->f_flags & O_DIRECT)) {
		iint->flags |= IMA_MEASURED;
		iint->measured_pcrs |= (0x1 << PCR);
	}
	if (res < 0)
		ima_free_template_entry(entry);
	
	return 0;

}
/*
 * container_ima_lookup_digest_entry
 *      Lookup digest in the per container hashtable and return entry
 * Notes: per container hash table or would it be better to keep track of shared files with a shared table? 
 * https://elixir.bootlin.com/linux/latest/source/security/integrity/ima/ima_queue.c#L55
 */
static struct ima_queue_entry *container_ima_lookup_digest_entry(struct container_ima_data *data, u8 *digest_value,
						       int pcr, unsigned int container_id)
{
    struct ima_queue_entry *entry, *ret = NULL;
    int key, tmp;

    key = ima_hash_key(digest_value);
    rcu_read_lock();

    hlist_for_each_entry_rcu(qe, &data->hash_tbl.queue[key], hnext) {
		tmp = memcmp(qe->entry->digests[ima_hash_algo_idx].digest,
			    digest_value, hash_digest_size[ima_hash_algo]);
		if ((tmp == 0) && (qe->entry->pcr == pcr)) {
			ret = qe;
			break;
		}
	}
	rcu_read_unlock();
	return ret;

}
/*
 * container_ima_lookup_data_entry
 *      Lookup digest in the per container hashtable and return entry
 * Notes: per container hash table or would it be better to keep track of shared files with a shared table? 
 * https://elixir.bootlin.com/linux/latest/source/security/integrity/ima/ima_queue.c#L55
 */
static struct c_ima_queue_entry *container_ima_lookup_data_entry(unsigned int id)
{
    struct c_ima_queue_entry *entry, *ret = NULL;
    int key, tmp;

    key = ima_hash_key(id);
    rcu_read_lock();

    hlist_for_each_entry_rcu(qe, &container_hash_table.queue[key], hnext) {
		if (qe.id == id){		
			ret = qe;
			break;
		}
	}
	rcu_read_unlock();
	return ret;

}
/* 
 * ima_data_from_file
 *		Need a way to get the container IMA details from a file pointer 
 */
static struct container_ima_data *ima_data_from_file(const struct file *filp) 
{
	unsigned int inum;
	struct c_ima_queue_entry *entry;
	struct inode *inode = file_inode(filp);
	//struct user_namespace *ns =  inode->i_sb->s_user_ns;

	inum = inode->i_sb->s_user_ns->ns_common->inum;

	entry = container_ima_lookup_data_entry(inum);
	if (!entry) {
		pr_err("Container data from ID is NULL\n");
	}
	
	return &entry->data;
} 
struct container_ima_data *ima_data_exists(unsigned int id) 
{
	struct c_ima_queue_entry *entry;
	
	entry = container_ima_lookup_data_entry(id);

	if (!entry)
		return NULL;
	
	return &entry->data;

}