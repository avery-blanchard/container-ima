/*
 * File: container_ima_api.c
 *      Functions for collecting and storing file measurments
 */
#ifndef __CONTAINER_IMA_API_H__
#define __CONTAINER_IMA_API_H__

#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/xattr.h>
#include <linux/evm.h>
#include <linux/audit.h>
#include <linux/iversion.h>
#include <linux/gfp.h>
#include <linux/skbuff.h>
#include <linux/audit.h>
#include <linux/mount.h>
#include <linux/hash.h>
#include <linux/crypto.h>
#include <linux/dcache.h>
#include <linux/hugetlb.h>
#include <linux/shm.h>
#include <linux/tpm.h>
#include <linux/tpm_command.h>
#include "container_ima.h"
#include "container_ima.h"
#include "container_ima_init.h"
#include "container_ima_fs.h"
#include "container_ima_api.h"
#include "container_ima_crypto.h"

#define IMA_PCR 10

static struct kmem_cache *c_ima_iint_cache;
static DEFINE_MUTEX(ima_extend_list_mutex);
int ima_policy = ORIGINAL_TCB;

extern struct ima_rule_entry container_ima_rules;
/* pre-allocated array of tpm_digest structures to extend a PCR */
static struct tpm_digest *digests;

/*
 * container_ima_retrieve_file
 *      Retrieve the file from mmap arguments
 *
 * https://elixir.bootlin.com/linux/v6.0.9/source/mm/mmap.c#L1586 
 */
noinline struct file *container_ima_retrieve_file(int fd) 
{
	int ret;
	ssize_t len;
	struct file *file;
	void *buf;
	/* Get file from fd, len, and address for measurment */
   	pr_err("Retrieving file struct for FD %d\n", fd);
	file = fget(fd);
	if (!file) {
		pr_err("F get fails\n");
		return PTR_ERR(file);
	}
	/*
	} else if (args->flags & MAP_HUGETLB) {
		struct user_struct *user = NULL;
		struct hstate *hs;
		hs = &default_hstate; // remove default later
		if (!hs) {
			ret = -EINVAL;
			return ret;
		}
		args->length = ALIGN(args->length, huge_page_size(hs));
		file = hugetlb_file_setup(HUGETLB_ANON_FILE, args->length,
				VM_NORESERVE,
				&user, HUGETLB_ANONHUGE_INODE,
				(args->flags >> MAP_HUGE_SHIFT) & MAP_HUGE_MASK);
		if (IS_ERR(file)) {
			ret = PTR_ERR(file);
			return ret;
		}
	} */
	pr_info("F get works\n");
	if (file)
		fput(file);
	return file;
 }
 /*
  * container_ima_collect_measurement
  *     Get file from mmap args and measure
  * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_api.c#L198
  */
noinline int container_ima_collect_measurement(struct file *file, struct mmap_args *args, unsigned int container_id, struct integrity_iint_cache *iint, enum hash_algo hash_algo, void *buf, loff_t size) 
{
	int result;
	struct file *f;
	struct inode *inode;
	const char *filename;
	void *tmpbuf; 
	int length;
	loff_t i_size;
	loff_t offset; 
	u64 i_version;
		struct {
		struct ima_digest_data hdr;
		char digest[IMA_MAX_DIGEST_SIZE];
	} hash;
	const char *audit_cause = "failed";
	ssize_t check;

	result = 0;
	pr_err("In collect measurement \n");
	inode = file_inode(file);
	filename = file->f_path.dentry->d_name.name;
	pr_err("got inode and filename\n");
	i_version = inode_query_iversion(inode);
	pr_err("collect measurement returning\n");
	hash.hdr.algo = hash_algo;
	hash.hdr.length = hash_digest_size[hash_algo];


	/* zero out, in case of failue*/ 
	memset(&hash.digest, 0, sizeof(hash.digest));
	if (buf) {
		result = ima_calc_buffer_hash(buf, size, &hash.hdr);
	} else {
		result = ima_calc_file_hash(file, &hash.hdr);
	}
	return 0;
	if (result == -ENOMEM)
		goto out;

	length = sizeof(hash.hdr) + hash.hdr.length;
	tmpbuf = krealloc(iint->ima_hash, length, GFP_NOFS);
	if (!tmpbuf) {
		result = -ENOMEM;
		goto out;
	}
	
	check = kernel_read(file, buf, 1, 0);
	if (check < 0) {
		pr_err("kernel read returns negative");
		return 0;
	}
	iint->ima_hash = tmpbuf;
	memcpy(iint->ima_hash, &hash, length);
	iint->version = i_version;

	/* Possibly temporary failure due to type of read (eg. O_DIRECT) *
	if (!result)
		iint->flags |= IMA_COLLECTED;*/
out:
	if (result) {
		if (file->f_flags & O_DIRECT)
			audit_cause = "failed(directio)";

		integrity_audit_msg(AUDIT_INTEGRITY_DATA, inode,
				    filename, "collect_data", audit_cause,
				    result, 0);
	}
	return result;
 }
 /*
  * container_integrity_inode_find
  *     Traverse rb_tree to see if the inode exists. If exits, return. Else, NULL.
  * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/iint.c#L98 
  */
noinline struct integrity_iint_cache *container_integrity_inode_find(struct ima_data *data, struct inode *inode, unsigned int container_id)
 {
	struct integrity_iint_cache *iint;
	struct rb_node *node = data->iint_tree.rb_node; // root inode for NS tree
	
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
 struct integrity_iint_cache *container_integrity_inode_get(struct ima_data *data, struct inode *inode, unsigned int container_id)
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

	//spin_lock(&data->queue_lock);

	ptr = &data->iint_tree.rb_node;
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
	rb_insert_color(node, &data->iint_tree);

	//spin_unlock(&data->queue_lock);
	return iint;

}
/*
 * container_ima_add_violation 
 *      Write violation to the measurement list
 * https://elixir.bootlin.com/linux/latest/source/security/integrity/ima/ima_api.c#L134
 */
void container_ima_add_violation(struct ima_data *data, struct file *file, const unsigned char *filename,
		       struct integrity_iint_cache *iint,
		       const char *op, const char *cause, unsigned int container_id) 
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
	//atomic_long_inc(&data->hash_tbl->violations);

	/* try to use IMA's allocation function */
	result = ima_alloc_init_template(&event_data, &entry, NULL);
	if (result < 0) {
		result = -ENOMEM;
		goto err_out;
	}
	result = container_ima_store_template(data, entry, violation, inode,
				    filename, IMA_PCR);
	if (result < 0)
		ima_free_template_entry(entry);
err_out:
    // try to use IMA's audit messages? may be fine 
	integrity_audit_msg(AUDIT_INTEGRITY_PCR, inode, filename,
			    op, cause, result, 0);

}
/*
 * container_ima_rdwr_violation_check
 *      Conditionally invalidate PCR for measured files
 * https://elixir.bootlin.com/linux/latest/source/security/integrity/ima/ima_main.c#L115 
 */
static void container_ima_rdwr_violation_check(struct ima_data *data, struct file *file,
				     struct integrity_iint_cache *iint,
				     int must_measure,
				     char **pathbuf,
				     const char **pathname,
				     char *filename, unsigned int container_id)
{
	return;
	struct inode *inode = file_inode(file);
	fmode_t mode = file->f_mode;
	bool send_t = false;
	bool send_w = false;

	if (mode & FMODE_WRITE) {
		if (atomic_read(&inode->i_count) && IS_IMA(inode)) {
			if (!iint)
				iint = container_integrity_inode_find(data, inode, container_id);
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
int container_ima_match_policy(struct ima_data *data, struct inode *inode,
		     int mask, int flags)
{
	int action; int action_mask;

	action_mask = flags | (flags << 1);
	/* TODO edit this for future use with different policies per container */
	pr_err("RETURN MEASURE\n");
	return MEASURE;

}
/*
 * container_ima_get_action
 *
 * Determine IMA policy for container 
 * https://elixir.bootlin.com/linux/latest/source/security/integrity/ima/ima_policy.c#L690 
 */
int container_ima_get_action(struct ima_data *data, struct inode *inode,
		   int mask) 
{
	int action;
	int flag;

	pr_err("IMA GET ACTION\n");	
	flag = IMA_MEASURE | IMA_AUDIT | IMA_APPRAISE | IMA_HASH; // not implementing appraisal currently, maybe exclude
	flag &= container_ima_rules.flags;
	/* ima_match policy reads IMA tmp rules list, which for container IMA is per
	 * container and in struct container_data, re-write for different policies (later on)
	 */ 
	pr_err("MATCHING POLICY\n");
	action = container_ima_match_policy(data, inode, mask,
				flag);

	return action;
}
/*
 * container_ima_process_measurement
 * https://elixir.bootlin.com/linux/latest/source/security/integrity/ima/ima_main.c#L201
 */
noinline int container_ima_process_measurement(struct ima_data *data, struct mmap_args *args, unsigned int container_id, int fd) 
{
	struct integrity_iint_cache *iint = NULL;
	struct ima_template_desc *template_desc = NULL;
	char filename[NAME_MAX];
	char *pathbuf = NULL;
	struct inode *inode;
	const char *pathname = NULL;
	int ret, action, appraisal; 
	struct evm_ima_xattr_data *xattr_value = NULL;
	int xattr_len = 0;
	bool violation_check;
	enum hash_algo hash_algo;
	unsigned int allowed_algos = 0;
	struct file *file;
	int mask = 0;
	void *buf = NULL;
	loff_t size = 0;

	pr_err("in process measurement %d\n\n", fd);
	file = container_ima_retrieve_file(fd);
	inode = file_inode(file);

	/*if (!data->c_ima_policy_flags || !S_ISREG(inode->i_mode))
		return 0;
	*/
	pr_err("IMA get action\n");
	/* re-write for future use of different IMA polcies per container */
	action  = container_ima_get_action(data, inode, mask);

	pr_info("Got action\n");
	
	/*violation_check = ((container_ima_rules.flags & IMA_MEASURE));
	if (!action && !violation_check)
		return 0;
	
	//appraisal = action & IMA_APPRAISE; // implement apprasial in future


	inode_lock(inode);

	if (action) {
		iint = container_integrity_inode_get(data, inode, container_id);
		if (!iint)
			ret = -ENOMEM;
	}
	pr_info("Retrived inode from rb tree\n");
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
				 IMA_APPRAISE_SUBMASK | IMA_APPRAISED_SUBMASK);

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

	if ((action & IMA_MEASURE) && (iint->measured_pcrs & (0x1 << IMA_PCR)))
		action ^= IMA_MEASURE;
	*/
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
	pr_info("Got hash algo\n");
	hash_algo = ima_get_hash_algo(xattr_value, xattr_len);
	
	pr_info("Pre-collect measurement\n");

	ret = container_ima_collect_measurement(file, args, container_id, iint, hash_algo, buf, size);
	if (ret != 0) {
		pr_err("collecting measurement failed\n");
	}
	/*if (!pathbuf)	/* ima_rdwr_violation possibly pre-fetched */
	/*	pathname = ima_d_path(&file->f_path, &pathbuf, filename);

	if (action & IMA_MEASURE)
		container_ima_store_measurement(data, args, container_id, iint, file,template_desc, pathname);
	
	// appraisal would go here

	if (action & IMA_AUDIT)
		ima_audit_measurement(iint, pathname);

	if ((file->f_flags & O_DIRECT) && (iint->flags & IMA_PERMIT_DIRECTIO))
		ret = 0;
out_locked:
	if ((mask & MAY_WRITE) && test_bit(IMA_DIGSIG, &iint->atomic_flags) &&
	     !(iint->flags & IMA_NEW_FILE))
			ret = -EACCES;
	mutex_unlock(&iint->mutex);
	kfree(xattr_value);
out:
	if ((mask & MAY_WRITE) && test_bit(IMA_DIGSIG, &iint->atomic_flags) &&
	     !(iint->flags & IMA_NEW_FILE))
		ret = -EACCES;
	mutex_unlock(&iint->mutex);
*/
	pr_info("leaving process measurment\n");
	return 0;


}
/*
 * container_ima_add_digest_entry
 *		Helper for container_ima_add_template_entry
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_queue.c#L96
 */
static int container_ima_add_digest_entry(struct ima_data *data, struct ima_template_entry *entry)
{
	struct ima_queue_entry *qe;
	unsigned int key;

	qe = kmalloc(sizeof(*qe),  GFP_KERNEL);

	qe->entry = entry;
	/*
	INIT_LIST_HEAD(&qe->later);
	list_add_tail_rcu(&qe->later, &data->measurements);
	atomic_long_inc(&data->hash_tbl->len);
	key = ima_hash_key(entry->digests[HASH_ALGO_SHA1].digest); // idx of hash algo
	hlist_add_head_rcu(&qe->hnext, &data->hash_tbl->queue[key]);
	if (&data->binary_runtime_size != ULONG_MAX) {
		int size;
		size = get_binary_runtime_size(entry);
		data->binary_runtime_size = (data->binary_runtime_size < ULONG_MAX - size) ?
		     data->binary_runtime_size + size : ULONG_MAX;
	}*/
	return 0;

}
static int container_ima_add_data_entry(struct ima_data *data, long id)
{
	struct c_ima_queue_entry *qe;
	qe = kmalloc(sizeof(*qe),  GFP_KERNEL);

	qe->data = data;
/*
	INIT_LIST_HEAD(&qe->hnext);
	atomic_long_inc(&container_hash_table.len);
	hlist_add_head_rcu(&qe->hnext, &container_hash_table.queue[id]);
	*/
	return 0;

}
/*
 * container_ima_add_template_entry
 *      Add digest to the hashtable and extend PCR
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_queue.c#L162
 */
int container_ima_add_template_entry(struct ima_data *data, struct ima_template_entry *entry, int violation,
			   const char *op, struct inode *inode,
			   const unsigned char *filename, unsigned int container_id)
{

	u8 *digest = entry->digests[IMA_PCR].digest;
	struct tpm_digest *digests_arg = entry->digests;
	const char *audit_cause = "hash_added";
	char tpm_audit_cause[AUDIT_CAUSE_LEN_MAX];
	int audit_info = 1;
	int res = 0, tpmresult = 0;

	// create a mutex per container list 
	mutex_lock(&ima_extend_list_mutex);
	/* 
	 * hash table lookup, need to reimplement for container specific hash tables 
	 * https://elixir.bootlin.com/linux/latest/source/security/integrity/ima/ima_queue.c#L48 
	 */
	if (!violation && !IS_ENABLED(CONFIG_IMA_DISABLE_HTABLE)) {
		if (container_ima_lookup_digest_entry(data, digest, IMA_PCR, container_id)) {
			audit_cause = "hash_exists";
			res = -EEXIST;
			goto out;
		}
	}
	/*
	 * add digest to the hashtable, need to reimplement for container specific hash tables 
	 * https://elixir.bootlin.com/linux/latest/source/security/integrity/ima/ima_queue.c#L93 
	 */
	res = container_ima_add_digest_entry(data, entry);

	if (res < 0) {
		audit_cause = "ENOMEM";
		audit_info = 0;
		goto out;
	}	

	/* if violation occurs, invalidate the PCR */
	if (violation)
		digests_arg = digests;
	
	/* 
	 * extend PCR of container's vTPM, figure out functions for extending vTPM 
	 * https://elixir.bootlin.com/linux/latest/source/drivers/char/tpm/tpm-interface.c#L314 
	 *
	res = ima_pcr_extend(data, digests_arg, entry->pcr);
	if (res != 0) {
		pr_err("vTPM failed\n");
		audit_info = 0;
	}*/
out:
	// unlock ml mutex here
	mutex_lock(&ima_extend_list_mutex);
	// make this container specific? 
	integrity_audit_msg(AUDIT_INTEGRITY_PCR, inode, filename,
			    op, audit_cause, res, 0);
	return res;

}
/*
 * container_ima_store_template
 *     Calculate hash, add to ML and extend to PCR
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_api.c#L89
 */
int container_ima_store_template(struct ima_data *data, struct ima_template_entry *entry,
		       int violation, struct inode *inode,
		       const char *filename, unsigned int container_id)
{
	int res;
	static const char op[] = "add_template_measure";
	static const char audit_cause[] = "ENOMEM";
	char *template_name = entry->template_desc->name;
		struct {
		struct ima_digest_data hdr;
		char digest[TPM_DIGEST_SIZE];
	} hash;

	if (!violation) {
		// try to use IMA's hashing functions, hash should be in entry->digests[tfm_idx].digest
		int num_fields = entry->template_desc->num_fields;
		hash.hdr.algo = HASH_ALGO_SHA1;
		res = ima_calc_field_array_hash(&entry->template_data[0],
						   entry->template_desc,
						   num_fields, &hash.hdr);
		if (res < 0) {
			// error, add logging
			pr_err("error calculating hash\n");
			return 0;
		}

	}
	entry->pcr = IMA_PCR;
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
int container_ima_store_measurement(struct ima_data *data, struct mmap_args *arg , unsigned int container_id, struct integrity_iint_cache *iint, struct file *file, struct ima_template_desc *template_desc, const char *filename) 
{
	struct inode *inode;
	struct ima_template_entry *entry;
	struct ima_event_data *event_data;
	static const char op[] = "add_template_measure";
	static const char audit_cause[] = "ENOMEM";
	int res;

	inode = file_inode(file);
	if (iint->measured_pcrs & (0x1 << IMA_PCR))
		return 0;

	/* using IMA's function to allocate should be define, not keeping memory separate yet */
	res = ima_alloc_init_template(event_data, &entry, template_desc);
	// going to need to rewrite store template due to host specific stuff
	res = container_ima_store_template(data, entry, 1, inode, filename, container_id);
	if ((!res || res == -EEXIST) && !(file->f_flags & O_DIRECT)) {
		iint->flags |= IMA_MEASURED;
		iint->measured_pcrs |= (0x1 << IMA_PCR);
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
static struct ima_queue_entry *container_ima_lookup_digest_entry(struct ima_data *data, u8 *digest_value,
						       int pcr, unsigned int container_id)
{
    struct ima_queue_entry *qe, *ret = NULL;
    unsigned int key;
	int tmp;

    key = ima_hash_key(digest_value);
    rcu_read_lock();
/*
    hlist_for_each_entry_rcu(qe, &data->hash_tbl->queue[key], hnext) {
		tmp = memcmp(qe->entry->digests[IMA_PCR].digest,
			    digest_value, hash_digest_size[HASH_ALGO_SHA1]);
		if ((tmp == 0) && (qe->entry->pcr == IMA_PCR)) {
			ret = qe;
			break;
		}
	}*/
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
    struct  c_ima_queue_entry *qe, *ret = NULL;
    unsigned int key;
	int tmp;

	pr_info("Pre hash key\n");
   // key = ima_hash_key(id);
    rcu_read_lock();

	pr_info("Before for loop in check\n");
    hlist_for_each_entry_rcu(qe, &container_hash_table.queue[id], hnext) {
		if (!qe)
			break;
		if (qe->id == id){		
			ret = qe;
			break;
		}
	}
	rcu_read_unlock();

	pr_info("After check, returning\n");
	return ret;

}
/*
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_queue.c#L77 
 */
static int get_binary_runtime_size(struct ima_template_entry *entry)
{
	int size = 0;

	size += sizeof(u32);	/* pcr */
	size += TPM_DIGEST_SIZE;
	size += sizeof(int);	/* template name size field */
	size += strlen(entry->template_desc->name);
	size += sizeof(entry->template_data_len);
	size += entry->template_data_len;
	return size;
}
/*
 * TO DO
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_api.c#L310 
 */
void ima_audit_measurement(struct integrity_iint_cache *iint,
			   const unsigned char *filename)
{
	struct audit_buffer *ab;
	char *hash;
	const char *algo_name = hash_algo_name[iint->ima_hash->algo];
	int i;

	if (iint->flags & IMA_AUDITED)
		return;

	hash = kzalloc((iint->ima_hash->length * 2) + 1, GFP_KERNEL);
	if (!hash)
		return;

	for (i = 0; i < iint->ima_hash->length; i++)
		hex_byte_pack(hash + (i * 2), iint->ima_hash->digest[i]);
	hash[i * 2] = '\0';

	ab = audit_log_start(audit_context(), GFP_KERNEL,
			     AUDIT_INTEGRITY_RULE);
	if (!ab)
		goto out;

	audit_log_format(ab, "file=");
	//audit_log_untrustedstring(ab, filename);
	audit_log_format(ab, " hash=\"%s:%s\"", algo_name, hash);

	audit_log_task_info(ab);
	audit_log_end(ab);

	iint->flags |= IMA_AUDITED;
out:
	kfree(hash);
	return;
}
/*
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_api.c#L357
 */
const char *ima_d_path(const struct path *path, char **pathbuf, char *namebuf)
{
	char *pathname = NULL;
	strlcpy(namebuf, path->dentry->d_name.name, NAME_MAX);
	pathname = namebuf;

	return pathname;
}
/*
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_api.c#L41 
 */
int ima_alloc_init_template(struct ima_event_data *event_data,
			    struct ima_template_entry **entry, struct ima_template_desc *template_desc)
{
	int i, result = 0;

	*entry = kzalloc(sizeof(**entry) + template_desc->num_fields *
			 sizeof(struct ima_field_data), GFP_NOFS);
	if (!*entry)
		return -ENOMEM;

	(*entry)->template_desc = template_desc;
	for (i = 0; i < template_desc->num_fields; i++) {
		struct ima_template_field *field = template_desc->fields[i];
		u32 len;

		result = field->field_init(event_data,
					   &((*entry)->template_data[i]));
		if (result != 0)
			goto out;

		len = (*entry)->template_data[i].len;
		(*entry)->template_data_len += sizeof(len);
		(*entry)->template_data_len += len;
	}
	return 0;
out:
	ima_free_template_entry(*entry);
	*entry = NULL;
	return result;
}
/* 
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/ima/ima_api.c#L28 
 */
void ima_free_template_entry(struct ima_template_entry *entry)
{
	int i;

	for (i = 0; i < entry->template_desc->num_fields; i++)
		kfree(entry->template_data[i].data);

	kfree(entry);
}
/*
 * https://elixir.bootlin.com/linux/v4.19/source/fs/read_write.c#L412 
 */
ssize_t __vfs_read(struct file *file, char __user *buf, size_t count,
		   loff_t *pos)
{
	return file->f_op->read(file, buf, count, pos);
}
/* 
 TO DO
 https://elixir.bootlin.com/linux/v4.19/source/kernel/audit.c#L1937 
void audit_log_string(struct audit_buffer *ab, const char *string,
			size_t slen)
{
	unsigned char *str;
	int len, new_len; 
	struct sk_buff *skb;

	if (!ab)
		return;
	skb = ab->skb;
	len = skb_tailroom(skb);
	new_len = slen + 3;

	// add quotes around string
	str =  skb_tail_pointer(skb);
	*str++ = '"';
	memcpy(str, string, slen);
	*str++ = '"';
	*str++ = 0;

	skb_put(skb, slen + 2);

}*/
/*
 * https://elixir.bootlin.com/linux/v4.19/source/security/integrity/integrity_audit.c#L31 
 */
void integrity_audit_msg(int audit_msgno, struct inode *inode,
			 const unsigned char *fname, const char *op,
			 const char *cause, int result, int audit_info)
{
	struct audit_buffer *ab;
	char name[TASK_COMM_LEN];

	ab = audit_log_start(audit_context(), GFP_KERNEL, audit_msgno);
	audit_log_format(ab, "pid=%d uid=%u auid=%u ses=%u",
			 task_pid_nr(current),
			 from_kuid(&init_user_ns, current_cred()->uid),
			 from_kuid(&init_user_ns, audit_get_loginuid(current)),
			 audit_get_sessionid(current));
	audit_log_task_context(ab);
	audit_log_format(ab, " op=");
	//audit_log_string(ab, op, strlen(op));
	audit_log_format(ab, " cause=");
	//audit_log_string(ab, op, strlen(op));
	audit_log_format(ab, " comm=");
	//audit_log_untrustedstring(ab, get_task_comm(name, current));
	if (fname) {
		audit_log_format(ab, " name=");
		//audit_log_untrustedstring(ab, fname);
	}
	if (inode) {
		audit_log_format(ab, " dev=");
		//audit_log_untrustedstring(ab, inode->i_sb->s_id);
		audit_log_format(ab, " ino=%lu", inode->i_ino);
	}
	audit_log_format(ab, " res=%d", !result);
	audit_log_end(ab);
}
int integrity_kernel_read(struct file *file, loff_t offset,
			  void *addr, unsigned long count)
{
	return kernel_read(file, addr, count, &offset);
}

noinline int ima_pcr_extend(struct tpm_digest *digests_arg, int pcr)
{
    int ret = 0;
    
    if (!ima_tpm_chip) {
	    return ret;
    }
    return tpm_pcr_extend(ima_tpm_chip, pcr, digests_arg); //until vTPM is fixed
	//return 0;
}
#endif
