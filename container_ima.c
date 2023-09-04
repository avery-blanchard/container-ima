/*
 * Container IMA using eBPF
 *
 * File: container_ima.c
 * 	Implements namespaced IMA measurements,
 * 	defines kernel symbols, registers kfuncs
 * 	with libbpf
 */

#define _GNU_SOURCE
#include <linux/unistd.h>
#include <linux/mount.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/printk.h>
#include <linux/ima.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/integrity.h>
#include <uapi/linux/bpf.h>
#include <linux/bpf.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/cred.h>
#include <linux/fcntl.h>
#include <crypto/hash_info.h>
#include <linux/bpf_trace.h>
#include <uapi/linux/bpf.h>
#include <linux/bpf_lirc.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/sysfs.h>
#include <linux/bpfptr.h>
#include <linux/bsearch.h>
#include <linux/btf_ids.h>
#include <uapi/linux/btf.h>
#include <uapi/linux/bpf.h>
#include <linux/iversion.h>
#include "container_ima.h"

#define MODULE_NAME "ContainerIMA"
extern void security_task_getsecid(struct task_struct *p, u32 *secid);
extern const int hash_digest_size[HASH_ALGO__LAST];

/*
 * ima_store_measurement
 * 	struct ima_max_digest_data *hash: hash information
 * 	struct file *file: file measured
 * 	char *filename: name of measured file (ns:file path) 
 * 	int length: size of hash data
 * 	struct ima_template_desc *desc: description of IMA template
 * 	int hash_algo: algorithm used in measurement 
 *
 * 	Store file with namespaced measurement and file name
 * 	Extend to pcr 11
 */
noinline int ima_store_measurement(struct ima_max_digest_data *hash, 
		struct file *file, char *filename, int length, 
		struct ima_template_desc *desc, int hash_algo)
{

	int i, check;
	u64 i_version;
	struct inode *inode;
	struct ima_template_entry *entry;
        struct integrity_iint_cache iint = {};

	/* init inode integrity data */
	inode = file->f_inode;
	i_version = inode_query_iversion(inode);

        iint.inode = inode;
        iint.ima_hash = &hash->hdr;
        iint.ima_hash->algo =  hash_algo;
        iint.ima_hash->length = hash_digest_size[hash_algo];
        iint.version = i_version;
        
	memcpy(hash->hdr.digest, hash->digest, sizeof(hash->digest));

        memcpy(iint.ima_hash, hash, length);
        
	/* IMA event data */
	struct ima_event_data event_data = { .iint = &iint,
                                             .file = file,
                                             .filename = filename
                                           };

	/* IMA template field data */
        check = ima_alloc_init_template(&event_data, &entry, desc);
        if (check < 0) {
                return 0;
        }

	/* Store template, extend to PCR 11 */
        check = ima_store_template(entry, 0, inode, filename, 11);
        if ((!check || check == -EEXIST) && !(file->f_flags & O_DIRECT)) {
                iint.flags |= IMA_MEASURED;
                iint.measured_pcrs |= (0x1 << 11);
                return 0;
        }

	/* Clean up if needed */
        for (i = 0; i < entry->template_desc->num_fields; i++)
                kfree(entry->template_data[i].data);

        kfree(entry->digests);
        kfree(entry);

	return check;
}

/*
 * ima_file_measure
 * 	struct file *file: file to be measured
 * 	unsigned int ns: namespace 
 * 	struct ima_template_desc *decs: description of IMA template
 * 	
 * 	Measures file using ima_file_hash 
 * 	Namespaced measurements are as follows
 * 		HASH(measurement || NS) 
 * 	Measurements are logged with the format NS:file_path 
 */
noinline int ima_file_measure(struct file *file, unsigned int ns, 
		struct ima_template_desc *desc)
{
        int check, length, hash_algo;
	char *buf = vmalloc(64);
	char *extend;
	char *path;
	char *filename = vmalloc(128);
	char *ns_buf = vmalloc(128);
        struct ima_max_digest_data hash;


	/* Measure file */
        hash_algo = ima_file_hash(file, buf, sizeof(buf));

	path = ima_d_path(&file->f_path, &path, filename);
	if (!path) {
		return 0;
	}
	
	/* Catch all for policy errors, todo */
	if (path[0] != '/')
		return 0;

	sprintf(ns_buf, "%u", ns);
	sprintf(filename, "%u:%s", ns, path);
	
	extend = strncat(buf, ns_buf, 32);

	hash.hdr.length = hash_digest_size[hash_algo]; 
        hash.hdr.algo =  hash_algo;
        memset(&hash.digest, 0, sizeof(hash.digest));

	length = sizeof(hash.hdr) + hash.hdr.length;
	
	/* Final measurement:
	 * HASH(measurement || NS) 
	 * Concatenate file measurement with the NS buffer
	 * Hash the concatonated string */	
	check = ima_calc_buffer_hash(extend, sizeof(extend), &hash.hdr);
	if (check < 0)
		return 0;
	
	check = ima_store_measurement(&hash, file, filename, length, 
			desc, hash_algo);

	vfree(buf);
	vfree(filename);
	vfree(ns_buf);
	return 0;
}

/*
 * bpf_process_measurement 
 * 	void *mem: pointer to struct ebpf_data to allow though verifier
 * 	int mem__sz: size of pointer 
 *
 * 	Function gets action from ima policy, measures, and stores
 * 	accordingly.
 * 	Exported by libbpf, called by eBPF program hooked to LSM (mmap_file)
 */
noinline int bpf_process_measurement(void *mem, int mem__sz)
{

	int ret, action, pcr;
	struct inode *inode;
	struct mnt_idmap *idmap;
	const struct cred *cred;
#ifdef _LSMSTACKING
	struct lsmblob blob;
#else
	u32 secid;
#endif /* _LSMSTACKING */
	struct ima_template_desc *desc = NULL;
	unsigned int allowed_algos = 0;
	struct ebpf_data *data = (struct ebpf_data *) mem;
	struct file *file = data->file;
	unsigned int ns = data->ns;
	
	if (!file)
		return 0;
	
	inode = file->f_inode;
	if (!S_ISREG(inode->i_mode))
                return 0;

#ifdef _LSMSTACKING
	security_current_getsecid_subj(&blob);
#else
	security_current_getsecid_subj(&secid);
#endif /* _LSMSTACKING */

	cred = current_cred();
	if (!cred)
		return 0;

	idmap = file->f_path.mnt->mnt_idmap; 

	/* Get action form IMA policy */
	pcr = 10;
#ifdef _LSMSTACKING
	action = ima_get_action(idmap, inode, cred, &blob, 
			MAY_EXEC, MMAP_CHECK, &pcr, &desc, 
			NULL, &allowed_algos);
#else
	action = ima_get_action(idmap, inode, cred, secid, 
			MAY_EXEC, MMAP_CHECK, &pcr, &desc, 
			NULL, &allowed_algos);

#endif /* _LSMSTACKING */
	if (!action)  
		return 0;
	
	
	if (action & IMA_MEASURE)
		ret =  ima_file_measure(file, ns, desc);

	
	return 0;
}

BTF_SET8_START(ima_kfunc_ids)
BTF_ID_FLAGS(func, bpf_process_measurement, KF_TRUSTED_ARGS | KF_SLEEPABLE)
BTF_ID_FLAGS(func,  ima_file_measure, KF_TRUSTED_ARGS | KF_SLEEPABLE)
BTF_ID_FLAGS(func,  ima_store_measurement, KF_TRUSTED_ARGS | KF_SLEEPABLE)
BTF_SET8_END(ima_kfunc_ids)

static const struct btf_kfunc_id_set bpf_ima_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &ima_kfunc_ids,
};
static int container_ima_init(void)
{

	/* Start container IMA */
	int ret;
	struct task_struct *task;
	
	pr_info("Starting Container IMA\n");


	task = current;
	host_inum = task->nsproxy->cgroup_ns->ns.inum;
	
	/* Register kernel module functions wiht libbpf */
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_LSM, &bpf_ima_kfunc_set);
	if (ret < 0)
		return ret;
	
	
	/* Attach kprobe to kaalsysms_lookup_name to 
	 * get function address (symbol no longer exported */
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);

	/* Use kallsyms_lookup_name to retrieve kernel IMA functions */
	ima_calc_buffer_hash = (int(*)(const void *, loff_t len, 
				struct ima_digest_data *)) 
		kallsyms_lookup_name("ima_calc_buffer_hash");
	if (ima_calc_buffer_hash == 0) {
		pr_err("Lookup fails\n");
		return -1;
	}
	ima_template_desc_current =  (struct ima_template_desc *(*)(void)) 
		kallsyms_lookup_name("ima_template_desc_current");
        if (ima_template_desc_current == 0) {
                pr_err("Lookup fails\n");
                return -1;
        }
	
	ima_store_template =(int(*)(struct ima_template_entry *, int, 
				struct inode *, const unsigned char *, int)) 
		kallsyms_lookup_name("ima_store_template");
        if (ima_store_template == 0) {
                pr_err("Lookup fails\n");
                return -1;
        }


	ima_alloc_init_template = (int(*)(struct ima_event_data *, 
				struct ima_template_entry **, 
				struct ima_template_desc *)) 
		kallsyms_lookup_name("ima_alloc_init_template");
        if (ima_alloc_init_template == 0) {
                pr_err("Lookup fails\n");
                return -1;
        }

	ima_calc_field_array_hash = (int(*)(struct ima_field_data *, 
				struct ima_template_entry *)) 
		kallsyms_lookup_name("ima_calc_field_array_hash");
        if (ima_calc_field_array_hash == 0) {
                pr_err("Lookup fails\n");
                return -1;
        }

	ima_d_path = (const char *(*)(const struct path *, char **, 
				char *)) kallsyms_lookup_name("ima_d_path");
        if (ima_d_path == 0) {
                pr_err("Lookup fails\n");
                return -1;
        }
	
	ima_get_action = (int (*)(struct mnt_idmap *, struct inode *, 
				const struct cred *, u32,  int,  
				enum ima_hooks,  int *, 
				struct ima_template_desc **, 
				const char *, unsigned int *)) 
		kallsyms_lookup_name("ima_get_action");
        
	if (ima_get_action == 0) {
                pr_err("Lookup fails\n");
                return -1;
        }
	
	ima_hash_algo = (int) kallsyms_lookup_name("ima_hash_algo");

	if (ima_hash_algo == 0) {
		pr_err("Lookup fails\n");
		return -1;
	}

	ima_calc_field_array_hash = (int (*)(struct ima_field_data *,
			      struct ima_template_entry *)) 
		kallsyms_lookup_name("ima_calc_field_array_hash");

        if (ima_calc_field_array_hash == 0) {
                pr_err("Lookup fails\n");
                return -1;
        }

	return ret;
}

static void container_ima_exit(void)
{
	pr_info("Exiting Container IMA\n");
	return;
}

module_init(container_ima_init);
module_exit(container_ima_exit);


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(MODULE_NAME);
MODULE_AUTHOR("Avery Blanchard");

