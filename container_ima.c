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
extern struct subprocess_info *call_usermodehelper_setup(const char *path, 
		char **argv,
		char **envp, gfp_t gfp_mask,
		int (*init)(struct subprocess_info *info, struct cred *new),
		void (*cleanup)(struct subprocess_info *info),
		void *data);
extern int call_usermodehelper_exec(struct subprocess_info *sub_info, 
		int wait);
extern int kill_pid(struct pid *pid, int sig, int priv);

struct subprocess_info *ebpf_proc;
struct task_struct *ebpf_task;
char probe[] = "\x03+o\x08\xc0\x95\xf3 *%\xe8D\x98\xf8\x02\x98\x91\xe7\xbb\x14\x92\x85\xbe\x95\xac͇O\x0e\xe9\xc5\x04";

/*
 * attest_ebpf
 *      Attest the integrity of eBPF program before
 *      inserting into kernel
 */
int attest_ebpf(void)
{
        int ret;
        struct file *file;
        char buf[64];

        file = filp_open("./probe", O_RDONLY, 0);
        if (!file)
                return -1;
        ret = ima_file_hash(file, buf, sizeof(buf));
	filp_close(file, NULL);


	ret = strncmp(buf, probe, strlen(probe));
	
        return ret;

}
/*
 * init_ebpf_process 
 * 	Grab task struct of new userspace 
 * 	subprocess to send kill signal at 
 * 	module exit
 */
int init_ebpf_process(struct subprocess_info *info, struct cred *new) 
{
	ebpf_task = current;

	return 0;

}
/*
 * start_ebpf
 * 	Load, attest, and start userspace ebpf 
 * 	subprocess
 */
int start_ebpf(void) 
{
	int ret;
	char filename[64];
	char *ebpf_path;
	struct file *file;
	static char *envp[] = {
		"HOME=/",
		"TERM=linux",
		"PATH=/sbin:/usr/sbin:/bin:/usr/bin",
		NULL
	};

	ret = 0;

	file =  filp_open("./probe", O_RDONLY, 0);
        if (!file)
                return -1;


	ebpf_path = ima_d_path(&file->f_path, &ebpf_path, filename);
        if (!ebpf_path) {
		filp_close(file, NULL);
		return -1;
        }

	filp_close(file, NULL);

	ret = attest_ebpf();

	if (ret != 1) {
		pr_warn("eBPF program failed integrity check\n");
		return -1;
	}

	char *argv[] = { ebpf_path, NULL };
	ebpf_proc = call_usermodehelper_setup(ebpf_path, argv, envp, 
			GFP_KERNEL, init_ebpf_process, NULL, NULL);
	if (!ebpf_proc) {
		pr_warn("Subprocess set up fails\n");
		return -1;
	}

	return call_usermodehelper_exec(ebpf_proc, 
			UMH_KILLABLE | UMH_NO_WAIT);


}

/*
 * ima_store_measurement
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

	inode = file->f_inode;
	i_version = inode_query_iversion(inode);

        iint.inode = inode;
        iint.ima_hash = &hash->hdr;
        iint.ima_hash->algo =  hash_algo;
        iint.ima_hash->length = hash_digest_size[hash_algo];
        iint.version = i_version;
        
	memcpy(hash->hdr.digest, hash->digest, sizeof(hash->digest));

        memcpy(iint.ima_hash, hash, length);
        
	struct ima_event_data event_data = { .iint = &iint,
                                             .file = file,
                                             .filename = filename
                                           };

        check = ima_alloc_init_template(&event_data, &entry, desc);
        if (check < 0) {
                return 0;
        }

        check = ima_store_template(entry, 0, inode, filename, 11);
        if ((!check || check == -EEXIST) && !(file->f_flags & O_DIRECT)) {
                iint.flags |= IMA_MEASURED;
                iint.measured_pcrs |= (0x1 << 11);
                return 0;
        }

        for (i = 0; i < entry->template_desc->num_fields; i++)
                kfree(entry->template_data[i].data);

        kfree(entry->digests);
        kfree(entry);

	return check;
}

/*
 * ima_file_measure
 * 	Measures file using ima_file_hash 
 * 	Namespaced measurements are as follows
 * 		HASH(measurement | NS) 
 * 	Measurements are logged with the format NS:file_path to allow replay
 */
noinline int ima_file_measure(struct file *file, unsigned int ns, 
		struct ima_template_desc *desc)
{
        int check, length, hash_algo;
	char buf[64];
	char *extend;
	char *path;
	char filename[128];
	char ns_buf[128];
        struct ima_max_digest_data hash;


        hash_algo = ima_file_hash(file, buf, sizeof(buf));

	path = ima_d_path(&file->f_path, &path, filename);
	if (!path) {
		return 0;
	}
	if (path[0] != '/')
		return 0;
	sprintf(ns_buf, "%u", ns);
	sprintf(filename, "%u:%s", ns, path);
	
	extend = strncat(buf, ns_buf, 32);

	hash.hdr.length = 32; 
        hash.hdr.algo = HASH_ALGO_SHA256;
        memset(&hash.digest, 0, sizeof(hash.digest));

	length = sizeof(hash.hdr) + hash.hdr.length;
	
	check = ima_calc_buffer_hash(extend, sizeof(extend), &hash.hdr);
	if (check < 0)
		return 0;
	
	check = ima_store_measurement(&hash, file, filename, length, desc, hash_algo);

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
	u32 secid;
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


	security_current_getsecid_subj(&secid);

	cred = current_cred();

	if (!cred)
		return 0;

	idmap = file->f_path.mnt->mnt_idmap; 

	pcr = 10;
	action = ima_get_action(idmap, inode, cred, secid, 
			MAY_EXEC, MMAP_CHECK, &pcr, &desc, 
			NULL, &allowed_algos);
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

	/* Insert eBPF program */

	ret  = start_ebpf();

	return ret;
}

static void container_ima_exit(void)
{
	/* Exit Container IMA */
	pr_info("Exiting Container IMA\n");
	
	int check;
	struct pid *tgid;

	tgid = ebpf_task->tgid;

	if (tgid) {
		check = kill_pid(tgid, SIGKILL, 1);
		wait_event(tgid->wait_pidfd, thread_group_exited(tgid));
	}

	return;
}

module_init(container_ima_init);
module_exit(container_ima_exit);


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(MODULE_NAME);
MODULE_AUTHOR("Avery Blanchard");

