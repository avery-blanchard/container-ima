#define _GNU_SOURCE
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/printk.h>
#include <linux/ima.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/integrity.h>
#include <uapi/linux/bpf.h>
#include <keys/system_keyring.h>
#include <linux/bpf.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/dcache.h>
#include <linux/syscalls.h>
#include <linux/hugetlb.h>
#include <linux/shm.h>
#include <linux/fcntl.h>
#include <linux/kthread.h>
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
#include <crypto/hash.h>
#include "container_ima.h"
#include "container_ima_crypto.h"
#include "container_ima_init.h"
#include "container_ima_fs.h"
#include "container_ima_api.h"

#define PROT_EXEC 0x04
#define LOG_SIZE 4096
#define PROBE_SIZE 2048
#define MAX_ENTRIES 100
#define MODULE_NAME "ContainerIMA"
#define INTEGRITY_KEYRING_IMA 1
#define LOG_BUF_SIZE 2048


unsigned int host_inum;
extern int ima_hash_algo;
struct container_ima_data *data;
extern int register_btf_kfunc_id_set(enum bpf_prog_type prog_type,
			      const struct btf_kfunc_id_set *kset);
/*
 * init_mmap_probe, TO DO
 */
static int init_mmap_probe(void) 
{
	// using probe.c, init probe from kernelspace using kernel bpf hooks that are reached from userspace through syscall
	int ret;

	/* approach: userspace subprocess to insert the probe */
	struct subprocess_info *subprocess_info; //https://elixir.bootlin.com/linux/v4.19/source/include/linux/umh.h#L19
	// https://developer.ibm.com/articles/l-user-space-apps/
	char *argv[] = {"./probe", "NULL"};
	static char *envp[] = {
		"HOME=/",
		"TERM=linux",
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL};

	return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);

}
noinline int bpfmeasurement(unsigned int inum ) {

	if (inum == host_inum)
		return -1;
	return 1;
/*
	struct container_ima_data *data;
	struct mmap_args_t *args;
	struct task_struct *task;
	unsigned int inum;
	struct file *file;
	struct inode *inode;
	const char *filename;
	int ret, action, len;
	void *buf;
	u64 i_version;
	loff_t i_size;
	struct crypto_shash *ftm;
	struct shash_desc *shash;
	unsigned int flags;
	fmode_t mode;

	struct {
		struct ima_digest_data hdr;
		char digest[IMA_MAX_DIGEST_SIZE];
	} hash;
	
	task = (void *) bpf_get_current_task();

	inum = BPF_CORE_READ(task, nsproxy, cgroup_ns, ns.inum);

	if (inum  == host_inum) {
		pr_err("inum  == host_inum check\n");
		args->fd = fd;
		args->length = length;
		args->flags = flags;
		args->prot = PROT_EXEC;
		args->offset = 0;

		file = container_ima_retrieve_file(args->fd);
		if (file) {
			pr_err("FILE\n");
			inode = file_inode(file);
			action = MEASURE;
			filename = BPF_CORE_READ(file, f_path.dentry, d_name.name);
			i_version = &(BPF_CORE_READ(inode, i_version));

			hash.hdr.algo = ima_hash_algo;
			hash.hdr.length = hash_digest_size[ima_hash_algo];
			
			flags = BPF_CORE_READ(file, f_flags);
			if (file->f_flags & O_DIRECT) {
				return 0;
			}
			mode = BPF_CORE_READ(file, f_mode);
			if (!(file->f_mode & FMODE_READ)) {
				return 0;
			}

			i_size = BPF_CORE_READ(inode, i_size);
			if (!i_size) {
				pr_err("panic\n");
				return 0;
			}
			ftm = ima_shash_tfm;

			//ftm = ftm->base.__crt_algo->cra_init(&ftm->base);

			return 0;
		}
	}
	return 0;*/
}

noinline struct ima_hash ima_hash_setup(void) 
{
	struct ima_hash hash;

        hash.hdr.algo = ima_hash_algo;
        hash.hdr.length = hash_digest_size[ima_hash_algo];

	return hash;

}
noinline void *ima_buffer_read(struct file *filp) 
{
	ssize_t ret;
	void *buf;

	ret = kernel_read(filp, buf, 0, NULL);
        if (ret) {
		return buf;
	}
	return NULL;
       	       
}
noinline int ima_crypto(void *buf, int size, struct crypto_shash *tfm, struct crypto_tfm base, int (*cra_init)(struct crypto_tfm *tfm), u8 digest[])
{
	int ret;
	unsigned int len;
	struct shash_desc *shash;

	shash->tfm = tfm;

	ret = cra_init(&base);
	if (ret != 0) {
		return ret;
	}

	while (size) {
		len = size < PAGE_SIZE ? size : PAGE_SIZE;
		ret = crypto_shash_update(shash, buf, len);
		if (ret)
			break;
		buf += len;
		size -= len;
	}

	if (!ret) {
		ret = crypto_shash_final(shash, digest);
	}

	return ret;

}
noinline struct crypto_shash *ima_shash_init(void) 
{
	return ima_shash_tfm;
}
BTF_SET8_START(container_ima_check_kfunc_ids)
BTF_ID_FLAGS(func, bpfmeasurement)
BTF_ID_FLAGS(func, container_ima_retrieve_file)
BTF_ID_FLAGS(func, ima_hash_setup)
BTF_ID_FLAGS(func, ima_buffer_read)
BTF_ID_FLAGS(func, ima_crypto)
BTF_ID_FLAGS(func, ima_shash_init)
BTF_SET8_END(container_ima_check_kfunc_ids)

static const struct btf_kfunc_id_set bpf_container_ima_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &container_ima_check_kfunc_ids,
};
static int container_ima_init(void)
{
	pr_info("Starting container IMA\n");

	/* Start container IMA */
	int ret;
	struct task_struct *task;
	struct nsproxy *ns;
	

	/* Initialize global/shared IMA data */
	pr_info("FS INIT\n");
	ret = container_ima_fs_init();
	if (ret < 0)
		return ret;

	pr_info("DATA INIT\n");
	data = init_container_ima(host_inum);
	
	/* Initialize IMA crypto */
	pr_info("CRYPTO INIT\n");
	ret = container_ima_crypto_init();

	/* Register kfunc for eBPF */
	task = current;
	pr_info("Getting host task\n");
	host_inum = task->nsproxy->cgroup_ns->ns.inum;
	

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &bpf_container_ima_kfunc_set);
	pr_info("Return val of registration %d\n", ret);
	if (ret < 0)
		return ret;
	
	pr_info("Return val of registration %d\n", ret);
	
	
	return ret;
}

static void container_ima_exit(void)
{
	/* Clean up 
	 */
	int ret;
	pr_info("Exiting Container IMA\n");
	kfree(data);
	//ret = container_ima_cleanup();
	return;
}

module_init(container_ima_init);
module_exit(container_ima_exit);


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(MODULE_NAME);
MODULE_AUTHOR("Avery Blanchard");

