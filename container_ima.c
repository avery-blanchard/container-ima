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

#define MODULE_NAME "ContainerIMA"
#define KEYRING_SIZE 10

const char *measure_log_dir = "/secure/container_ima/"; // in this dir, per container measurement logs 
struct vtpm_proxy_new_dev *container_vtpms;
struct key *keyring[KEYRING_SIZE];


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
	u32 container_id;
	u32 data_len;
};
struct inode_ima_data {
	struct mutex mut;
	struct inode *inode;
	unsigned long flags;
	struct container_ima_hash_data *hash;
};
struct container_ima_data {
	struct inode_ima_data iiam;
	struct vtpm_proxy_new_dev vtpm;
	struct file *file;
	const char *filename;
	const void *buf;
	int len;
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
int contain_keyring_init()
{


}
/*
 * container_keyring_add_key
 * create key from loading the vTPM x.509 cert
 */
int container_keyring_add_key() 
{

}
/*
 * ima_vtpm_setup 
 *
 * Set up per container vTPM, PCR 10 for IMA
 * https://www.kernel.org/doc/html/v4.13/security/tpm/tpm_vtpm_proxy.html
 * https://elixir.bootlin.com/linux/v6.0.5/source/drivers/char/tpm/tpm_vtpm_proxy.c#L624 
 */
long ima_vtpm_setup() 
{
	struct vtpm_proxy_new_dev new_vtpm;
	long ret;
	int ioctl; 
	struct file *vtpm_file;


	new_vtpm.flags = VTPM_PROXY_FLAG_TPM2;
	new_vtpm.tpm_num = 1; // change to unique container ID or use a countet
	new_vtpm.fd = "/dev/vtpm1";
	new_vtpm.major = 0; // major number of the TPM device
	new_vtp.minor = 1; // minor number of the TPM device


	ret = vtpmx_ioc_new_dev(vtpm_file, ioctl, (unsigned long)&new_vtpm);
	
	if (ret != 0) {
		pr_err("Failed to create a new vTPM device\n");
	}

	return ret;
	
}
/*
 * container_ima_setup
 *
 * Set up environment to initalize container IMA
 */
void container_ima_setup()
{
	ima_hash_setup();

}
/*
 * container_ima_init
 *
 * Initalize container IMA
 */
int container_ima_init() 
{
	int ret;

	container_ima_tpm = ima_vtpm_setup() // per container vTPM

	ret = integrity_init_keyring(INTEGRITY_KEYRING_IMA); // per container key ring

	if (ret)
		return ret;
	ret = container_ima_crypto_init(); // iterate over PCR banks and init the algorithms per bank  

	if (ret)
		return ret;

	ret = container_ima_ml_init(); // set up directory for per container Measurment Log

	if (ret) 
		return ret;

	container_ima_policy_init();

	return ret;
}
/* check_container_map 
 * 
 * Determine whether mmap call was from a container or host process  
 */
int check_container_map() 
{


}

/* mapping of id to system call arguments */
BPF_HASH(active_mmap_args_map, uint64, struct mmap_args_t);

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
	struct mmap_args_t *args = {};
	struct task_struct *task = bpf_get_current_task();
	unsigned int inum = task->nsproxy->cgroup_ns->ns_common->inum;

	active_mmap_args_map.pop(&args);

	if (inum == host_inum) {
		return 0;
	}

	if (args->prot != PROT_READ && args->prot != PROR_EXEC) {
		return 0;
	}

	/* Check if container already has an active ML, create hash of page and add to ML */

	/* If not, create vTPM and key ring, create hash of page and add to ML */


}
static int container_ima_init(void)
{
	/* Start container IMA */
	int ret;
	container_ima_setup();
	ret = container_ima_init();

	return ret;
}

static void container_ima_init(void)
{
	/* Clean up 
	 * Free keyring and vTPMs
	 */
	return NULL;
}


module_init(container_ima_init);
module_exit(container_ima_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(MODULE_NAME);
MODULE_AUTHOR("Avery Blanchard");

