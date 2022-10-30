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
#include <keys/system_keyring.h>

#define MODULE_NAME "ContainerIMA"

struct tpm_chip *container_ima_tpm;
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
	struct file *file;
	const char *filename;
	const void *buf;
	int len;
};
/*
 * ima_hash_setup
 *
 * Set up container IMA hashing/crypto algorithm 
 * use the alorithm that the kernel IMA defaulted 
 * to. Kernel IMA defaults to PCR IDX 10 (range 8-14), make sure
 * to choose a different register than host IMA
 */
void ima_hash_setup() 
{
	
	
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

	container_ima_tpm = tpm_default_chip();
	if (!container_ima_chip)
		pr_info("No TPM chip detected, bypassing\n");
	ret = integrity_init_keyring(INTEGRITY_KEYRING_IMA); // decide whether to use normal IMA keyring or not. Think about how this will affect normal IMA

	if (ret)
		return ret;
	ret = container_ima_crypto_init(); // iterate over PCR banks and init the algorithms per bank  

	if (ret)
		return ret;

	ret = container_ima_fs_init(); // set up directory for per container Measurment Log

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
	return NULL;
}


module_init(container_ima_init);
module_exit(container_ima_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(MODULE_NAME);
MODULE_AUTHOR("Avery Blanchard");

