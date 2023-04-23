#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <string.h>

#define bpf_target_x86
#define bpf_target_defined

#define FMODE_READ	0x1
#define O_DIRECT	00040000
#define TPM_ALG_SHA256	0x000B
#define TPM_ALG_SHA1	0x0004 //to do

char _license[] SEC("license") = "GPL";

struct ima_hash {
            struct ima_digest_data hdr;
            char digest[2048];
};

struct ima_data {
        unsigned int inum;
        struct ima_hash hash;
        struct file *file;
        struct inode *inode;
        void *f_buf;
        fmode_t f_mode;
        unsigned int f_flags;
        const unsigned char *f_name;
        int (*cra_init)(struct crypto_tfm *tfm);
        struct crypto_shash *shash;
        struct crypto_tfm base;
	int size;
	struct tpm_digest *tpm_digest;
};

extern int bpfmeasurement(unsigned int inum) __ksym;
extern struct file *container_ima_retrieve_file(int fd) __ksym;
extern struct ima_hash ima_hash_setup(void) __ksym;
extern void *ima_buffer_read(struct file *file) __ksym;
extern struct crypto_shash *ima_shash_init(void) __ksym;
extern int ima_crypto(void *buf, int size, struct crypto_shash *shash, struct crypto_tfm base, int (*cra_init)(struct crypto_tfm *tfm), u8 digest[]) __ksym;
extern int ima_pcr_extend(struct tpm_digest *digests_arg, int pcr) __ksym;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct ima_data);
	__uint(max_entries, 256);
} map SEC(".maps");

// int mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
SEC("kprobe/__x64_sys_mmap")
int BPF_KPROBE(kprobe___sys_mmap, void *addr, unsigned long length, unsigned long prot, unsigned long flags, unsigned long fd) {

    int ret, len;
    u32 key;
    struct ima_data *data;
    struct task_struct *task;

    bpf_printk("Integrity measurement for fd %d\n", fd);
    
    if (prot != 0x04)
	    return 0;
    
    task = (void *) bpf_get_current_task();

    key = bpf_get_prandom_u32();
    data = (struct ima_data *) bpf_map_lookup_elem(&map, &key);

    if (ret) {
         bpf_printk("ERROR: Could not update map element");
	 return 0;
    }

    data->inum = BPF_CORE_READ(task, nsproxy, cgroup_ns, ns.inum);
    ret = bpfmeasurement(data->inum);

    if (ret < 0) {

	    bpf_printk("PRE RETRIEVE FILE\n");
	    data->file = container_ima_retrieve_file(fd);
	   	    
	    if (data->file) {

                        data->inode = BPF_CORE_READ(data->file, f_inode);
                        data->f_name = BPF_CORE_READ(data->file, f_path.dentry, d_name.name);


			data->hash = ima_hash_setup();

                        data->f_flags = BPF_CORE_READ(data->file, f_flags); 
			if (data->f_flags & O_DIRECT) {
                                return 0;
                        }
                        
			data->f_mode = BPF_CORE_READ(data->file, f_mode);
                        if (!(data->f_mode & FMODE_READ)) {
                                return 0;
                        }

			data->f_buf = ima_buffer_read(data->file);
			if (!data->f_buf) {
				return 0;
			}

			data->shash = ima_shash_init();

			data->cra_init = BPF_CORE_READ(data->shash,base.__crt_alg, cra_init);
			data->base = BPF_CORE_READ(data->shash, base);
			data->size = 0; // to do
			
			ret = ima_crypto(data->f_buf, data->size, data->shash, data->base, data->cra_init, data->hash.hdr.digest);

			strncpy(&data->tpm_digest->digest[0], &data->hash.hdr.digest[0], sizeof(data->hash.hdr.digest));
			
			data->tpm_digest->alg_id = TPM_ALG_SHA256;
			
			ret = ima_pcr_extend(data->tpm_digest, 10);

                        ret = bpf_map_update_elem(&map, &key, &data, BPF_ANY);
			
			if (ret) 	
				bpf_printk("ERROR: Could not update map element");
	   		
			return 0;

	    }

    }
    return 0;

}
