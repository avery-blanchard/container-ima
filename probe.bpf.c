#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#define bpf_target_x86
#define bpf_target_defined

char _license[] SEC("license") = "GPL";

extern int bpfmeasurement(unsigned int inum) __ksym;
extern struct file *container_ima_retrieve_file(int fd) __ksym;

// int mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
SEC("kprobe/__x64_sys_mmap")
int BPF_KPROBE(kprobe___sys_mmap, void *addr, unsigned long length, unsigned long prot, unsigned long flags, unsigned long fd) {

    struct task_struct *task;
    unsigned int inum;
    struct file *file;
    struct mmap_args_t mmap;
    struct inode *inode;
    const unsigned char *filename;
    int ret, action, len;
    void *buf;
    atomic64_t i_version;
    loff_t i_size;
    struct crypto_shash *ftm;
    struct shash_desc *shash;
    unsigned int file_flags;
    fmode_t mode;
    struct {
	    struct ima_digest_data hdr;
	    char digest[2048];
    } hash;


    bpf_printk("Integrity measurement for fd %d\n", fd);
    task = (void *) bpf_get_current_task();

    inum = BPF_CORE_READ(task, nsproxy, cgroup_ns, ns.inum);
    ret = bpfmeasurement(inum);

    if (ret < 0) {

	    bpf_printk("PRE RETRIEVE FILE\n");
	    file = container_ima_retrieve_file(fd);
	   	    
	    if (file) {

                        inode = BPF_CORE_READ(file, f_inode);
                        filename = BPF_CORE_READ(file, f_path.dentry, d_name.name);
                        i_version = BPF_CORE_READ(inode, i_version);

                        //hash.hdr.algo = ima_hash_algo;
                        //hash.hdr.length = hash_digest_size[ima_hash_algo];

                        flags = BPF_CORE_READ(file, f_flags); /*
			if (file->f_flags & O_DIRECT) {
                                return 0;
                        }*/
                        mode = BPF_CORE_READ(file, f_mode);/*
                        if (!(file->f_mode & FMODE_READ)) {
                                return 0;
                        }*/

                        i_size = BPF_CORE_READ(inode, i_size);
                        if (!i_size) {
                                return 0;
                        }
                        //ftm = ima_shash_tfm;

                        //ftm = BPF_CORE_READ(ftm,base.__crt_alg, cra_init(&ftm->base));

                        return 0;

	    }

    }
    return 0;

}
