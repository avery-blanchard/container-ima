#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#define bpf_target_x86
#define bpf_target_defined

char _license[] SEC("license") = "GPL";

struct mmap_args_t {
	void *addr;
	size_t length;
	int prot;
	int flags;
	int fd;
	int offset;
};
extern int bpfmeasurement(unsigned int inum) __ksym;
extern struct file *container_ima_retrieve_file(int fd) __ksym;

// int mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
SEC("kprobe/__x64_sys_mmap")
int kprobe__sys_mmap(struct pt_regs *ctx) {

    struct task_struct *task;
    unsigned int inum;
    struct file *file;
    struct mmap_args_t *mmap;
    struct inode *inode;
    const unsigned char *filename;
    int ret, action, len;
    void *buf;
    atomic64_t i_version;
    loff_t i_size;
    struct crypto_shash *ftm;
    struct shash_desc *shash;
    unsigned int flags;
    fmode_t mode;
    struct {
	    struct ima_digest_data hdr;
	    char digest[2048];
    } hash;


    mmap->length = (int) PT_REGS_PARM2(ctx);
    mmap->prot = (int) PT_REGS_PARM3(ctx);
    mmap->flags = (int) PT_REGS_PARM4(ctx);
    mmap->fd = (int) PT_REGS_PARM5(ctx);
    mmap->offset = 0;

    if (mmap->prot != 0x04)
	    return 0;

    task = (void *) bpf_get_current_task();

    inum = BPF_CORE_READ(task, nsproxy, cgroup_ns, ns.inum);

    ret = bpfmeasurement(inum);

    if (ret > 0) {

	    file = container_ima_retrieve_file(mmap->fd);
	    
	    if (file) {

                        inode = BPF_CORE_READ(file, f_inode);
                        filename = BPF_CORE_READ(file, f_path.dentry, d_name.name);
                        //i_version = BPF_CORE_READ(inode, i_version);

                        //hash.hdr.algo = ima_hash_algo;
                        //hash.hdr.length = hash_digest_size[ima_hash_algo];

                        flags = BPF_CORE_READ(file, f_flags);
                        /*
			if (file->f_flags & O_DIRECT) {
                                return 0;
                        }
                        mode = BPF_CORE_READ(file, f_mode);
                        if (!(file->f_mode & FMODE_READ)) {
                                return 0;
                        }*/

                        i_size = BPF_CORE_READ(inode, i_size);
                        if (!i_size) {
                                return 0;
                        }
                        //ftm = ima_shash_tfm;

                        //ftm = ftm->base.__crt_algo->cra_init(&ftm->base);

                        return 0;

	    }

    }
    return 0;

}
