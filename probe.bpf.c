#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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
extern int testing(void) __ksym;

// int mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
SEC("kprobe/__x64_sys_mmap")
int mmap_probe(struct pt_regs *ctx) {
    
    int len;
    struct mmap_args_t  *value;
    struct file *file;
    struct mmap_args_t mmap;
   
    __builtin_memset(&mmap, 0, sizeof(mmap));
    

    mmap.addr = (void *)PT_REGS_PARM1(ctx);
    mmap.length = (int)PT_REGS_PARM2(ctx);
    mmap.prot = (int) PT_REGS_PARM3(ctx);
    mmap.flags = (int) PT_REGS_PARM4(ctx);
    mmap.fd = (int) PT_REGS_PARM5(ctx);
    //mmap.offset = (int)offset; //(int) __bpf_syscall_args5(ctx);
    
    //task = (struct task_struct *)bpf_get_current_task();
    //id =  task->nsproxy->cgroup_ns->ns.inum;
    //mmap.id = id;
    if (mmap.prot == 0x04)
        testing();

    return 0;

}