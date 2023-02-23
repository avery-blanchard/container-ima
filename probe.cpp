#include <unistd.h>
#include <fstream>
#include <iostream>
#include <string>
#include <bcc/BPF.h>

const std::string BPF_PROGRAM = R"(#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/bpf.h>
#include <linux/nsproxy.h>
#include <linux/cgroup.h>
#include <linux/security.h>
#include <linux/integrity.h>

struct mmap_args_t {
	void *addr;
	size_t length;
	int prot;
	int flags;
	int fd;
	int offset;
	long id;
};
extern int testing(void) __ksym;

int syscall__mmap(struct pt_regs *ctx, void *addr, size_t length, int prot, int flags, int fd, off_t offset)  {
    
    struct task_struct *task;
    u64 id;
    u32 key;
    int len;
    struct mmap_args_t  *value;
    struct file *file;
    struct mmap_args_t mmap;
   
    __builtin_memset(&mmap, 0, sizeof(mmap));
    
    mmap.addr = addr;
    mmap.length = length;
    mmap.prot = prot;
    mmap.flags = flags;
    mmap.fd = fd;
    mmap.offset = offset;
    
    task = (struct task_struct *)bpf_get_current_task();
    id =  task->nsproxy->cgroup_ns->ns.inum;
    mmap.id = id;
    key = bpf_get_prandom_u32();

    if (prot == 0x04)
        testing();
    

    return 0;
})";

int main() {
    ebpf::BPF bpf;
    std::string clone_fnname = bpf.get_syscall_fnname("mmap");
    
    auto init_res = bpf.init(BPF_PROGRAM);
    if (init_res.code() != 0) {
        return -1;
    }

    auto attach_res = bpf.attach_kprobe(clone_fnname, "syscall__mmap");
    if (attach_res.code()!=0) {
        return -1;
    }

    return 0;

}