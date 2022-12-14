#!/usr/bin/python3
from bcc import BPF

prog = """
#include <linux/sched.h>
#include <linux/fs.h>
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
	off_t offset;
    uint64_t id;
};

BPF_HASH(mmap_args, u32, struct mmap_args_t);

int syscall__mmap(struct pt_regs *ctx, void *addr, size_t length, int prot, int flags, int fd, off_t offset)  {
    
    struct task_struct *task;
    u64 id;
    u32 key;
    int len;
    struct mmap_args_t  *value;
    struct file *file;
    struct mmap_args_t mmap;
    // https://github.com/iovisor/bcc/issues/2623#issuecomment-560214481 
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
        mmap_args.insert(&key, &mmap);
    
    
    return 0;
}
"""

b = BPF(text=prog)
clone = b.get_syscall_fnname("mmap")
b.attach_kprobe(event=clone, fn_name="syscall__mmap")
table = b.get_table("mmap_args")
while 1:
        for key, value in table.items():
            log = open("/home/avery/container-ima/log.txt", 'a+')
            cur_line = ""
            cur_line += "{0}, {1}, {2}, {3}, {4}, {5}\n".format(value.id, value.addr, value.length, value.flags, value.fd, value.offset)
            #cur_line += "{0}\n".format(value)
            log.write(cur_line)
            log.close()
            print(cur_line)

