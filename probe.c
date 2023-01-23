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

int syscall__mmap(struct pt_regs *ctx, void *addr, size_t length, int prot, int flags, int fd, off_t offset)  {
    
    struct task_struct *task;
    u64 id;
    int ret;
    const struct cred *cred;
    struct file *file;
    struct mmap_args_t args = {
        .addr = addr,
        .length = length,
        .prot = prot,
        .flags = flags,
        .fd = fd,
        .offset = offset,
        .id = 0
    };

    task = (struct task_struct *)bpf_get_current_task();
    id =  task->nsproxy->cgroup_ns->ns.inum;
    ars.id = id;

    /* Check if file is executable */
    if (prot == 0x04) {
        data = init_container_ima(args->id, c_ima_dir, c_ima_symlink);
				
		file = container_ima_retrieve_file(args);
		if (!file) 
            return 0;		
		cred = task->real_cred;
		security_cred_getsecid(cred, &sec_id);
		ret = container_ima_process_measurement(data, cur_file, current_cred(), sec_id, NULL, 0, MAY_EXEC, args->id, args);
        return 0;
    }
           
    
    return 0;
}
