#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
/* struct for BPF argument mappings */
struct mmap_args_t {
	void *addr;
	size_t length;
	int prot;
	int flags;
	int fd;
	off_t offset;
};
BPF_HASH(active_mmap_args_map, u64);
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
	printf("In mmap probe entry\n");
	uint64_t id = bpf_get_current_pid_tgid();
	
	struct mmap_args_t *args;

	args->addr = addr;
	args->length = length;
	args->prot = prot;
	args->flags = flags;
	args->fd = fd;
	args->offset = offset;

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

	int ret;
	struct task_struct *task;
	struct file *file;
	struct container_ima_data *data;
	unsigned int inum;
	const struct cred *cred;
	struct nsproxy *ns;
	u32 sec_id;
	struct mmap_args_t *args;
	uint64_t id = bpf_get_current_pid_tgid();
	
	ret = 0;
	task =  bpf_get_current_task();
    ns = task->nsproxy;
	if (!ns->cgroup_ns)
		return -1;
	
	inum = ns->cgroup_ns->ns.inum;
	active_mmap_args_map.pop(&args);
	//ret = mmap_bpf_map_lookup(id, args, map_fd);

	if (inum == host_inum) {
		return ret;
	}
	if (args->prot != PROT_EXEC) {
        printf("Protocol is not exec\n");
		return ret;
	}
    printf("Mmap length is %d\n", args->len);
	/*data = init_container_ima(inum, c_ima_dir, c_ima_symlink);

	/*file = container_ima_retrieve_file(args);
	if (!file) {
		pr_err("error retrieving file\n");
		return -1;
	}
	//cred = get_task_cred(task);
	cred = rcu_dereference_protected(current->cred, 1);
	security_cred_getsecid(cred, &sec_id);

	/*ret = container_ima_process_measurement(data, file, current_cred(), sec_id, NULL, 0, MAY_EXEC, inum, args);
	if (ret != 0) {
		pr_err("measurement fails\n");
		return ret;
	}*/

	return ret;
}