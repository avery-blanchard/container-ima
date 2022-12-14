#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <linux/bpf.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include "ebpf/bpf_helpers.h"

#define MAX_ENTRIES 100
/* struct for BPF argument mappings */
struct mmap_args_t {
	void *addr;
	size_t length;
	int prot;
	int flags;
	int fd;
	off_t offset;
};

int map_fd;
union bpf_attr map_attr = {
	.map_type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(uint64_t),
	.value_size = sizeof(struct mmap_args_t),
	.max_entries = MAX_ENTRIES,
	.map_flags = 0

};
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
	
	struct mmap_args_t *args;

	args->addr = addr;
	args->length = length;
	args->prot = prot;
	args->flags = flags;
	args->fd = fd;
	args->offset = offset;

	// https://man7.org/linux/man-pages/man2/bpf.2.html
	union bpf_attr attr = {
                          .map_fd = map_fd,
                          .key    = &id,
                          .value  = &args,
                          .flags  = 0,
                      };
	
	return syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));

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
	int sec_id;
	struct mmap_args_t *args;
	uint64_t id = bpf_get_current_pid_tgid();
	
	ret = 0;
	task =  bpf_get_current_task();
	union bpf_attr attr = {
                          .map_fd = map_fd,
                          .key    = &id,
                          .value  = &args,
        };

	ret = syscall(SYS_bpf,BPF_MAP_LOOKUP_ELEM, &attr,  sizeof(attr));

	//ret = mmap_bpf_map_lookup(id, args, map_fd);
	if (args->prot != 0x04) {
        printf("Protocol is not exec\n");
		return ret;
	}
    printf("Mmap length is %ld\n", args->length);
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
int main(int argc, char **argv)
{
	map_fd = syscall(SYS_bpf, BPF_MAP_CREATE, &map_attr, sizeof(map_attr));
}