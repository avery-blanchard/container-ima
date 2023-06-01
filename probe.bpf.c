#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <string.h>

#define bpf_target_x86
#define bpf_target_defined
#define IMA_HASH_BITS 9
#define IMA_MEASURE_HTABLE_SIZE 64
#define MAP_ANONYMOUS	0x20	
#define PROT_EXEC 0x04

char _license[] SEC("license") = "GPL";

struct ima_data {
	long len; // number of digest
	long violations; // violations count 
	//spinlock_t queue_lock;
	struct list_head measurements; // linked list of measurements 
	//unsigned long binary_runtime_size;
	//struct ima_h_table *hash_tbl;  
	int policy_flags;
	struct rb_root iint_tree;
};

struct mmap_args {
	size_t length;
       	int prot;
       	int flags;
       	int fd;
	unsigned int ns;
};

struct ebpf_var {
	struct ima_data *ima_data;
	struct mmap_args *args;
};

struct test {
	struct file *file;
	unsigned int ns;
};

extern int bpf_process_measurement(struct file *, int, unsigned int ) __ksym;
extern struct list_head init_ns_ml(void) __ksym;
extern struct rb_root init_ns_iint_tree(void) __ksym;
extern int measure_file(struct file *) __ksym;
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct mmap_args);
	__uint(max_entries, 256);
} mmap_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key, u32);
        __type(value, struct file *);
        __uint(max_entries, 256);
} var_map SEC(".maps");
/*
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct ima_data);
	__uint(max_entries, 256);
} ima_map SEC(".maps");
*/

// int mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
/*SEC("kprobe/__x64_sys_mmap.s")
int  BPF_KPROBE_SYSCALL(kprobe___sys_mmap, void *addr, unsigned long length, unsigned long prot, unsigned long flags, unsigned long fd) 
{*/
SEC("lsm.s/mmap_file")
int BPF_PROG(mmap_hook, struct file *file, unsigned int reqprot, unsigned int prot, int flags) 
{
    struct mmap_args *args;
    struct ima_data *ima_data;
    struct task_struct *task;
    struct file *current;
    u32 key;
    unsigned int ns;
    int ret;

    if (!file) 
	return 0;
    if (prot & PROT_EXEC || reqprot & PROT_EXEC) {
    
	
	key = 0;/*
	current = (struct ebpf_var *) bpf_map_lookup_elem(&var_map, &key);
        if (!current) {
		return 0;
	}*/
	task = (void *) bpf_get_current_task();


        current = (struct file *) bpf_map_lookup_elem(&var_map, &key);
        if (!current) {
                bpf_printk("Map element lookup failed\n");
                return 0;
        }
	/*
	args->length = length;
	args->prot = prot;
	args->flags = flags;
	args->fd = fd;
	*/

        ns = BPF_CORE_READ(task, nsproxy, cgroup_ns, ns.inum);
	
	//current->args = args;
	//ima_data = (struct ima_data *) bpf_map_lookup_elem(&ima_map, &ns);
	
	ret = bpf_process_measurement(file, sizeof(file), ns);


    }

    
    return 0;

}
