#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <string.h>

#define bpf_target_x86
#define bpf_target_defined
#define PROT_EXEC 0x04

char _license[] SEC("license") = "GPL";

struct ebpf_data {
        struct file *file;
        unsigned int ns;
};

extern int bpf_process_measurement(void *, int) __ksym;
extern int measure_file(struct file *) __ksym;

SEC("lsm.s/mmap_file")
int BPF_PROG(mmap_hook, struct file *file, unsigned int reqprot, 
		unsigned int prot, int flags) 
{
    struct task_struct *task;
    u32 key;
    unsigned int ns;
    int ret;

    if (!file) 
	return 0;
    
    if (prot & PROT_EXEC) {
	
	task = (void *) bpf_get_current_task();
        ns = BPF_CORE_READ(task, nsproxy, cgroup_ns, ns.inum);
	
	struct ebpf_data data = { .file = file, .ns = ns };
	
	ret = bpf_process_measurement((void *) &data, 
			sizeof(&data));


    }

    
    return 0;

}
