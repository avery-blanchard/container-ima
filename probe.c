#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <openssl/sha.h>
#include "probe.skel.h"


int cleanup(struct probe_bpf *skel)
{
    probe_bpf__destroy(skel);
    return -1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct probe_bpf *skel;
    int ret;

    libbpf_set_print(libbpf_print_fn);

    skel = probe_bpf__open_and_load();
    if (!skel) {
	    fprintf(stderr, "Failed to open BPF skeleton\n");
        return -1;
    }
    ret = probe_bpf__attach(skel);
    if (ret) {
	fprintf(stderr, "Failed to attach BPF skeleton\n");
	goto cleanup;
    }

    while(1) {
	sleep(5);
    }	

cleanup:
    cleanup(skel);
    return 0;
}
