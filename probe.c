#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <openssl/sha.h>
#include "probe.skel.h"

struct ima {
        char digest[2048];
        char f_buf[2048];
        char *f_name;
        struct ima_template *template;
        int size;
        int algo;
};

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
    struct ima *ima_data;
    size_t len;
    FILE *filp, *ima_log;
    char *ima_name = "/ima";
    u32 key = 1;

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
        ima_data = bpf_map_lookup_elem(&map, &key);
        if (ima_data) {
            filp = fopen(ima_data->f_name, "r");
            ima_log = fopen("/ima", "a");
            fgets(ima_data->f_buf, 2048, filp);
            len = strlen(ima_data->f_buf);

            SHA1(ima_data->f_buf, len, ima_data->digest);

            bpf_map_update_elem(&map. &key, &ima_data);

            fputs(ima_data->digest, len, ima_log);

        }
    }
	    

cleanup:
    cleanup(skel);
    return 0;
}
