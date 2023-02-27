#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "probe.skel.h"

int cleanup(struct probe_bpf *skel)
{
    probe_bpf__destroy(skel);
    return -1;
}

int main(int argc, char **argv)
{
    struct probe_bpf *skel;
    int ret;

    skel = probe_bpf__open_and_load();
    if (!skel)
        return -1;

    ret = probe_bpf__attach(skel);
    if (ret)
        return cleanup(skel);

    return 0;
}
