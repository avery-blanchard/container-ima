#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "probe.skel.h"

int cleanup(struct kprobe_bpf *skel)
{
    kprobe_bpf__destroy(skel);
    return -1;
}

int main(int argc, char **argv)
{
    struct kprobe_bpf *skel;
    int ret;

    skel = kprobe_bpf__open_and_load();
    if (!skel)
        return -1;

    ret = kprobe_bpf__attach(skel);
    if (ret)
        return cleanup(skel);

    return 0;
}
