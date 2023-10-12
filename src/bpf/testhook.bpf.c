#include "testhook.bpf.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

extern int LINUX_KERNEL_VERSION __kconfig;

struct event _event = {}; // Dummy instance for skeleton to generate definition

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events
    SEC(".maps");

static __always_inline int record_cap(void *ctx, const struct cred *cred,
                                      struct user_namespace *targ_ns, int cap, int cap_opt)
{
    u64 __pid_tgid = bpf_get_current_pid_tgid();
    gid_t tgid = __pid_tgid >> 32;
    pid_t pid = __pid_tgid;

    struct event event = {
        .pid = pid,
    };

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kprobe__cap_capable, const struct cred *cred,
               struct user_namespace *targ_ns, int cap, int cap_opt)
{
    return record_cap(ctx, cred, targ_ns, cap, cap_opt);
}

char LICENSE[] SEC("license") = "GPL";