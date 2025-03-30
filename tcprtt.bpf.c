#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "tcprtt.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile bool targ_ms = false; // Flag for --ms
const volatile bool targ_ext = false; // Flag for --ext

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32); // PID as key
    __type(value, struct rtt_stats); // Extended statistics
} stats SEC(".maps");

SEC("fentry/tcp_rcv_established")
int BPF_PROG(tcp_rcv, struct sock *sk) {
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    struct rtt_event evt = {};
    struct rtt_stats *stat;
    u32 srtt_us, pid;

    srtt_us = BPF_CORE_READ(tp, srtt_us) >> 3; // Convert to microseconds
    if (targ_ms)
        srtt_us /= 1000; // Convert to milliseconds if --ms is set

    pid = bpf_get_current_pid_tgid() >> 32;
    evt.srtt = srtt_us;
    evt.pid = pid;

    if (targ_ext) {
        stat = bpf_map_lookup_elem(&stats, &pid);
        if (!stat) {
            struct rtt_stats zero = {};
            bpf_map_update_elem(&stats, &pid, &zero, BPF_ANY);
            stat = bpf_map_lookup_elem(&stats, &pid);
        }
        if (stat) {
            __sync_fetch_and_add(&stat->total_rtt, srtt_us);
            __sync_fetch_and_add(&stat->count, 1);
        }
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}
