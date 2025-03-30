#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "udpbwth.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct sock *);
    __type(value, struct udp_flow_data);
} udp_flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u16);
} target_port SEC(".maps");

static int trace_udp_sendmsg(struct sock *sk, size_t size)
{
    u32 key = 0;
    u16 *port = bpf_map_lookup_elem(&target_port, &key);
    if (port) {
        u16 dport;
        if (bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport) < 0)
            return 0; // Fail gracefully if memory cannot be read
        if (dport != *port)
            return 0;
    }

    struct udp_flow_data *flow_data;
    u64 ts = bpf_ktime_get_ns();

    flow_data = bpf_map_lookup_elem(&udp_flows, &sk);
    if (!flow_data) {
        struct udp_flow_data new_flow = {};
        new_flow.bytes = size;
        new_flow.start_ts = ts;
        bpf_map_update_elem(&udp_flows, &sk, &new_flow, BPF_ANY);
    } else {
        flow_data->bytes += size;
    }

    return 0;
}

static int trace_udp_recvmsg(struct sock *sk, void *ctx) // Add ctx as a parameter
{
    u32 key = 0;
    u16 *port = bpf_map_lookup_elem(&target_port, &key);
    if (port) {
        u16 dport;
        if (bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport) < 0)
            return 0; // Fail gracefully if memory cannot be read
        if (dport != *port)
            return 0;
    }

    struct udp_flow_data *flow_data;
    struct udp_bw_event event = {};
    u64 ts = bpf_ktime_get_ns();

    flow_data = bpf_map_lookup_elem(&udp_flows, &sk);
    if (!flow_data)
        return 0;

    event.bytes = flow_data->bytes;
    event.duration_ns = ts - flow_data->start_ts;
    event.ts_ns = ts;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event)); // Use ctx here
    bpf_map_delete_elem(&udp_flows, &sk);

    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kprobe_udp_sendmsg, struct sock *sk, size_t size)
{
    return trace_udp_sendmsg(sk, size);
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(kprobe_udp_recvmsg, struct sock *sk)
{
    return trace_udp_recvmsg(sk, ctx); // Pass ctx to the function
}

char LICENSE[] SEC("license") = "GPL";
