#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "udpcongest.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct sock *);
    __type(value, struct udp_congest_data);
} udp_congest SEC(".maps");

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

static int trace_udp_congestion(struct sock *sk, void *ctx)
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

    // Read socket's drop counter and queue length
    u32 drops;
    u32 queue_len, sndbuf;
    if (bpf_probe_read_kernel(&drops, sizeof(drops), &sk->sk_drops) < 0)
        return 0;
    if (bpf_probe_read_kernel(&queue_len, sizeof(queue_len), &sk->sk_wmem_queued) < 0)
        return 0;
    if (bpf_probe_read_kernel(&sndbuf, sizeof(sndbuf), &sk->sk_sndbuf) < 0)
        return 0;

    struct udp_congest_data *congest_data = bpf_map_lookup_elem(&udp_congest, &sk);
    if (!congest_data) {
        struct udp_congest_data new_data = {};
        new_data.start_ts = bpf_ktime_get_ns();
        new_data.prev_drops = drops;
        bpf_map_update_elem(&udp_congest, &sk, &new_data, BPF_ANY);
        return 0;
    }

    // Check for congestion: drop count increased or queue length exceeds threshold
    if (drops > congest_data->prev_drops || queue_len >= sndbuf) {
        struct udp_congest_event event = {};
        event.duration_ns = bpf_ktime_get_ns() - congest_data->start_ts;
        event.ts_ns = bpf_ktime_get_ns();
        event.drops = drops - congest_data->prev_drops; // Number of dropped packets
        event.queue_len = queue_len; // Current queue length

        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

        // Update congestion data
        congest_data->start_ts = bpf_ktime_get_ns();
        congest_data->prev_drops = drops;
    }

    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kprobe_udp_sendmsg, struct sock *sk)
{
    return trace_udp_congestion(sk, ctx);
}

char LICENSE[] SEC("license") = "GPL";
