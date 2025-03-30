#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "sockredirect.h"

#define AF_INET    2
#define AF_INET6   10

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 1024);
    __type(key, struct sock_key);
    __type(value, __u64); // Socket reference
} sock_map SEC(".maps");

SEC("sockops")
int sock_map_update(struct bpf_sock_ops *skops) {
    struct sock_key key = {};
    if (skops->family == AF_INET) {
        key.family = AF_INET;
        key.src_ip4 = skops->local_ip4;
        key.dst_ip4 = skops->remote_ip4;
    } else if (skops->family == AF_INET6) {
        key.family = AF_INET6;
        bpf_probe_read_kernel(&key.src_ip6, sizeof(key.src_ip6), skops->local_ip6);
        bpf_probe_read_kernel(&key.dst_ip6, sizeof(key.dst_ip6), skops->remote_ip6);
    } else {
        return 0; // Unsupported family
    }
    key.src_port = bpf_ntohs(skops->local_port);
    key.dst_port = bpf_ntohs(skops->remote_port);

    if (skops->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB ||
        skops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
        bpf_sock_hash_update(skops, &sock_map, &key, BPF_ANY);
    }

    return 0;
}

// Update the section name to 'sk_msg' to specify the correct BPF program type
SEC("sk_msg")
int sockredirect_msg_redirect(struct sk_msg_md *msg) {
    struct sock_key key = {};
    if (msg->family == AF_INET) {
        key.family = AF_INET;
        key.src_ip4 = msg->local_ip4;
        key.dst_ip4 = msg->remote_ip4;
    } else if (msg->family == AF_INET6) {
        key.family = AF_INET6;
        bpf_probe_read_kernel(&key.src_ip6, sizeof(key.src_ip6), msg->local_ip6);
        bpf_probe_read_kernel(&key.dst_ip6, sizeof(key.dst_ip6), msg->remote_ip6);
    } else {
        return SK_DROP; // Unsupported family
    }
    key.src_port = bpf_ntohs(msg->local_port);
    key.dst_port = bpf_ntohs(msg->remote_port);

    if (bpf_msg_redirect_hash(msg, &sock_map, &key, BPF_F_INGRESS) == 0) {
        return SK_PASS;
    }

    return SK_DROP;
}

char LICENSE[] SEC("license") = "GPL";
