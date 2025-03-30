#include "vmlinux.h"
#include "xdpforward.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Define ETH_P_IP and ETH_P_IPV6 if not already defined
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

// Use an external map, which will be created in user space
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct rule_key);
    __type(value, struct rule_value);
} rules_map SEC(".maps");

static __always_inline int match_ports(__u16 rule_port, __u16 pkt_port) {
    return rule_port == 0 || rule_port == pkt_port;
}

static __always_inline int match_rule(const struct rule_key *key, const struct rule_key *pkt_key) {
    // Match source and destination IPs
    if (__builtin_memcmp(key->saddr_v6, pkt_key->saddr_v6, 16) != 0 &&
        __builtin_memcmp(key->saddr_v6, (const __u8[16]){0}, 16) != 0)
        return 0;

    if (__builtin_memcmp(key->daddr_v6, pkt_key->daddr_v6, 16) != 0 &&
        __builtin_memcmp(key->daddr_v6, (const __u8[16]){0}, 16) != 0)
        return 0;

    // Match source and destination ports
    if (!match_ports(key->sport, pkt_key->sport) || !match_ports(key->dport, pkt_key->dport))
        return 0;

    // Match protocol
    if (key->protocol != 0 && key->protocol != pkt_key->protocol)
        return 0;

    return 1;
}

static __always_inline int process_packet(struct xdp_md *ctx, struct rule_key *pkt_key) {
    struct rule_key key = {};
    struct rule_value *value;
    int action = XDP_DROP; 
    __u32 highest_priority = 0;

    // Iterate through all rules in the map
    for (int i = 0; i < 1024; i++) { // Assume a maximum of 1024 entries
        value = bpf_map_lookup_elem(&rules_map, &key);
        if (!value)
            break;

        if (match_rule(&key, pkt_key) && key.priority >= highest_priority) {
            highest_priority = key.priority;
            action = value->action == 0 ? XDP_DROP : XDP_PASS;
        }

        // Move to the next key (simulate iteration)
        __builtin_memset(&key, 0, sizeof(key)); // Reset key for next lookup
    }

    return action;
}

static __always_inline int parse_ipv4(struct xdp_md *ctx, void *data, void *data_end) {
    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(*eth);
    struct rule_key pkt_key = {};

    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    pkt_key.protocol = ip->protocol;
    pkt_key.saddr_v6[10] = 0xff; // Map IPv4 to IPv6-mapped address
    pkt_key.saddr_v6[11] = 0xff;
    pkt_key.daddr_v6[10] = 0xff;
    pkt_key.daddr_v6[11] = 0xff;
    *(__be32 *)&pkt_key.saddr_v6[12] = ip->saddr;
    *(__be32 *)&pkt_key.daddr_v6[12] = ip->daddr;

    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        struct tcphdr *l4 = (void *)(ip + 1);
        if ((void *)(l4 + 1) > data_end)
            return XDP_DROP;

        pkt_key.sport = l4->source;
        pkt_key.dport = l4->dest;
    }else{
        return XDP_PASS;
    }

    return process_packet(ctx, &pkt_key);
}

static __always_inline int parse_ipv6(struct xdp_md *ctx, void *data, void *data_end) {
    struct ethhdr *eth = data;
    struct ipv6hdr *ip6 = data + sizeof(*eth);
    struct rule_key pkt_key = {};

    if ((void *)(ip6 + 1) > data_end)
        return XDP_DROP;

    pkt_key.protocol = ip6->nexthdr;
    __builtin_memcpy(pkt_key.saddr_v6, ip6->saddr.in6_u.u6_addr8, 16);
    __builtin_memcpy(pkt_key.daddr_v6, ip6->daddr.in6_u.u6_addr8, 16);

    if (ip6->nexthdr == IPPROTO_TCP || ip6->nexthdr == IPPROTO_UDP) {
        struct tcphdr *l4 = (void *)(ip6 + 1);
        if ((void *)(l4 + 1) > data_end)
            return XDP_DROP;

        pkt_key.sport = l4->source;
        pkt_key.dport = l4->dest;
    }else{
        return XDP_PASS;
    }

    return process_packet(ctx, &pkt_key);
}

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    if (eth->h_proto == bpf_htons(ETH_P_IP))
        return parse_ipv4(ctx, data, data_end);
    else if (eth->h_proto == bpf_htons(ETH_P_IPV6))
        return parse_ipv6(ctx, data, data_end);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
