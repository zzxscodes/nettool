#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "sockredirect.h"

#define AF_INET     2
#define AF_INET6    10
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define ETH_HLEN    14

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 1024);
    __type(key, struct sock_key);
    __type(value, __u64);
} sock_map SEC(".maps");

// 获取协议类型
static __always_inline int get_protocol(struct bpf_sock_ops *skops) {
    struct bpf_sock *sk = skops->sk;
    return sk ? sk->protocol : IPPROTO_TCP; // 默认TCP
}

// 从sock_ops填充键
static __always_inline void populate_sock_key_from_sockops(struct sock_key *key, struct bpf_sock_ops *skops) {
    key->protocol = get_protocol(skops);
    if (skops->family == AF_INET) {
        key->family = AF_INET;
        key->src_ip4 = skops->local_ip4;
        key->dst_ip4 = skops->remote_ip4;
    } else if (skops->family == AF_INET6) {
        key->family = AF_INET6;
        bpf_probe_read_kernel(&key->src_ip6, sizeof(key->src_ip6), skops->local_ip6);
        bpf_probe_read_kernel(&key->dst_ip6, sizeof(key->dst_ip6), skops->remote_ip6);
    }
    key->src_port = bpf_ntohs(skops->local_port);
    key->dst_port = bpf_ntohs(skops->remote_port);
}

// 从sk_msg填充键
static __always_inline void populate_sock_key_from_sk_msg(struct sock_key *key, struct sk_msg_md *msg) {
    key->protocol = msg->protocol;
    if (msg->family == AF_INET) {
        key->family = AF_INET;
        key->src_ip4 = msg->local_ip4;
        key->dst_ip4 = msg->remote_ip4;
    } else if (msg->family == AF_INET6) {
        key->family = AF_INET6;
        bpf_probe_read_kernel(&key->src_ip6, sizeof(key->src_ip6), msg->local_ip6);
        bpf_probe_read_kernel(&key->dst_ip6, sizeof(key->dst_ip6), msg->remote_ip6);
    }
    key->src_port = bpf_ntohs(msg->local_port);
    key->dst_port = bpf_ntohs(msg->remote_port);
}

// 从sk_skb填充键
static __always_inline int populate_sock_key_from_sk_skb(struct sock_key *key, struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return -1;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = data + ETH_HLEN;
        if ((void *)(ip + 1) > data_end) return -1;
        
        key->family = AF_INET;
        key->src_ip4 = ip->saddr;
        key->dst_ip4 = ip->daddr;
        
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
            if ((void *)(tcp + 1) > data_end) return -1;
            key->protocol = IPPROTO_TCP;
            key->src_port = tcp->source;
            key->dst_port = tcp->dest;
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip + (ip->ihl * 4);
            if ((void *)(udp + 1) > data_end) return -1;
            key->protocol = IPPROTO_UDP;
            key->src_port = udp->source;
            key->dst_port = udp->dest;
        } else {
            return 1; // 非TCP/UDP
        }
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = data + ETH_HLEN;
        if ((void *)(ip6 + 1) > data_end) return -1;
        
        key->family = AF_INET6;
        bpf_probe_read_kernel(&key->src_ip6, sizeof(key->src_ip6), &ip6->saddr);
        bpf_probe_read_kernel(&key->dst_ip6, sizeof(key->dst_ip6), &ip6->daddr);
        
        if (ip6->nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip6 + sizeof(struct ipv6hdr);
            if ((void *)(tcp + 1) > data_end) return -1;
            key->protocol = IPPROTO_TCP;
            key->src_port = tcp->source;
            key->dst_port = tcp->dest;
        } else if (ip6->nexthdr == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip6 + sizeof(struct ipv6hdr);
            if ((void *)(udp + 1) > data_end) return -1;
            key->protocol = IPPROTO_UDP;
            key->src_port = udp->source;
            key->dst_port = udp->dest;
        } else {
            return 1; // 非TCP/UDP
        }
    } else {
        return 1; // 非IP协议
    }
    
    return 0;
}

SEC("sockops")
int sock_map_update(struct bpf_sock_ops *skops) {
    if (skops->family != AF_INET && skops->family != AF_INET6) return 0;

    struct sock_key key = {};
    populate_sock_key_from_sockops(&key, skops);

    // 处理TCP连接
    if ((skops->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB ||
         skops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) && 
        key.protocol == IPPROTO_TCP) {
        bpf_sock_hash_update(skops, &sock_map, &key, BPF_ANY);
    }

    // 处理UDP socket
    if (key.protocol == IPPROTO_UDP) {
        bpf_sock_hash_update(skops, &sock_map, &key, BPF_ANY);
    }

    return 0;
}

SEC("sk_msg")
int sock_redirect_msg(struct sk_msg_md *msg) {
    struct sock_key key = {};
    populate_sock_key_from_sk_msg(&key, msg);

    // 仅处理TCP/UDP
    if (key.protocol != IPPROTO_TCP && key.protocol != IPPROTO_UDP) 
        return SK_DROP;

    return bpf_msg_redirect_hash(msg, &sock_map, &key, BPF_F_INGRESS) == 0 ? SK_PASS : SK_DROP;
}

SEC("sk_skb/stream_verdict")
int udp_tcp_redirect_verdict(struct __sk_buff *skb) {
    struct sock_key key = {};
    int ret = populate_sock_key_from_sk_skb(&key, skb);
    
    if (ret < 0) return SK_DROP; // 解析失败
    if (ret > 0) return SK_PASS;  // 非目标协议
    
    return bpf_sk_redirect_hash(skb, &sock_map, &key, BPF_F_INGRESS) == 0 ? SK_PASS : SK_DROP;
}

SEC("sk_skb/stream_parser")
int packet_parser(struct __sk_buff *skb) {
    return skb->len;
}

char LICENSE[] SEC("license") = "GPL";
