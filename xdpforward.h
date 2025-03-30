#ifndef __XDPFORWARD_H
#define __XDPFORWARD_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define IPV6_ADDR_LEN 16

struct rule_key {
    __u8 saddr_v6[IPV6_ADDR_LEN];
    __u8 daddr_v6[IPV6_ADDR_LEN];
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u32 priority; // Higher value means higher priority
};

struct rule_value {
    __u32 action; // 0: drop, 1: forward
};

#endif /* __XDPFORWARD_H */
