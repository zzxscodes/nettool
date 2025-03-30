#ifndef __SOCKREDIRECT_H
#define __SOCKREDIRECT_H

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

struct sock_key {
    __u16 family;   // Address family (AF_INET or AF_INET6)
    __u8 protocol;  // IPPROTO_TCP or IPPROTO_UDP
    union {
        __u32 src_ip4;
        __u32 src_ip6[4];
    };
    union {
        __u32 dst_ip4;
        __u32 dst_ip6[4];
    };
    __u16 src_port;
    __u16 dst_port;
};

#endif /* __SOCKREDIRECT_H */
