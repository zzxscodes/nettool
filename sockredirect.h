#ifndef __SOCKREDIRECT_H
#define __SOCKREDIRECT_H

struct sock_key {
    __u16 family; // Address family (AF_INET or AF_INET6)
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
