#ifndef __TCPCONNLAT_H
#define __TCPCONNLAT_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define TASK_COMM_LEN 16

struct connlat_event {
    union {
        __u32 saddr_v4;
        __u8 saddr_v6[16];
    };
    union {
        __u32 daddr_v4;
        __u8 daddr_v6[16];
    };
    char comm[TASK_COMM_LEN];
    __u64 delta_us;
    __u64 ts_us;
    __u32 tgid;
    int af;
    __u16 lport;
    __u16 dport;
};

#endif /* __TCPCONNLAT_H */