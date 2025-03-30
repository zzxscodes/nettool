#ifndef __UDPBWTH_H
#define __UDPBWTH_H

typedef unsigned long long __u64;

struct udp_flow_data {
    __u64 bytes;
    __u64 start_ts;
};

struct udp_bw_event {
    __u64 bytes;
    __u64 duration_ns;
    __u64 ts_ns;
};

#endif /* __UDPBWTH_H */
