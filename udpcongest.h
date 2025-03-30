#ifndef __UDPCONGEST_H
#define __UDPCONGEST_H

typedef unsigned long long __u64;

struct udp_congest_data {
    __u64 start_ts;
    __u32 prev_drops; // Previous drop count
};

struct udp_congest_event {
    __u64 duration_ns;
    __u64 ts_ns;
    __u32 drops;      // Number of dropped packets
    __u32 queue_len;  // Current queue length
};

#endif /* __UDPCONGEST_H */
