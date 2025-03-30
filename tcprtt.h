#ifndef __TCPRTT_H
#define __TCPRTT_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

struct rtt_event {
    __u32 pid;
    __u32 srtt; // Smoothed RTT in microseconds
};

struct rtt_stats {
    __u64 total_rtt; // Total RTT for calculating average
    __u64 count;     // Count of RTT samples
};

#endif /* __TCPRTT_H */
