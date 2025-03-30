#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h> 
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <linux/types.h> 
#include "tcpstates.h"
#include "tcprtt.h"
#include "tcpconnlat.h"
#include "udpbwth.h"
#include "udpcongest.h"
#include "sockredirect.h"
#include "xdpforward.h"
#include "tcpstates.skel.h"
#include "tcpconnlat.skel.h"
#include "tcprtt.skel.h"
#include "udpbwth.skel.h"
#include "udpcongest.skel.h"
#include "sockredirect.skel.h"
#include "xdpforward.skel.h"
#include <sys/stat.h>
#include <fnmatch.h> // Include fnmatch for wildcard matching

#define PERF_BUFFER_PAGES 16
#define PERF_POLL_TIMEOUT_MS 100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

enum tool_mode {
    MODE_TCPSTATES,
    MODE_TCPRTT,
    MODE_TCPCONNLAT, 
    MODE_UDPBANDWIDTH,
    MODE_UDPCONGEST,
    MODE_SOCKREDIRECT, 
    MODE_XDPFORWARD,
};

static enum tool_mode mode = MODE_TCPSTATES;
static bool verbose = false;
static bool emit_timestamp = false;
static bool targ_ms = false;
static bool targ_show_ext = false;
static short target_family = 0;
static char *target_sports = NULL;
static char *target_dports = NULL;
static __u64 targ_min_us = 0;
static pid_t targ_pid = 0;
static __u16 target_udp_port = 0; // Updated to use __u16
static char *config_file = "../conf/rules.conf"; // Default config file path

const char *tcp_states[] = {
    [1] = "ESTABLISHED", [2] = "SYN_SENT",   [3] = "SYN_RECV",
    [4] = "FIN_WAIT1",   [5] = "FIN_WAIT2",  [6] = "TIME_WAIT",
    [7] = "CLOSE",       [8] = "CLOSE_WAIT", [9] = "LAST_ACK",
    [10] = "LISTEN",     [11] = "CLOSING",   [12] = "NEW_SYN_RECV",
    [13] = "UNKNOWN",
};

const char *argp_program_version = "nettool 1.0";
const char *argp_program_bug_address = "https://github.com/example/nettool";
const char argp_program_doc[] =
    "Unified tool for tracing TCP state changes, RTT statistics, connection latency, UDP bandwidth, UDP congestion, socket redirection, and XDP forwarding.\n"
    "\n"
    "USAGE: nettool [--mode=MODE] [OPTIONS]\n"
    "\n"
    "MODES:\n"
    "    tcpstates               Trace TCP state changes\n"
    "    tcprtt                  Trace TCP RTT statistics\n"
    "    tcpconnlat              Trace TCP connection latency\n"
    "    udpbandwidth            Trace UDP bandwidth usage\n"
    "    udpcongest              Trace UDP congestion events\n"
    "    sockredirect            Redirect traffic between sockets\n"
    "    xdpforward              Manage and forward traffic using XDP rules\n"
    "\n"
    "OPTIONS:\n"
    "    -v, --verbose           Verbose debug output\n"
    "    -T, --timestamp         Include timestamp on output (tcpstates mode)\n"
    "    -4, --ipv4              Trace IPv4 family only (tcpstates mode)\n"
    "    -6, --ipv6              Trace IPv6 family only (tcpstates mode)\n"
    "    -L, --localport=LPORT   Trace specific local ports (tcpstates mode)\n"
    "    -D, --remoteport=DPORT  Trace specific remote ports (tcpstates mode)\n"
    "    --ms                    Show RTT in milliseconds (tcprtt mode)\n"
    "    --ext                   Show extended statistics (tcprtt mode)\n"
    "    --min=MINUS             Minimum latency in microseconds (tcpconnlat mode)\n"
    "    --pid=PID               Trace specific PID (tcpconnlat mode)\n"
    "    --udpport=PORT          Trace specific UDP port (udpbandwidth and udpcongest modes)\n"
    "    -c, --conf=FILE         Path to configuration file for xdpforward mode (default: ./conf/rules.conf)\n";

static const struct argp_option opts[] = {
    {"mode", 'm', "MODE", 0, "Set the tool mode (tcpstates, tcprtt, tcpconnlat, udpbandwidth, udpcongest, sockredirect, or xdpforward)"},
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {"timestamp", 'T', NULL, 0, "Include timestamp on output (tcpstates mode)"},
    {"ipv4", '4', NULL, 0, "Trace IPv4 family only (tcpstates mode)"},
    {"ipv6", '6', NULL, 0, "Trace IPv6 family only (tcpstates mode)"},
    {"localport", 'L', "LPORT", 0, "Trace specific local ports (tcpstates mode)"},
    {"remoteport", 'D', "DPORT", 0, "Trace specific remote ports (tcpstates mode)"},
    {"ms", 1, NULL, 0, "Show RTT in milliseconds (tcprtt mode)"},
    {"ext", 2, NULL, 0, "Show extended statistics (tcprtt mode)"},
    {"min", 3, "MINUS", 0, "Minimum latency in microseconds (tcpconnlat mode)"},
    {"pid", 'p', "PID", 0, "Trace specific PID (tcpconnlat mode)"}, // Updated with short option -p
    {"udpport", 'u', "PORT", 0, "Trace specific UDP port (udpbandwidth and udpcongest modes)"}, // Updated with short option -u
    {"conf", 'c', "FILE", OPTION_ARG_OPTIONAL, "Path to configuration file for xdpforward mode (default: ./conf/rules.conf)"},
    {NULL, 0, NULL, 0, NULL}, // Removed --sockmap
};

// Move these function declarations above their usage
static int parse_ip(const char *str, __u8 *ip);
static int parse_protocol(const char *str);

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
    switch (key) {
        case 'm':
            if (strcmp(arg, "tcpstates") == 0)
                mode = MODE_TCPSTATES;
            else if (strcmp(arg, "tcprtt") == 0)
                mode = MODE_TCPRTT;
            else if (strcmp(arg, "tcpconnlat") == 0)
                mode = MODE_TCPCONNLAT;
            else if (strcmp(arg, "udpbandwidth") == 0)
                mode = MODE_UDPBANDWIDTH;
            else if (strcmp(arg, "udpcongest") == 0)
                mode = MODE_UDPCONGEST;
            else if (strcmp(arg, "sockredirect") == 0)
                mode = MODE_SOCKREDIRECT;
            else if (strcmp(arg, "xdpforward") == 0)
                mode = MODE_XDPFORWARD;
            else {
                warn("Invalid mode: %s\n", arg);
                argp_usage(state);
            }
            break;
        case 'v':
            verbose = true;
            break;
        case 'T':
            emit_timestamp = true;
            break;
        case '4':
            target_family = AF_INET;
            break;
        case '6':
            target_family = AF_INET6;
            break;
        case 'L':
            target_sports = strdup(arg);
            break;
        case 'D':
            target_dports = strdup(arg);
            break;
        case 1:
            targ_ms = true;
            break;
        case 2:
            targ_show_ext = true;
            break;
        case 3:
            targ_min_us = strtoull(arg, NULL, 10);
            break;
        case 'p': // Short option for --pid
            targ_pid = strtol(arg, NULL, 10);
            break;
        case 'u': // Short option for --udpport
            target_udp_port = strtoul(arg, NULL, 10);
            break;
        case 'c': // Handle -c or --conf
            if (arg) {
                config_file = strdup(arg);
            } else {
                config_file = "./conf/rules.conf"; // Assign default path if no argument is provided
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level == LIBBPF_DEBUG && !verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

static void handle_tcpstates_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct event *e = data;
    char ts[32], saddr[26], daddr[26];
    struct tm *tm;
    time_t t;

    if (emit_timestamp) {
        time(&t);
        tm = localtime(&t);
        strftime(ts, sizeof(ts), "%H:%M:%S", tm);
        printf("%8s ", ts);
    }

    inet_ntop(e->family, &e->saddr, saddr, sizeof(saddr));
    inet_ntop(e->family, &e->daddr, daddr, sizeof(daddr));
    printf("%-16llx %-7d %-10.10s %-15s %-5d %-15s %-5d %-11s -> %-11s %.3f\n",
           e->skaddr, e->pid, e->task, saddr, e->sport, daddr, e->dport,
           tcp_states[e->oldstate], tcp_states[e->newstate],
           (double)e->delta_us / 1000);
}

static void handle_tcpconnlat_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct connlat_event *e = data; // Use renamed struct
    char saddr[INET6_ADDRSTRLEN], daddr[INET6_ADDRSTRLEN];

    if (e->af == AF_INET) {
        inet_ntop(AF_INET, &e->saddr_v4, saddr, sizeof(saddr));
        inet_ntop(AF_INET, &e->daddr_v4, daddr, sizeof(daddr));
    } else {
        inet_ntop(AF_INET6, &e->saddr_v6, saddr, sizeof(saddr));
        inet_ntop(AF_INET6, &e->daddr_v6, daddr, sizeof(daddr));
    }

    printf("%-7d %-16s %-26s %-5d %-26s %-5d %-11llu\n",
           e->tgid, e->comm, saddr, ntohs(e->lport), daddr, ntohs(e->dport), e->delta_us);
}

static struct tcprtt_bpf *tcprtt_obj = NULL; // Global variable for tcprtt_bpf object

static void handle_tcprtt_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct rtt_event *e = data;
    printf("PID: %u, SRTT: %u %s\n", e->pid, e->srtt, targ_ms ? "ms" : "us");

    if (targ_show_ext) {
        struct rtt_stats stat;
        if (bpf_map_lookup_elem(bpf_map__fd(tcprtt_obj->maps.stats), &e->pid, &stat) == 0) {
            double avg_rtt = stat.count ? (double)stat.total_rtt / stat.count : 0;
            printf("  [Extended] Count: %llu, Avg RTT: %.2f %s\n",
                   stat.count, avg_rtt, targ_ms ? "ms" : "us");
        }
    }
}

static void handle_udpbwth_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct udp_bw_event *e = data;
    printf("Bytes: %llu, Duration: %.2f ms, Timestamp: %llu ns\n",
           e->bytes, (double)e->duration_ns / 1e6, e->ts_ns);
}

static void handle_udpcongest_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct udp_congest_event *e = data;
    printf("Duration: %.2f ms, Drops: %u, Queue Length: %u, Timestamp: %llu ns\n",
           (double)e->duration_ns / 1e6, e->drops, e->queue_len, e->ts_ns);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
    warn("Lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

static void print_xdpforward_rule(const struct rule_key *key, const struct rule_value *value) {
    char saddr[INET6_ADDRSTRLEN], daddr[INET6_ADDRSTRLEN];
    char sport[8], dport[8];

    inet_ntop(AF_INET6, key->saddr_v6, saddr, sizeof(saddr));
    inet_ntop(AF_INET6, key->daddr_v6, daddr, sizeof(daddr));

    // Format source and destination ports
    if (key->sport == 0)
        snprintf(sport, sizeof(sport), "*");
    else
        snprintf(sport, sizeof(sport), "%u", ntohs(key->sport));

    if (key->dport == 0)
        snprintf(dport, sizeof(dport), "*");
    else
        snprintf(dport, sizeof(dport), "%u", ntohs(key->dport));

    printf("Rule: saddr=%s, daddr=%s, sport=%s, dport=%s, protocol=%s, priority=%u, action=%s\n",
           (memcmp(key->saddr_v6, (const __u8[16]){0}, 16) == 0) ? "*" : saddr,
           (memcmp(key->daddr_v6, (const __u8[16]){0}, 16) == 0) ? "*" : daddr,
           sport,
           dport,
           (key->protocol == 0) ? "*" :
           (key->protocol == IPPROTO_TCP ? "tcp" : "udp"),
           key->priority,
           (value->action == 0) ? "drop" : "forward");
}

static int parse_ip(const char *str, __u8 *ip) {
    if (strcmp(str, "*") == 0) {
        memset(ip, 0, 16); // Wildcard for IPv6
        return 1;
    }

    struct in_addr ipv4;
    struct in6_addr ipv6;

    if (inet_pton(AF_INET, str, &ipv4) == 1) {
        memset(ip, 0, 10); // Map IPv4 to IPv6-mapped address
        ip[10] = 0xff;
        ip[11] = 0xff;
        memcpy(&ip[12], &ipv4, 4);
        return 1;
    } else if (inet_pton(AF_INET6, str, &ipv6) == 1) {
        memcpy(ip, &ipv6, 16);
        return 1;
    }

    return 0; // Invalid IP
}

static int parse_protocol(const char *str) {
    if (strcmp(str, "*") == 0)
        return 0; // Wildcard for protocol
    if (strcasecmp(str, "tcp") == 0)
        return IPPROTO_TCP;
    if (strcasecmp(str, "udp") == 0)
        return IPPROTO_UDP;
    return -1; // Invalid protocol
}

static int create_rules_map() {
    int map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, "rules_map",
                                sizeof(struct rule_key), sizeof(struct rule_value), 1024, NULL);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to create rules_map: %s\n", strerror(errno));
        return -1;
    }
    return map_fd;
}

static int load_rules_into_map(int map_fd, const char *path) {
    FILE *file = fopen(path, "r");
    if (!file) {
        fprintf(stderr, "Failed to open config file: %s\n", path);
        return -1;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        // Skip empty lines and comments
        char *trimmed = line;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++; // Trim leading spaces
        if (*trimmed == '#' || *trimmed == '\n' || *trimmed == '\0') continue;

        char saddr[INET6_ADDRSTRLEN], daddr[INET6_ADDRSTRLEN], protocol[8];
        char sport[8], dport[8];
        int action;
        struct rule_key key = {};
        struct rule_value value = {};

        // Parse the line
        if (sscanf(trimmed, "%45s %45s %7s %7s %7s %u %d", saddr, daddr, sport, dport, protocol, &key.priority, &action) != 7) {
            fprintf(stderr, "Invalid rule format: %s", line);
            continue;
        }

        memset(&key, 0, sizeof(key));
        memset(&value, 0, sizeof(value));

        if (!parse_ip(saddr, key.saddr_v6)) {
            fprintf(stderr, "Invalid source IP address format: %s\n", saddr);
            continue;
        }
        if (!parse_ip(daddr, key.daddr_v6)) {
            fprintf(stderr, "Invalid destination IP address format: %s\n", daddr);
            continue;
        }

        key.sport = (strcmp(sport, "*") == 0) ? 0 : htons(atoi(sport));
        key.dport = (strcmp(dport, "*") == 0) ? 0 : htons(atoi(dport));
        key.protocol = parse_protocol(protocol);
        if (key.protocol == -1) {
            fprintf(stderr, "Invalid protocol: %s\n", protocol);
            continue;
        }

        value.action = action;
        if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
            printf("Rule already exists, skipping: saddr=%s, daddr=%s, sport=%s, dport=%s, protocol=%s\n",
                   saddr, daddr, sport, dport, protocol);
            continue;
        }
        if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
            fprintf(stderr, "Failed to add rule to map: saddr=%s, daddr=%s, sport=%s, dport=%s, protocol=%s, action=%d\n",
                    saddr, daddr, sport, dport, protocol, action);
            continue;
        }
        printf("Loaded rule: saddr=%s, daddr=%s, sport=%s, dport=%s, protocol=%s, action=%d\n",
               saddr, daddr, sport, dport, protocol, action);
    }

    fclose(file);
    return 0;
}

static void manage_xdpforward_rules(int map_fd) {
    char command[16];
    printf("Enter commands to manage rules (add/del/show/find/exit):\n");
    while (1) {
        printf("> ");
        if (scanf("%15s", command) != 1) {
            fprintf(stderr, "Failed to read command. Please try again.\n");
            continue;
        }

        if (strcmp(command, "add") == 0) {
            char saddr[INET6_ADDRSTRLEN], daddr[INET6_ADDRSTRLEN], protocol[8];
            char sport[8], dport[8];
            int action;
            struct rule_key key = {};
            struct rule_value value = {};

            printf("Enter saddr, daddr, sport, dport, protocol, priority, action (0: drop, 1: forward):\n> ");
            if (scanf("%45s %45s %7s %7s %7s %u %d", saddr, daddr, sport, dport, protocol, &key.priority, &action) != 7) {
                fprintf(stderr, "Invalid input. Please provide all required fields.\n");
                continue;
            }

            if (!parse_ip(saddr, key.saddr_v6)) {
                fprintf(stderr, "Invalid source IP address format: %s\n", saddr);
                continue;
            }
            if (!parse_ip(daddr, key.daddr_v6)) {
                fprintf(stderr, "Invalid destination IP address format: %s\n", daddr);
                continue;
            }

            key.sport = (strcmp(sport, "*") == 0) ? 0 : htons(atoi(sport));
            key.dport = (strcmp(dport, "*") == 0) ? 0 : htons(atoi(dport));
            key.protocol = parse_protocol(protocol);
            if (key.protocol == -1) {
                fprintf(stderr, "Invalid protocol. Use 'tcp', 'udp', or '*'.\n");
                continue;
            }

            value.action = action;

            if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
                fprintf(stderr, "Failed to add rule to map.\n");
                continue;
            }
            printf("Rule added successfully.\n");
        } else if (strcmp(command, "del") == 0) {
            char saddr[INET6_ADDRSTRLEN], daddr[INET6_ADDRSTRLEN], protocol[8];
            char sport[8], dport[8];
            struct rule_key key = {};

            printf("Enter saddr, daddr, sport, dport, protocol to delete:\n> ");
            if (scanf("%45s %45s %7s %7s %7s", saddr, daddr, sport, dport, protocol) != 5) {
                fprintf(stderr, "Invalid input. Please provide all required fields.\n");
                continue;
            }

            if (!parse_ip(saddr, key.saddr_v6)) {
                fprintf(stderr, "Invalid source IP address format: %s\n", saddr);
                continue;
            }
            if (!parse_ip(daddr, key.daddr_v6)) {
                fprintf(stderr, "Invalid destination IP address format: %s\n", daddr);
                continue;
            }

            key.sport = (strcmp(sport, "*") == 0) ? 0 : htons(atoi(sport));
            key.dport = (strcmp(dport, "*") == 0) ? 0 : htons(atoi(dport));
            key.protocol = parse_protocol(protocol);
            if (key.protocol == -1) {
                fprintf(stderr, "Invalid protocol. Use 'tcp', 'udp', or '*'.\n");
                continue;
            }

            if (bpf_map_delete_elem(map_fd, &key) != 0) {
                fprintf(stderr, "Failed to delete rule from map.\n");
                continue;
            }
            printf("Rule deleted successfully.\n");
    
        } else if (strcmp(command, "show") == 0) {
            printf("Current rules:\n");
            struct rule_key key = {};
            struct rule_key next_key;
            struct rule_value value;
            bool first_key = true;

            while (1) {
                int ret = bpf_map_get_next_key(map_fd, first_key ? NULL : &key, &next_key);
                if (ret < 0) {
                    if (errno == ENOENT) {
                        break;
                    }
                    warn("Failed to get next key: %s\n", strerror(errno));
                    break;
                }

                if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
                    print_xdpforward_rule(&next_key, &value);
                }

                memcpy(&key, &next_key, sizeof(key));
                first_key = false;
            }
        } else if (strcmp(command, "find") == 0) {
            char saddr_pattern[INET6_ADDRSTRLEN], daddr_pattern[INET6_ADDRSTRLEN];
            char sport_pattern[8], dport_pattern[8], protocol_pattern[8];
            printf("Enter patterns for saddr, daddr, sport, dport, protocol (use * for wildcard)\n> ");
            if (scanf("%45s %45s %7s %7s %7s", saddr_pattern, daddr_pattern, sport_pattern, dport_pattern, protocol_pattern) != 5) {
                fprintf(stderr, "Invalid input. Please provide all required patterns.\n");
                continue;
            }

            printf("Matching rules:\n");
            struct rule_key key = {};
            struct rule_key next_key;
            struct rule_value value;
            bool first_key = true;

            while (1) {
                int ret = bpf_map_get_next_key(map_fd, first_key ? NULL : &key, &next_key);
                if (ret < 0) {
                    if (errno == ENOENT) {
                        break;
                    }
                    warn("Failed to get next key: %s\n", strerror(errno));
                    break;
                }

                if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
                    char saddr[INET6_ADDRSTRLEN], daddr[INET6_ADDRSTRLEN];
                    char sport[8], dport[8], protocol[8];

                    inet_ntop(AF_INET6, next_key.saddr_v6, saddr, sizeof(saddr));
                    inet_ntop(AF_INET6, next_key.daddr_v6, daddr, sizeof(daddr));
                    snprintf(sport, sizeof(sport), next_key.sport == 0 ? "*" : "%u", ntohs(next_key.sport));
                    snprintf(dport, sizeof(dport), next_key.dport == 0 ? "*" : "%u", ntohs(next_key.dport));
                    snprintf(protocol, sizeof(protocol), next_key.protocol == 0 ? "*" : (next_key.protocol == IPPROTO_TCP ? "tcp" : "udp"));

                    if (fnmatch(saddr_pattern, saddr, 0) == 0 &&
                        fnmatch(daddr_pattern, daddr, 0) == 0 &&
                        fnmatch(sport_pattern, sport, 0) == 0 &&
                        fnmatch(dport_pattern, dport, 0) == 0 &&
                        fnmatch(protocol_pattern, protocol, 0) == 0) {
                        print_xdpforward_rule(&next_key, &value);
                    }
                }

                memcpy(&key, &next_key, sizeof(key));
                first_key = false;
            }
        } else if (strcmp(command, "exit") == 0) {
            break;
        } else {
            fprintf(stderr, "Unknown command. Please try again.\n");
        }
    }
}

int main(int argc, char **argv) {
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
        .doc = argp_program_doc,
    };
    struct perf_buffer *pb = NULL;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    if (mode == MODE_TCPSTATES) {
        struct tcpstates_bpf *obj = tcpstates_bpf__open_opts(&open_opts);
        if (!obj) {
            warn("Failed to open tcpstates BPF object\n");
            return 1;
        }

        obj->rodata->filter_by_sport = target_sports != NULL;
        obj->rodata->filter_by_dport = target_dports != NULL;
        obj->rodata->target_family = target_family;

        err = tcpstates_bpf__load(obj);
        if (err) {
            warn("Failed to load tcpstates BPF object: %d\n", err);
            goto cleanup_tcpstates;
        }

        err = tcpstates_bpf__attach(obj);
        if (err) {
            warn("Failed to attach tcpstates BPF programs: %d\n", err);
            goto cleanup_tcpstates;
        }

        pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
                              handle_tcpstates_event, handle_lost_events, NULL, NULL);
        if (!pb) {
            err = -errno;
            warn("Failed to open perf buffer: %d\n", err);
            goto cleanup_tcpstates;
        }

        printf("Tracing TCP state changes... Press Ctrl+C to exit.\n");
        while (!exiting) {
            err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
            if (err < 0 && err != -EINTR) {
                warn("Error polling perf buffer: %s\n", strerror(-err));
                goto cleanup_tcpstates;
            }
            err = 0;
        }

    cleanup_tcpstates:
        perf_buffer__free(pb);
        tcpstates_bpf__destroy(obj);

    } else if (mode == MODE_TCPRTT) {
        tcprtt_obj = tcprtt_bpf__open(); // Assign to global variable
        if (!tcprtt_obj) {
            warn("Failed to open tcprtt BPF object\n");
            return 1;
        }

        tcprtt_obj->rodata->targ_ms = targ_ms;
        tcprtt_obj->rodata->targ_ext = targ_show_ext;

        if (tcprtt_bpf__load(tcprtt_obj)) {
            warn("Failed to load tcprtt BPF object\n");
            tcprtt_bpf__destroy(tcprtt_obj);
            return 1;
        }

        if (tcprtt_bpf__attach(tcprtt_obj)) {
            warn("Failed to attach tcprtt BPF programs\n");
            tcprtt_bpf__destroy(tcprtt_obj);
            return 1;
        }

        struct perf_buffer *pb = perf_buffer__new(bpf_map__fd(tcprtt_obj->maps.events), PERF_BUFFER_PAGES,
                                                  handle_tcprtt_event, handle_lost_events, NULL, NULL);
        if (!pb) {
            warn("Failed to open perf buffer\n");
            tcprtt_bpf__destroy(tcprtt_obj);
            return 1;
        }

        printf("Tracing TCP RTT... Press Ctrl+C to exit.\n");
        while (!exiting) {
            int err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
            if (err < 0 && err != -EINTR) {
                warn("Error polling perf buffer: %s\n", strerror(-err));
                break;
            }
            sleep(1); // Add a delay to control output speed
        }

        perf_buffer__free(pb);
        tcprtt_bpf__destroy(tcprtt_obj);
        tcprtt_obj = NULL; // Reset global variable
    } else if (mode == MODE_TCPCONNLAT) {
        struct tcpconnlat_bpf *obj = tcpconnlat_bpf__open_opts(&open_opts);
        if (!obj) {
            warn("Failed to open tcpconnlat BPF object\n");
            return 1;
        }

        obj->rodata->targ_min_us = targ_min_us;
        obj->rodata->targ_tgid = targ_pid;

        err = tcpconnlat_bpf__load(obj);
        if (err) {
            warn("Failed to load tcpconnlat BPF object: %d\n", err);
            goto cleanup_tcpconnlat;
        }

        err = tcpconnlat_bpf__attach(obj);
        if (err) {
            warn("Failed to attach tcpconnlat BPF programs: %d\n", err);
            goto cleanup_tcpconnlat;
        }

        pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
                              handle_tcpconnlat_event, handle_lost_events, NULL, NULL);
        if (!pb) {
            err = -errno;
            warn("Failed to open perf buffer: %d\n", err);
            goto cleanup_tcpconnlat;
        }

        printf("Tracing TCP connection latency... Press Ctrl+C to exit.\n");
        while (!exiting) {
            err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
            if (err < 0 && err != -EINTR) {
                warn("Error polling perf buffer: %s\n", strerror(-err));
                goto cleanup_tcpconnlat;
            }
            err = 0;
        }

    cleanup_tcpconnlat:
        perf_buffer__free(pb);
        tcpconnlat_bpf__destroy(obj);
    } else if (mode == MODE_UDPBANDWIDTH) {
        struct udpbwth_bpf *obj = udpbwth_bpf__open();
        if (!obj) {
            warn("Failed to open udpbwth BPF object\n");
            return 1;
        }

        if (udpbwth_bpf__load(obj)) {
            warn("Failed to load udpbwth BPF object\n");
            udpbwth_bpf__destroy(obj);
            return 1;
        }

        if (target_udp_port > 0) {
            __u32 key = 0; // Updated to use __u32
            if (bpf_map_update_elem(bpf_map__fd(obj->maps.target_port), &key, &target_udp_port, BPF_ANY)) {
                warn("Failed to set target UDP port\n");
                udpbwth_bpf__destroy(obj);
                return 1;
            }
        }

        if (udpbwth_bpf__attach(obj)) {
            warn("Failed to attach udpbwth BPF programs\n");
            udpbwth_bpf__destroy(obj);
            return 1;
        }

        struct perf_buffer *pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
                                                  handle_udpbwth_event, handle_lost_events, NULL, NULL);
        if (!pb) {
            warn("Failed to open perf buffer\n");
            udpbwth_bpf__destroy(obj);
            return 1;
        }

        printf("Tracing UDP bandwidth... Press Ctrl+C to exit.\n");
        while (!exiting) {
            int err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
            if (err < 0 && err != -EINTR) {
                warn("Error polling perf buffer: %s\n", strerror(-err));
                break;
            }
        }

        perf_buffer__free(pb);
        udpbwth_bpf__destroy(obj);
    } else if (mode == MODE_UDPCONGEST) {
        struct udpcongest_bpf *obj = udpcongest_bpf__open();
        if (!obj) {
            warn("Failed to open udpcongest BPF object\n");
            return 1;
        }

        if (udpcongest_bpf__load(obj)) {
            warn("Failed to load udpcongest BPF object\n");
            udpcongest_bpf__destroy(obj);
            return 1;
        }

        if (target_udp_port > 0) {
            __u32 key = 0;
            if (bpf_map_update_elem(bpf_map__fd(obj->maps.target_port), &key, &target_udp_port, BPF_ANY)) {
                warn("Failed to set target UDP port\n");
                udpcongest_bpf__destroy(obj);
                return 1;
            }
        }

        if (udpcongest_bpf__attach(obj)) {
            warn("Failed to attach udpcongest BPF programs\n");
            udpcongest_bpf__destroy(obj);
            return 1;
        }

        struct perf_buffer *pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
                                                  handle_udpcongest_event, handle_lost_events, NULL, NULL);
        if (!pb) {
            warn("Failed to open perf buffer\n");
            udpcongest_bpf__destroy(obj);
            return 1;
        }

        printf("Tracing UDP congestion... Press Ctrl+C to exit.\n");
        while (!exiting) {
            int err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
            if (err < 0 && err != -EINTR) {
                warn("Error polling perf buffer: %s\n", strerror(-err));
                break;
            }
        }

        perf_buffer__free(pb);
        udpcongest_bpf__destroy(obj);
    } else if (mode == MODE_SOCKREDIRECT) {
        struct sockredirect_bpf *obj = sockredirect_bpf__open();
        if (!obj) {
            warn("Failed to open sockredirect BPF object\n");
            return 1;
        }

        if (sockredirect_bpf__load(obj)) {
            warn("Failed to load sockredirect BPF object\n");
            sockredirect_bpf__destroy(obj);
            return 1;
        }

        if (sockredirect_bpf__attach(obj)) {
            warn("Failed to attach sockredirect BPF programs\n");
            sockredirect_bpf__destroy(obj);
            return 1;
        }

        printf("Redirecting traffic between sockets (IPv4/IPv6)... Press Ctrl+C to exit.\n");
        while (!exiting) {
            sleep(1); // Add a delay to control output speed
        }

        sockredirect_bpf__destroy(obj);
    } else if (mode == MODE_XDPFORWARD) {
        int map_fd = create_rules_map();
        if (map_fd < 0) {
            return 1;
        }

        if (load_rules_into_map(map_fd, config_file) != 0) {
            close(map_fd);
            return 1;
        }

        struct xdpforward_bpf *obj = xdpforward_bpf__open();
        if (!obj) {
            warn("Failed to open xdpforward BPF object\n");
            close(map_fd);
            return 1;
        }

        if (bpf_map__reuse_fd(obj->maps.rules_map, map_fd)) {
            warn("Failed to reuse map FD for rules_map\n");
            xdpforward_bpf__destroy(obj);
            close(map_fd);
            return 1;
        }

        if (xdpforward_bpf__load(obj)) {
            warn("Failed to load xdpforward BPF object\n");
            xdpforward_bpf__destroy(obj);
            close(map_fd);
            return 1;
        }

        if (xdpforward_bpf__attach(obj)) {
            warn("Failed to attach xdpforward BPF programs\n");
            xdpforward_bpf__destroy(obj);
            close(map_fd);
            return 1;
        }

        printf("XDP program attached. Rules loaded from %s.\n", config_file);
        manage_xdpforward_rules(map_fd);

        xdpforward_bpf__destroy(obj);
        close(map_fd);
    }

    return err != 0;
}
