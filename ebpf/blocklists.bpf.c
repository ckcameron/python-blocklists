// SPDX-License-Identifier: GPL-3.0-only
// Copyright 2026 CK Cameron
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef MAX_PREFIXES
#define MAX_PREFIXES 1024
#endif
struct key4 { __u32 prefixlen; __u8 address[4]; };
struct key6 { __u32 prefixlen; __u8 address[16]; };
struct event_key {
    __u32 family;
    __u32 ifindex;
    __u32 direction; // 0 ingress, 1 egress
    __u32 endpoint;  // 0 source, 1 destination
    __u8 address[16];
};
struct counters { __u64 packets; __u64 bytes; };
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_PREFIXES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct key4);
    __type(value, __u32);
} blocked4 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_PREFIXES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct key6);
    __type(value, __u32);
} blocked6 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct event_key);
    __type(value, struct counters);
} drops SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2); // 0 matched drops, 1 malformed IP drops
    __type(key, __u32);
    __type(value, struct counters);
} totals SEC(".maps");

static __always_inline int deny(struct __sk_buff *skb, struct event_key *key)
{
    __u32 index = key ? 0 : 1;
    struct counters *total = bpf_map_lookup_elem(&totals, &index);
    if (total) { total->packets++; total->bytes += skb->len; }
    if (key) {
        struct counters *counter = bpf_map_lookup_elem(&drops, key);
        if (!counter) {
            struct counters zero = {};
            bpf_map_update_elem(&drops, key, &zero, BPF_NOEXIST);
            counter = bpf_map_lookup_elem(&drops, key);
        }
        if (counter) { counter->packets++; counter->bytes += skb->len; }
    }
    return TC_ACT_SHOT;
}

static __always_inline int filter(struct __sk_buff *skb, __u32 direction)
{
    __u16 protocol = bpf_ntohs(skb->protocol);
    __u32 offset = 0;
    // Relative network-header reads work on Ethernet, loopback and L3 devices.
    // In-band VLAN headers precede the network header until VLAN decapsulation.
#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (protocol == ETH_P_8021Q || protocol == ETH_P_8021AD) {
            struct { __be16 tci; __be16 proto; } vlan;
            if (bpf_skb_load_bytes_relative(skb, offset, &vlan, sizeof(vlan), BPF_HDR_START_NET))
                return deny(skb, 0);
            protocol = bpf_ntohs(vlan.proto);
            offset += sizeof(vlan);
        }
    }
    if (protocol == ETH_P_8021Q || protocol == ETH_P_8021AD)
        return deny(skb, 0);
    struct event_key event = { .ifindex = skb->ifindex, .direction = direction };
    if (protocol == ETH_P_IP) {
        struct iphdr hdr;
        if (bpf_skb_load_bytes_relative(skb, offset, &hdr, sizeof(hdr), BPF_HDR_START_NET)
            || hdr.version != 4 || hdr.ihl < 5)
            return deny(skb, 0);
        struct key4 key = { .prefixlen = 32 };
        event.family = 4;
        __builtin_memcpy(key.address, &hdr.saddr, 4);
        if (bpf_map_lookup_elem(&blocked4, &key)) {
            __builtin_memcpy(event.address, key.address, 4);
            return deny(skb, &event);
        }
        __builtin_memcpy(key.address, &hdr.daddr, 4);
        if (bpf_map_lookup_elem(&blocked4, &key)) {
            event.endpoint = 1;
            __builtin_memcpy(event.address, key.address, 4);
            return deny(skb, &event);
        }
    } else if (protocol == ETH_P_IPV6) {
        struct ipv6hdr hdr;
        if (bpf_skb_load_bytes_relative(skb, offset, &hdr, sizeof(hdr), BPF_HDR_START_NET)
            || hdr.version != 6)
            return deny(skb, 0);
        struct key6 key = { .prefixlen = 128 };
        event.family = 6;
        __builtin_memcpy(key.address, &hdr.saddr, 16);
        if (bpf_map_lookup_elem(&blocked6, &key)) {
            __builtin_memcpy(event.address, key.address, 16);
            return deny(skb, &event);
        }
        __builtin_memcpy(key.address, &hdr.daddr, 16);
        if (bpf_map_lookup_elem(&blocked6, &key)) {
            event.endpoint = 1;
            __builtin_memcpy(event.address, key.address, 16);
            return deny(skb, &event);
        }
    }
    // Continue other TC filters; do not override their policies with TC_ACT_OK.
    return TC_ACT_UNSPEC;
}
SEC("tc/ingress") int bl_ingress(struct __sk_buff *skb) { return filter(skb, 0); }
SEC("tc/egress") int bl_egress(struct __sk_buff *skb) { return filter(skb, 1); }
char LICENSE[] SEC("license") = "GPL";
