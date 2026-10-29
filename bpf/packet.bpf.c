// SPDX-License-Identifier: GPL-2.0
// Counts packets and bytes per flow. Dropped labels are zeroed before the
// map update so flows that differ only in a dropped field share one entry.
//
// Label bits must match internal/config/config.go.
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0

#define LABEL_INTERFACE (1u << 0)
#define LABEL_SRC_IP (1u << 1)
#define LABEL_DST_IP (1u << 2)
#define LABEL_SRC_PORT (1u << 3)
#define LABEL_DST_PORT (1u << 4)
#define LABEL_TYPE (1u << 5)
#define LABEL_DIRECTION (1u << 6)

#define TYPE_SYN 1
#define TYPE_SYNACK 2
#define TYPE_RST 3
#define TYPE_FIN 4
#define TYPE_ACK 5
#define TYPE_UDP 6
#define TYPE_ICMP 7

#define DIR_INGRESS 0
#define DIR_EGRESS 1

#define FAM_IPV4 4
#define FAM_IPV6 6

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8

#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMPV6 58

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_ACK 0x10

#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff

#define DROP_OK 0
#define DROP_NOT_IP 1
#define DROP_TRUNCATED 2
#define DROP_FRAGMENT 3
#define DROP_EXT_HDR 4
#define DROP_VLAN 5
#define DROP_UPDATE_RACE 6
#define DROP_L4 7
#define DROP_REASON_COUNT 8

struct packet_key {
	__u32 ifindex;
	__u8 direction;
	__u8 type;
	__u8 family;
	__u8 pad;
	__u16 src_port;
	__u16 dst_port;
	__u8 src[16];
	__u8 dst[16];
};

struct packet_value {
	__u64 packets;
	__u64 bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} label_mask SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct packet_key);
	__type(value, struct packet_value);
} packet_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, DROP_REASON_COUNT);
	__type(key, __u32);
	__type(value, __u64);
} drop_reasons SEC(".maps");

static __always_inline void bump_drop(__u32 reason)
{
	__u64 *val;

	if (reason >= DROP_REASON_COUNT)
		return;
	val = bpf_map_lookup_elem(&drop_reasons, &reason);
	if (val)
		__sync_fetch_and_add(val, 1);
}

static __always_inline int load_be16(struct __sk_buff *skb, __u32 off, __u16 *out)
{
	__u8 b[2];

	if (bpf_skb_load_bytes(skb, off, b, sizeof(b)) < 0)
		return -1;
	*out = (__u16)((b[0] << 8) | b[1]);
	return 0;
}

static __always_inline int is_l3(__u16 proto)
{
	return proto == ETH_P_IP || proto == ETH_P_IPV6;
}

static __always_inline int is_vlan(__u16 proto)
{
	return proto == ETH_P_8021Q || proto == ETH_P_8021AD;
}

// Ethernet if the ethertype at offset 12 is VLAN or IP. After peeling at most
// two VLAN tags the inner ethertype must be IPv4/IPv6. Otherwise treat as raw
// L3 when the kernel protocol is IP.
static __always_inline int locate_l3(struct __sk_buff *skb, __u32 *l3_off)
{
	__u16 kernel_proto = bpf_ntohs((__be16)skb->protocol);
	__u16 eth_proto = 0;

	if (load_be16(skb, 12, &eth_proto) < 0)
		return DROP_TRUNCATED;

	if (is_vlan(eth_proto) || is_l3(eth_proto)) {
		__u32 off = 14;

		if (is_vlan(eth_proto)) {
			if (load_be16(skb, off + 2, &eth_proto) < 0)
				return DROP_TRUNCATED;
			off += 4;
			if (is_vlan(eth_proto)) {
				if (load_be16(skb, off + 2, &eth_proto) < 0)
					return DROP_TRUNCATED;
				off += 4;
			}
		}
		if (!is_l3(eth_proto))
			return DROP_VLAN;
		*l3_off = off;
		return DROP_OK;
	}

	if (is_l3(kernel_proto)) {
		*l3_off = 0;
		return DROP_OK;
	}
	return DROP_NOT_IP;
}

static __always_inline __u8 tcp_type(__u8 flags)
{
	if (flags & TCP_RST)
		return TYPE_RST;
	if ((flags & TCP_SYN) && (flags & TCP_ACK))
		return TYPE_SYNACK;
	if (flags & TCP_SYN)
		return TYPE_SYN;
	if (flags & TCP_FIN)
		return TYPE_FIN;
	return TYPE_ACK;
}

static __always_inline int parse_l4(struct __sk_buff *skb, __u32 off, __u8 proto, struct packet_key *key)
{
	if (proto == IPPROTO_TCP) {
		__u8 tcp[14];

		if (bpf_skb_load_bytes(skb, off, tcp, sizeof(tcp)) < 0)
			return DROP_TRUNCATED;
		key->src_port = (__u16)((tcp[0] << 8) | tcp[1]);
		key->dst_port = (__u16)((tcp[2] << 8) | tcp[3]);
		key->type = tcp_type(tcp[13]);
		return DROP_OK;
	}
	if (proto == IPPROTO_UDP) {
		__u8 udp[4];

		if (bpf_skb_load_bytes(skb, off, udp, sizeof(udp)) < 0)
			return DROP_TRUNCATED;
		key->src_port = (__u16)((udp[0] << 8) | udp[1]);
		key->dst_port = (__u16)((udp[2] << 8) | udp[3]);
		key->type = TYPE_UDP;
		return DROP_OK;
	}
	if (proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6) {
		key->type = TYPE_ICMP;
		return DROP_OK;
	}
	return DROP_L4;
}

static __always_inline int handle_ip(struct __sk_buff *skb, __u32 l3, struct packet_key *key)
{
	__u8 version;

	if (bpf_skb_load_bytes(skb, l3, &version, 1) < 0)
		return DROP_TRUNCATED;
	version >>= 4;

	if (l3 > 128)
		return DROP_TRUNCATED;

	if (version == 4) {
		__u8 ip[20];
		__u32 ihl;
		__u16 frag;
		__u32 l4;

		if (bpf_skb_load_bytes(skb, l3, ip, sizeof(ip)) < 0)
			return DROP_TRUNCATED;
		ihl = (__u32)(ip[0] & 0x0f) * 4;
		if (ihl < 20 || ihl > 60)
			return DROP_TRUNCATED;
		l4 = l3 + ihl;
		if (l4 < l3)
			return DROP_TRUNCATED;
		frag = ((__u16)ip[6] << 8) | ip[7];
		if ((frag & (IP_MF | IP_OFFMASK)) != 0)
			return DROP_FRAGMENT;
		key->family = FAM_IPV4;
		__builtin_memcpy(key->src, ip + 12, 4);
		__builtin_memcpy(key->dst, ip + 16, 4);
		return parse_l4(skb, l4, ip[9], key);
	}

	if (version == 6) {
		__u8 ip[40];

		if (bpf_skb_load_bytes(skb, l3, ip, sizeof(ip)) < 0)
			return DROP_TRUNCATED;
		if (ip[6] != IPPROTO_TCP && ip[6] != IPPROTO_UDP && ip[6] != IPPROTO_ICMPV6)
			return DROP_EXT_HDR;
		key->family = FAM_IPV6;
		__builtin_memcpy(key->src, ip + 8, 16);
		__builtin_memcpy(key->dst, ip + 24, 16);
		return parse_l4(skb, l3 + 40, ip[6], key);
	}
	return DROP_NOT_IP;
}

static __always_inline void apply_mask(struct packet_key *key)
{
	__u32 zero = 0;
	__u32 mask = 0;
	__u32 *mp;

	mp = bpf_map_lookup_elem(&label_mask, &zero);
	if (mp)
		mask = *mp;

	if ((mask & LABEL_INTERFACE) == 0)
		key->ifindex = 0;
	if ((mask & LABEL_DIRECTION) == 0)
		key->direction = 0;
	if ((mask & LABEL_TYPE) == 0)
		key->type = 0;
	if ((mask & LABEL_SRC_PORT) == 0)
		key->src_port = 0;
	if ((mask & LABEL_DST_PORT) == 0)
		key->dst_port = 0;
	if ((mask & LABEL_SRC_IP) == 0)
		__builtin_memset(key->src, 0, sizeof(key->src));
	if ((mask & LABEL_DST_IP) == 0)
		__builtin_memset(key->dst, 0, sizeof(key->dst));
	if ((mask & (LABEL_SRC_IP | LABEL_DST_IP)) == 0)
		key->family = 0;
}

static __always_inline int add_stats(struct packet_key *key, __u64 bytes)
{
	struct packet_value *val;
	struct packet_value init = {};

	val = bpf_map_lookup_elem(&packet_stats, key);
	if (val) {
		__sync_fetch_and_add(&val->packets, 1);
		__sync_fetch_and_add(&val->bytes, bytes);
		return DROP_OK;
	}

	init.packets = 1;
	init.bytes = bytes;
	if (bpf_map_update_elem(&packet_stats, key, &init, BPF_NOEXIST) == 0)
		return DROP_OK;

	val = bpf_map_lookup_elem(&packet_stats, key);
	if (!val)
		return DROP_UPDATE_RACE;
	__sync_fetch_and_add(&val->packets, 1);
	__sync_fetch_and_add(&val->bytes, bytes);
	return DROP_OK;
}

static __always_inline int handle(struct __sk_buff *skb, __u8 direction)
{
	struct packet_key key = {};
	__u32 l3 = 0;
	int err;

	err = locate_l3(skb, &l3);
	if (err != DROP_OK) {
		bump_drop((__u32)err);
		return TC_ACT_OK;
	}
	key.ifindex = skb->ifindex;
	key.direction = direction;
	err = handle_ip(skb, l3, &key);
	if (err != DROP_OK) {
		bump_drop((__u32)err);
		return TC_ACT_OK;
	}
	apply_mask(&key);
	err = add_stats(&key, skb->len);
	if (err != DROP_OK)
		bump_drop((__u32)err);
	return TC_ACT_OK;
}

SEC("tc")
int packet_ingress(struct __sk_buff *skb)
{
	return handle(skb, DIR_INGRESS);
}

SEC("tc")
int packet_egress(struct __sk_buff *skb)
{
	return handle(skb, DIR_EGRESS);
}

char LICENSE[] SEC("license") = "GPL";
