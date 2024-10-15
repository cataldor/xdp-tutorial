/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

struct vlan_hdr {
	__be16 h_vlan_tci;
	__be16 h_vlan_encapsulated_proto;
};

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in network byte order.
 */
static __always_inline int proto_is_vlan(__be16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	const size_t hdrsize = sizeof(*eth);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;

	if (proto_is_vlan(eth->h_proto)) {
		struct vlan_hdr *vh;
		const size_t vsize = sizeof(*vh);

		/* need to check if we can access the area */
		if (nh->pos + vsize > data_end)
			return -1;

		vh = nh->pos;
		nh->pos += vsize;
		return vh->h_vlan_encapsulated_proto; /* network-byte-order */
	} else
		return eth->h_proto; /* network-byte-order */
}

/* Assignment 2: Implement and use this */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6 = nh->pos;
	const size_t hdrsize = sizeof(*ip6);

	/* OR ip6 + 1 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ip6hdr = ip6;

	return ip6->nexthdr; /* network-byte-order */
}

/* Assignment 3: Implement and use this */
static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *ic6 = nh->pos;

	if (ic6 + 1 > data_end)
		return -1;

	nh->pos += sizeof(*ic6);
	*icmp6hdr = ic6;

	return ic6->icmp6_sequence;
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
				       void *data_end,
				       struct iphdr **iphdr)
{
	struct iphdr *ip = nh->pos;
	size_t ipsize = sizeof(*ip);

	if (nh->pos + ipsize > data_end)
		return -1;

	/* real size */
	ipsize = ip->ihl * 4;
	if (nh->pos + ipsize > data_end)
		return -1;

	nh->pos += ipsize;
	*iphdr = ip;

	return ip->protocol;
}

static __always_inline int parse_icmphdr(struct hdr_cursor *nh,
					 void *data_end,
					 struct icmphdr **icmphdr)
{
	struct icmphdr *icmp = nh->pos;
	size_t icmpsize = sizeof(*icmp);

	if (nh->pos + icmpsize > data_end)
		return -1;

	nh->pos += icmpsize;
	*icmphdr = icmp;

	return icmp->un.echo.sequence;
}

SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
	struct ipv6hdr *ip6hdr;
	struct icmp6hdr *icmp6hdr;
	struct iphdr *iphdr;
	struct icmphdr *icmphdr;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	int ip_type;
	int icmp_seq;


	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type != bpf_htons(ETH_P_IPV6) && nh_type != bpf_htons(ETH_P_IP))
		goto out;

	if (nh_type == bpf_htons(ETH_P_IPV6)) {
		/* Assignment additions go below here */
		ip_type = parse_ip6hdr(&nh, data_end, &ip6hdr);
		/* 8bits... */
		if (ip_type != IPPROTO_ICMPV6)
			goto out;

		icmp_seq = parse_icmp6hdr(&nh, data_end, &icmp6hdr);
	} else {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type != IPPROTO_ICMP)
			goto out;

		icmp_seq = parse_icmphdr(&nh, data_end, &icmphdr);
	}

	if (bpf_ntohs(icmp_seq) % 2 != 0)
		goto out;

	action = XDP_DROP;
out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
