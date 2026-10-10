/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * The few kernel types spectraNET reads, declared for CO-RE: field offsets are not taken
 * from these definitions but relocated at load time against the running kernel's BTF, by
 * field name. Only names and types must match the kernel, not layout.
 */
#pragma once

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef int __s32;
typedef __u16 __be16;
typedef __u32 __be32;

#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

struct in6_addr {
	union {
		__u8 u6_addr8[16];
	} in6_u;
};

struct sock_common {
	union {
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
	unsigned short skc_family;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
};

struct sock {
	struct sock_common __sk_common;
};

struct socket {
	struct sock *sk;
};

struct msghdr {
	void *msg_name;
	int msg_namelen;
};

#pragma clang attribute pop

/* User-visible ABI, fixed layout. */
struct sockaddr_in_abi {
	unsigned short sin_family;
	__be16 sin_port;
	__be32 sin_addr;
};

struct sockaddr_in6_abi {
	unsigned short sin6_family;
	__be16 sin6_port;
	__be32 sin6_flowinfo;
	__u8 sin6_addr[16];
};
