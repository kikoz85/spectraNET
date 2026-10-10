/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * spectraNET kernel probe: exact bytes per socket, attributed to the process doing the I/O.
 *
 *   tcp_sendmsg (exit)       bytes sent on TCP, as accepted by the kernel
 *   tcp_cleanup_rbuf (entry) bytes read by the application from TCP (recvmsg, splice, ...)
 *   udp[v6]_sendmsg (exit)   bytes sent on UDP (including QUIC), with destination
 *   udp[v6]_recvmsg (exit)   bytes received on UDP, with source
 *   inet_release (entry)     the socket is closed: its final counters are emitted as an
 *                            event and its entry removed, so even connections shorter than
 *                            a sampling interval are reported with exact totals.
 *
 * Besides bytes, each socket counts its send and receive calls (for UDP, one per datagram),
 * which gives packet rates and average sizes.
 *
 * The program never reads or copies packet contents.
 */
#include "vmlinux_min.h"

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

enum {
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_RINGBUF = 27,
};
#define BPF_NOEXIST 1
#define AF_INET 2
#define AF_INET6 10
#define PROTO_TCP 6
#define PROTO_UDP 17

/* Helper IDs from include/uapi/linux/bpf.h (stable ABI). */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)16;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *src) = (void *)113;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;

#define READ(dst, src) bpf_probe_read_kernel(&(dst), sizeof(dst), __builtin_preserve_access_index(&(src)))

/* Mirrored by `SockInfo` in Rust: keep in sync (layout checked by tests). */
struct sock_info {
	__u64 born_ns;
	__u64 tx;
	__u64 rx;
	__u32 tgid;
	__u16 family;
	__u16 sport;   /* host byte order */
	__u16 dport;   /* host byte order */
	__u8 proto;
	__u8 pad[5];
	__u8 saddr[16];
	__u8 daddr[16];
	char comm[16];
	/* Send and receive calls (UDP: datagrams), for packet rates. */
	__u32 tx_msgs;
	__u32 rx_msgs;
};

struct close_event {
	__u64 sk;
	struct sock_info info;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct sock_info);
} socks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 21);
} closed SEC(".maps");

static __attribute__((always_inline)) __u16 swap16(__u16 v)
{
	return (__u16)((v >> 8) | (v << 8));
}

/* Local and remote address of a socket, as the kernel knows them. */
static __attribute__((always_inline)) void read_tuple(struct sock *sk, struct sock_info *info)
{
	unsigned short family = 0;
	__u16 num = 0;
	__be16 dport = 0;
	READ(family, sk->__sk_common.skc_family);
	READ(num, sk->__sk_common.skc_num);
	READ(dport, sk->__sk_common.skc_dport);
	info->family = family;
	info->sport = num;
	info->dport = swap16(dport);
	if (family == AF_INET) {
		__be32 s = 0, d = 0;
		READ(s, sk->__sk_common.skc_rcv_saddr);
		READ(d, sk->__sk_common.skc_daddr);
		__builtin_memcpy(info->saddr, &s, 4);
		__builtin_memcpy(info->daddr, &d, 4);
	} else if (family == AF_INET6) {
		READ(info->saddr, sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
		READ(info->daddr, sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
	}
}

/* For unconnected UDP the peer is in the message, not the socket. */
static __attribute__((always_inline)) void read_msg_peer(struct msghdr *msg, struct sock_info *info)
{
	void *name = 0;
	int namelen = 0;
	if (!msg)
		return;
	READ(name, msg->msg_name);
	READ(namelen, msg->msg_namelen);
	if (!name)
		return;
	if (info->family == AF_INET && namelen >= (int)sizeof(struct sockaddr_in_abi)) {
		struct sockaddr_in_abi sa = {};
		bpf_probe_read_kernel(&sa, sizeof(sa), name);
		if (sa.sin_family == AF_INET) {
			info->dport = swap16(sa.sin_port);
			__builtin_memcpy(info->daddr, &sa.sin_addr, 4);
		}
	} else if (info->family == AF_INET6 && namelen >= (int)sizeof(struct sockaddr_in6_abi)) {
		struct sockaddr_in6_abi sa = {};
		bpf_probe_read_kernel(&sa, sizeof(sa), name);
		if (sa.sin6_family == AF_INET6) {
			info->dport = swap16(sa.sin6_port);
			__builtin_memcpy(info->daddr, sa.sin6_addr, 16);
		}
	}
}

static __attribute__((always_inline)) void account(struct sock *sk, __u8 proto, __u64 tx, __u64 rx, struct msghdr *msg)
{
	__u64 key = (__u64)sk;
	struct sock_info *info = bpf_map_lookup_elem(&socks, &key);
	if (!info) {
		struct sock_info fresh = {};
		fresh.born_ns = bpf_ktime_get_ns();
		fresh.tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
		fresh.proto = proto;
		bpf_get_current_comm(fresh.comm, sizeof(fresh.comm));
		read_tuple(sk, &fresh);
		bpf_map_update_elem(&socks, &key, &fresh, BPF_NOEXIST);
		info = bpf_map_lookup_elem(&socks, &key);
		if (!info)
			return;
	} else if (info->dport == 0 || proto == PROTO_TCP) {
		/* TCP: the tuple is complete once connected; refresh it until then. */
		read_tuple(sk, info);
	}
	/* Unconnected UDP (DNS, mDNS...): the peer of this datagram is in the message. */
	if (proto == PROTO_UDP)
		read_msg_peer(msg, info);
	if (tx) {
		__sync_fetch_and_add(&info->tx, tx);
		__sync_fetch_and_add(&info->tx_msgs, 1);
	}
	if (rx) {
		__sync_fetch_and_add(&info->rx, rx);
		__sync_fetch_and_add(&info->rx_msgs, 1);
	}
}

SEC("fexit/tcp_sendmsg")
int tcp_sendmsg_exit(__u64 *ctx)
{
	int ret = (int)ctx[3];
	if (ret > 0)
		account((struct sock *)ctx[0], PROTO_TCP, ret, 0, 0);
	return 0;
}

SEC("fentry/tcp_cleanup_rbuf")
int tcp_cleanup_rbuf_entry(__u64 *ctx)
{
	int copied = (int)ctx[1];
	if (copied > 0)
		account((struct sock *)ctx[0], PROTO_TCP, 0, copied, 0);
	return 0;
}

SEC("fexit/udp_sendmsg")
int udp_sendmsg_exit(__u64 *ctx)
{
	int ret = (int)ctx[3];
	if (ret > 0)
		account((struct sock *)ctx[0], PROTO_UDP, ret, 0, (struct msghdr *)ctx[1]);
	return 0;
}

SEC("fexit/udpv6_sendmsg")
int udpv6_sendmsg_exit(__u64 *ctx)
{
	int ret = (int)ctx[3];
	if (ret > 0)
		account((struct sock *)ctx[0], PROTO_UDP, ret, 0, (struct msghdr *)ctx[1]);
	return 0;
}

/* int udp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len) */
SEC("fexit/udp_recvmsg")
int udp_recvmsg_exit(__u64 *ctx)
{
	int ret = (int)ctx[5];
	if (ret > 0)
		account((struct sock *)ctx[0], PROTO_UDP, 0, ret, (struct msghdr *)ctx[1]);
	return 0;
}

SEC("fexit/udpv6_recvmsg")
int udpv6_recvmsg_exit(__u64 *ctx)
{
	int ret = (int)ctx[5];
	if (ret > 0)
		account((struct sock *)ctx[0], PROTO_UDP, 0, ret, (struct msghdr *)ctx[1]);
	return 0;
}

SEC("fentry/inet_release")
int inet_release_entry(__u64 *ctx)
{
	struct socket *sock = (struct socket *)ctx[0];
	struct sock *sk = 0;
	READ(sk, sock->sk);
	if (!sk)
		return 0;
	__u64 key = (__u64)sk;
	struct sock_info *info = bpf_map_lookup_elem(&socks, &key);
	if (!info)
		return 0;
	struct close_event *event = bpf_ringbuf_reserve(&closed, sizeof(*event), 0);
	if (event) {
		event->sk = key;
		__builtin_memcpy(&event->info, info, sizeof(*info));
		bpf_ringbuf_submit(event, 0);
	}
	bpf_map_delete_elem(&socks, &key);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
