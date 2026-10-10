/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * spectraNET blocks: applications and addresses the user chose to cut off.
 *
 * Attached by snetd to the root cgroup, so it applies to every process. The attachments
 * are bpf links owned by snetd: when snetd stops, for whatever reason, they go away and
 * nothing stays blocked by accident.
 *
 *   cgroup/sock_create       a blocked application can't open a network socket
 *   cgroup/connect4|6        nor connect one it already had, nor reach a blocked address
 *   cgroup/sendmsg4|6        nor send UDP datagrams there
 *   cgroup_skb/ingress|egress  packets from or to a blocked address are dropped
 *
 * Applications are recognised by their executable file (device and inode), not by name:
 * renaming or copying a program elsewhere doesn't change what is blocked, but a different
 * file is a different program. Sockets the application already had are closed by snetd.
 *
 * The program never reads or copies packet contents beyond the IP addresses.
 */
#include "vmlinux_min.h"

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __always_inline inline __attribute__((always_inline))

enum {
	BPF_MAP_TYPE_HASH = 1,
};
#define AF_INET 2
#define AF_INET6 10

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to, __u32 len) = (void *)26;
static __u64 (*bpf_get_current_task)(void) = (void *)35;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *src) = (void *)113;

#define READ(dst, src) bpf_probe_read_kernel(&(dst), sizeof(dst), __builtin_preserve_access_index(&(src)))

/* The kernel types read to find the running executable, for CO-RE (see vmlinux_min.h). */
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)
struct super_block {
	__u32 s_dev;
};
struct inode {
	unsigned long i_ino;
	struct super_block *i_sb;
};
struct file {
	struct inode *f_inode;
};
struct mm_struct {
	struct {
		struct file *exe_file;
	};
};
struct task_struct {
	struct mm_struct *mm;
};
#pragma clang attribute pop

/* Program contexts: user-visible ABI, fixed layout (include/uapi/linux/bpf.h). */
struct bpf_sock {
	__u32 bound_dev_if;
	__u32 family;
};

struct bpf_sock_addr {
	__u32 user_family;
	__u32 user_ip4;     /* network byte order */
	__u32 user_ip6[4];  /* network byte order */
};

struct __sk_buff {
	__u32 len;
};

/* Mirrored by `ExeKey` in Rust. `dev` is the kernel's encoding (major << 20 | minor). */
struct exe_key {
	__u64 ino;
	__u32 dev;
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct exe_key);
	__type(value, __u32);
} blocked_exes SEC(".maps");

/* IPv6 addresses, IPv4 as v4-mapped (::ffff:a.b.c.d). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u8[16]);
	__type(value, __u32);
} blocked_ips SEC(".maps");

static __always_inline int exe_blocked(void)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct mm_struct *mm = 0;
	struct file *exe = 0;
	struct inode *inode = 0;
	struct super_block *sb = 0;
	struct exe_key key = {};

	if (!task)
		return 0;
	READ(mm, task->mm);
	if (!mm) /* kernel threads */
		return 0;
	READ(exe, mm->exe_file);
	if (!exe)
		return 0;
	READ(inode, exe->f_inode);
	if (!inode)
		return 0;
	READ(key.ino, inode->i_ino);
	READ(sb, inode->i_sb);
	if (!sb)
		return 0;
	READ(key.dev, sb->s_dev);
	return bpf_map_lookup_elem(&blocked_exes, &key) != 0;
}

static __always_inline int ip4_blocked(__u32 addr)
{
	__u8 key[16] = {};
	key[10] = 0xff;
	key[11] = 0xff;
	__builtin_memcpy(&key[12], &addr, 4);
	return bpf_map_lookup_elem(&blocked_ips, key) != 0;
}

static __always_inline int ip6_blocked(const __u8 *addr)
{
	__u8 key[16];
	__builtin_memcpy(key, addr, 16);
	return bpf_map_lookup_elem(&blocked_ips, key) != 0;
}

/* Return values: 1 lets the operation through, 0 refuses it (EPERM) or drops the packet. */

SEC("cgroup/sock_create")
int block_sock_create(struct bpf_sock *sk)
{
	if (sk->family != AF_INET && sk->family != AF_INET6)
		return 1;
	return !exe_blocked();
}

SEC("cgroup/connect4")
int block_connect4(struct bpf_sock_addr *ctx)
{
	return !(exe_blocked() || ip4_blocked(ctx->user_ip4));
}

SEC("cgroup/connect6")
int block_connect6(struct bpf_sock_addr *ctx)
{
	__u32 ip[4] = {ctx->user_ip6[0], ctx->user_ip6[1], ctx->user_ip6[2], ctx->user_ip6[3]};
	return !(exe_blocked() || ip6_blocked((const __u8 *)ip));
}

SEC("cgroup/sendmsg4")
int block_sendmsg4(struct bpf_sock_addr *ctx)
{
	return !(exe_blocked() || ip4_blocked(ctx->user_ip4));
}

SEC("cgroup/sendmsg6")
int block_sendmsg6(struct bpf_sock_addr *ctx)
{
	__u32 ip[4] = {ctx->user_ip6[0], ctx->user_ip6[1], ctx->user_ip6[2], ctx->user_ip6[3]};
	return !(exe_blocked() || ip6_blocked((const __u8 *)ip));
}

/* The packet's remote address: source when receiving, destination when sending. */
static __always_inline int skb_blocked(struct __sk_buff *skb, int ingress)
{
	__u8 version = 0;
	if (bpf_skb_load_bytes(skb, 0, &version, 1) < 0)
		return 0;
	version >>= 4;
	if (version == 4) {
		__u32 addr = 0;
		if (bpf_skb_load_bytes(skb, ingress ? 12 : 16, &addr, 4) < 0)
			return 0;
		return ip4_blocked(addr);
	}
	if (version == 6) {
		__u8 addr[16];
		if (bpf_skb_load_bytes(skb, ingress ? 8 : 24, addr, 16) < 0)
			return 0;
		return ip6_blocked(addr);
	}
	return 0;
}

SEC("cgroup_skb/ingress")
int block_ingress(struct __sk_buff *skb)
{
	return !skb_blocked(skb, 1);
}

SEC("cgroup_skb/egress")
int block_egress(struct __sk_buff *skb)
{
	return !skb_blocked(skb, 0);
}

char LICENSE[] SEC("license") = "GPL";
