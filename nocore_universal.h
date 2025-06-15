/*
 * Definition contained in kernel source code, we report them here to produce
 * a universal no CO-RE binary, which is compatible with all no CO-RE kernels.
 *	  
 */

/* Definitions stable but arch dependent */
typedef unsigned char __u8;
typedef short unsigned int __u16;
typedef unsigned int __u32;
typedef long long unsigned int __u64;

typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

typedef __u16 __be16;
typedef __u32 __be32;

typedef int __s32;
typedef long long int __s64;

typedef __s32 s32;

typedef __u32 __wsum;

#ifdef __TARGET_ARCH_x86
	struct pt_regs { /* From Linux source arch/x86/include/uapi/asm/ptrace.h */
		unsigned long r15;
		unsigned long r14;
		unsigned long r13;
		unsigned long r12;
		unsigned long rbp;
		unsigned long rbx;
		unsigned long r11;
		unsigned long r10;
		unsigned long r9;
		unsigned long r8;
		unsigned long rax;
		unsigned long rcx;
		unsigned long rdx;
		unsigned long rsi;
		unsigned long rdi;
		unsigned long orig_rax;
		unsigned long rip;
		unsigned long cs;
		unsigned long eflags;
		unsigned long rsp;
		unsigned long ss;
	};

#elif __TARGET_ARCH_arm64
	struct user_pt_regs { /* From Linux source arch/arm64/include/asm/ptrace.h */
		__u64 regs[31];
		__u64 sp;
		__u64 pc;
		__u64 pstate;
	};

	struct pt_regs {
		union {
			struct user_pt_regs user_regs;
			struct {
				u64 regs[31];
				u64 sp;
				u64 pc;
				u64 pstate;
			};
		};
		u64 orig_x0;
		s32 syscallno;
		u32 unused2;
		u64 sdei_ttbr1;
		u64 pmr_save;
		u64 stackframe[2];
		u64 lockdep_hardirqs;
		u64 exit_rcu;
	};
#endif

/* Definitions that can be extended in newer kernel versions */
enum bpf_map_type { /* From Linux source include/uapi/linux/bpf.h */
	BPF_MAP_TYPE_UNSPEC = 0,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PROG_ARRAY = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_STACK_TRACE = 7,
	BPF_MAP_TYPE_CGROUP_ARRAY = 8,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
	BPF_MAP_TYPE_LPM_TRIE = 11,
	BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
	BPF_MAP_TYPE_HASH_OF_MAPS = 13,
	BPF_MAP_TYPE_DEVMAP = 14,
	BPF_MAP_TYPE_SOCKMAP = 15,
	BPF_MAP_TYPE_CPUMAP = 16,
	BPF_MAP_TYPE_XSKMAP = 17,
	BPF_MAP_TYPE_SOCKHASH = 18,
	BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED = 19,
	BPF_MAP_TYPE_CGROUP_STORAGE = 19,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED = 21,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
	BPF_MAP_TYPE_QUEUE = 22,
	BPF_MAP_TYPE_STACK = 23,
	BPF_MAP_TYPE_SK_STORAGE = 24,
	BPF_MAP_TYPE_DEVMAP_HASH = 25,
	BPF_MAP_TYPE_STRUCT_OPS = 26,
	BPF_MAP_TYPE_RINGBUF = 27,
	BPF_MAP_TYPE_INODE_STORAGE = 28,
	BPF_MAP_TYPE_TASK_STORAGE = 29,
	BPF_MAP_TYPE_BLOOM_FILTER = 30,
	BPF_MAP_TYPE_USER_RINGBUF = 31,
	BPF_MAP_TYPE_CGRP_STORAGE = 32,
	BPF_MAP_TYPE_ARENA = 33,
	__MAX_BPF_MAP_TYPE = 34,
};

enum { /* From Linux source include/uapi/linux/bpf.h */
	BPF_F_NO_PREALLOC	= (1U << 0),
	BPF_F_NO_COMMON_LRU	= (1U << 1),
	BPF_F_NUMA_NODE		= (1U << 2),
	BPF_F_RDONLY		= (1U << 3),
	BPF_F_WRONLY		= (1U << 4),
	BPF_F_STACK_BUILD_ID	= (1U << 5),
	BPF_F_ZERO_SEED		= (1U << 6),
	BPF_F_RDONLY_PROG	= (1U << 7),
	BPF_F_WRONLY_PROG	= (1U << 8),
	BPF_F_CLONE		= (1U << 9),
	BPF_F_MMAPABLE		= (1U << 10),
	BPF_F_PRESERVE_ELEMS	= (1U << 11),
	BPF_F_INNER_MAP		= (1U << 12),
	BPF_F_LINK		= (1U << 13),
	BPF_F_PATH_FD		= (1U << 14),
	BPF_F_VTYPE_BTF_OBJ_FD	= (1U << 15),
	BPF_F_TOKEN_FD          = (1U << 16),
	BPF_F_SEGV_ON_FAULT	= (1U << 17),
	BPF_F_NO_USER_CONV	= (1U << 18),
};

/* XDP struct. As specified in include/uapi/linux/bpf.h this struct is back compatible because we fields are add at the end */
struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	__u32 ingress_ifindex;
	__u32 rx_queue_index;
	__u32 egress_ifindex;
};

enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP,
	XDP_PASS,
	XDP_TX,
	XDP_REDIRECT,
};

/* Network frame/packets constants and structures */
typedef __u16 __sum16;

#define ETH_P_IP	0x0800
#define IPPROTO_UDP 22
#define ETH_ALEN	6	

struct ethhdr {
	unsigned char	h_dest[ETH_ALEN];
	unsigned char	h_source[ETH_ALEN];
	__be16		h_proto;
} __attribute__((packed));

struct iphdr {
		__u8	ihl:4,
			version:4;
		__u8	tos;
		__be16	tot_len;
		__be16	id;
		__be16	frag_off;
		__u8	ttl;
		__u8	protocol;
		__sum16	check;
		union {
			__be32	saddr;
			__be32	daddr;
		};
};

struct udphdr {
	__be16	source;
	__be16	dest;
	__be16	len;
	__sum16	check;
};