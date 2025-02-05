#define __KERNEL__
#include <linux/bpf.h>
#include <stdbool.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "tcpVision.h"

#define AF_INET 2
#define AF_INET6 10

typedef unsigned int size_t;

struct sk_common_regs
{
	// rference https://elixir.bootlin.com/linux/v5.15.115/source/include/net/sock.h#L163
	char skc_daddr[4];	   // 外部IPv4
	char skc_rcv_saddr[4]; // 本地IPv4
	char _1[4];			   // 不关心字段
	char skc_dport[2];	   // 外部端口
	char skc_num[2];	   // 内部端口
	short family;		   // 协议族
	char _2[6];
	char _3[4 * sizeof(void *)];
	struct in6_addr skc_v6_daddr;	  // 外部IPv6
	struct in6_addr skc_v6_rcv_saddr; // 本地IPv6
};

struct
{
	// 创建环形缓冲区map
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));   // cpu id
	__uint(value_size, sizeof(__u32)); // 文件描述符fd
	__uint(max_entries, 128);		   // 最多支持128个cpu
} events SEC(".maps");

static int sock_handle(bool receiving, void *ctx, struct sk_common_regs *sk, size_t size)
{
	__u16 family;
	__u16 R_port;
	__u32 pid;
	bpf_probe_read_kernel(&family, sizeof(family), &sk->family);
	if (family != AF_INET && family != AF_INET6)
		return 0;
	struct tcp_event event = {};
	// bpf_get_current_pid_tgid 返回 pid 和 tid
	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	event.tgid = pid;
	event.pkt_len = size;
	bpf_probe_read_kernel(&event.L_port, sizeof(event.L_port), &sk->skc_num);
	bpf_probe_read_kernel(&event.R_port, sizeof(event.R_port), &sk->skc_dport);
	// 网络传输时通常使用大端字节序，Big-Endian，宿主机通常使用小端字节序，需要进行转换
	event.R_port = bpf_ntohs(event.R_port);
	event.af = family;
	event.proto = 1;		// TCP
	if (event.L_port == 22) // 过滤本地22端口(ssh开发背景流量过多)
		return 0;
	
	// 所有的IP都是大端存储的，但是在此处没有进行转换，而是放在了用户空间进行转换
	if (family == AF_INET)
	{
		bpf_probe_read_kernel(&event.L_ip_v4, sizeof(event.L_ip_v4), &sk->skc_rcv_saddr);
		bpf_probe_read_kernel(&event.R_ip_v4, sizeof(event.R_ip_v4), &sk->skc_daddr);
	}
	else
	{
		bpf_probe_read_kernel(&event.L_ip_v6, sizeof(event.L_ip_v6), &sk->skc_v6_rcv_saddr.in6_u.u6_addr32);
		bpf_probe_read_kernel(&event.R_ip_v6, sizeof(event.R_ip_v6), &sk->skc_v6_daddr.in6_u.u6_addr32);
	}
	event.direct_input_flag = receiving ? 1 : 0;
	// 将数据添加到缓冲区
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

// rference https://elixir.bootlin.com/linux/v5.15.115/source/net/ipv4/tcp.c#L1549
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(tcp_cleanup_rbuf, void *sk, int copied)
{
	if (copied <= 0)
		return 0;
	return sock_handle(true, ctx, sk, copied);
}

// rference https://elixir.bootlin.com/linux/v5.15.115/source/net/ipv4/tcp.c#L1457
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, void *sk, void *msg, size_t size)
{
	return sock_handle(false, ctx, sk, size);
}

char LICENSE[] SEC("license") = "GPL";