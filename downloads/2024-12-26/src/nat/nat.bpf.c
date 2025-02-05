#define __KERNEL__
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "nat.h"

#define AF_INET 2
#define AF_INET6 10

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 10000);
//     __type(key, struct nat_key);
//     __type(value, struct nat_info);
// } nat_sessions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1024);
} nat_sessions SEC(".maps");


// 创建一个临时 map 用于在 kprobe 和 kretprobe 之间传递信息
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32); 
    __type(value, struct nat);  // 存放 struct sk_buff *skb 指针
} task_ids SEC(".maps");

// 辅助函数：从 skb 中提取 IP 头
static inline struct iphdr *extract_iphdr(struct sk_buff *skb) {
    return (struct iphdr *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, network_header));
}

// 辅助函数：从 skb 中提取 TCP/UDP 头
static inline void *extract_transport_header(struct sk_buff *skb) {
    return (void *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, transport_header));
}

SEC("kprobe/nf_nat_ipv4_manip_pkt")
int BPF_KPROBE(nf_nat_ipv4_manip_pkt, struct sk_buff *skb) {
    __u32 tid = bpf_get_current_pid_tgid();
    if (!skb)
        return 0;

    struct iphdr *iph = extract_iphdr(skb);
    if (!iph)
        return 0;

    // 提取传输层协议头
    void *transport_header = extract_transport_header(skb);
    if (!transport_header)
        return 0;

    // 创建 NAT 会话键
    struct nat _nat = {};
    _nat.skb_ptr = (__u64)skb;
    // bpf_printk("kprobe skb: %llx", key.skb_ptr);
    _nat.proto = BPF_CORE_READ(iph, protocol);
    _nat.src_ip_old = BPF_CORE_READ(iph, saddr);
    _nat.dst_ip_old = BPF_CORE_READ(iph, daddr);

    if (_nat.proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)transport_header;
        _nat.src_port_old = BPF_CORE_READ(tcp, source);
        _nat.dst_port_old = BPF_CORE_READ(tcp, dest);
    } else if (_nat.proto == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)transport_header;
        _nat.src_port_old = BPF_CORE_READ(udp, source);
        _nat.dst_port_old = BPF_CORE_READ(udp, dest);
    } else {
        return 0;
    }
    bpf_map_update_elem(&task_ids, &tid, &_nat, BPF_ANY);

    return 0;
}

SEC("kretprobe/nf_nat_ipv4_manip_pkt")
int BPF_KRETPROBE(nf_nat_ipv4_manip_pkt_exit) {
    __u32 tid = bpf_get_current_pid_tgid();
    struct nat *_nat = bpf_map_lookup_elem(&task_ids, &tid);
    if (!_nat)
        goto cleanup;
    bpf_get_current_comm(&_nat->comm, sizeof(_nat->comm));	
    
    __u64 ret = PT_REGS_RC(ctx);
    // nf_nat_ipv4_manip_pkt 返回值为false直接退出
    if (ret == 0)
        goto cleanup;

    struct sk_buff *skb = (struct sk_buff *)(_nat->skb_ptr);
    // bpf_printk("kretprobe skb: %llx", key->skb_ptr);
    if (!skb)
        goto cleanup;
    
    struct iphdr *iph = extract_iphdr(skb);
    if (!iph)
        goto cleanup;
    
    void *transport_header = extract_transport_header(skb);
    if (!transport_header)
        goto cleanup;

    _nat->src_ip_new = BPF_CORE_READ(iph, saddr);
    _nat->dst_ip_new = BPF_CORE_READ(iph, daddr);

    if (_nat->proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)transport_header;
        _nat->src_port_new = BPF_CORE_READ(tcp, source);
        _nat->dst_port_new = BPF_CORE_READ(tcp, dest);
    } else if (_nat->proto == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)transport_header;
        _nat->src_port_new = BPF_CORE_READ(udp, source);
        _nat->dst_port_new = BPF_CORE_READ(udp, dest);
    } else 
        goto cleanup;
	bpf_perf_event_output(ctx, &nat_sessions, BPF_F_CURRENT_CPU, _nat, sizeof(struct nat));

    cleanup:
        bpf_map_delete_elem(&task_ids, &tid);
        return 0;
}


// SEC("kprobe/nf_nat_ipv4_manip_pkt")
// int BPF_KPROBE(nf_nat_ipv4_manip_pkt, struct sk_buff *skb)
// {
// 	__be32 src_ip, dst_ip;
//     __u16 src_port, dst_port;
//     __u8 protocol;
    
//     // 通过sk_buff获取IP头
//     // struct iphdr *iph;
//     // iph = (struct iphdr *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, network_header));

// 	struct iphdr *iph = extract_iphdr(skb);
//     if (!iph)
//         return 0;


//     // 读取IP地址
//     src_ip = BPF_CORE_READ(iph, saddr);
//     dst_ip = BPF_CORE_READ(iph, daddr);
//     protocol = BPF_CORE_READ(iph, protocol);

//     // 如果是TCP/UDP，获取端口信息
//     if (protocol == IPPROTO_TCP) {
//         struct tcphdr *tcph;
//         // tcph = (struct tcphdr *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, transport_header));
//         tcph = (struct tcphdr *)extract_transport_header(skb);
        
// 		src_port = BPF_CORE_READ(tcph, source);
//         dst_port = BPF_CORE_READ(tcph, dest);
//     } else if (protocol == IPPROTO_UDP) {
// 		struct udphdr *udph;
// 		udph = (struct udphdr *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, transport_header));
// 		src_port = BPF_CORE_READ(udph, source);
// 		dst_port = BPF_CORE_READ(udph, dest);
// 	}
// 	// bpf_printk("src_port: %u", bpf_ntohs(src_port));
// 	// bpf_printk("dst_port: %u", bpf_ntohs(dst_port));
// 	__u16 src_port_hs, dst_port_hs;
// 	src_port_hs = bpf_ntohs(src_port);
// 	dst_port_hs = bpf_ntohs(dst_port);
// 	bpf_printk(
//         "%pI4:%u:  ->  %pI4", 
//         &src_ip, 
// 		src_port_hs,
//         &dst_ip
//     );
// 	return 0;
// }

char LICENSE[] SEC("license") = "GPL";