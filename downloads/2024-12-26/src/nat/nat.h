#ifndef __NAT_H
#define __NAT_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define TASK_COMM_LEN 16

struct nat_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u64 skb_ptr;
};

struct nat_info {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct nat {
    char comm[TASK_COMM_LEN]; 
    __u64 skb_ptr;
    __u8  proto;
    __u32 src_ip_old;
    __u32 dst_ip_old;
    __u16 src_port_old;
    __u16 dst_port_old;
    __u32 src_ip_new;
    __u32 dst_ip_new;
    __u16 src_port_new;
    __u16 dst_port_new;
};

#endif /* #define __NAT_H */