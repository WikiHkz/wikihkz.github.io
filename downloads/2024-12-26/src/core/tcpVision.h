#ifndef __TCPVERSION_H
#define __TCPVERSION_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define TASK_COMM_LEN 16

struct tcp_event
{
    union
    {  // 本地IP地址
        __u32 L_ip_v4;
        __u8 L_ip_v6[16];
    };
    union
    {  // 外部IP地址
        __u32 R_ip_v4;
        __u8 R_ip_v6[16];
    };
    char comm[TASK_COMM_LEN];  // 进程名称
    __u32 tgid;  // pid
    __u16 af; // ipv4 ipv6
    __u16 L_port;  // 本地端口
    __u16 R_port;  // 外部端口
    __u16 pkt_len; // 包大小，单位是Byte
    __u8 direct_input_flag; // tcp_recvmsg=1 or tcp_sendmsg=0
    __u8 proto;             // 1: TCP  2: UDP
};

#endif /* #define __TCPVERSION_H */