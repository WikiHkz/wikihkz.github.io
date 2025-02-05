---
title: ebpf开发介绍-tcpVision
date: 2024-12-26
categories: [linux,ebpf]
tags: [ebpf]
description: 本文将会介绍，基于libbpf开发ebpf程序tcpVision。
---

## Introduction

libbpf是一个用于与 Linux 内核中的 eBPF (extended Berkeley Packet Filter) 子系统交互的用户空间库。它简化了 eBPF 程序的加载、验证、映射、附加和管理等工作，使开发者能够更容易地编写和运行 eBPF 程序。

**[libbpf](https://github.com/libbpf/libbpf)**库提供了CO-RE(complier once - run everywhere)能力。

而在实际开发中，我们不常直接使用libbpf库，而是使用**[bpftool](https://github.com/libbpf/bpftool)**库。

bpftool提供了一些额外的能力能够简化开发流程。

## tcpVision

在本文中，将会实现一个简单的能力，实现追踪tcp的流量包。

需要关注的信息主要有IP、端口、流量包大小、关联进程等信息。

在本地开启一个web server，然后本地访问本地。效果如下：

```bash
(base) root@ubuntu:~/tcpVision/build/nonCore# ./tcpVision
Process: curl            PID: 3590477 IPv4: 127.0.0.1      :37170-->127.0.0.1      :34567  size: 79B
Process: web             PID: 3590185 IPv6: ::ffff:127.0.0.1                       :34567<--::ffff:127.0.0.1                       :37170  size: 79B
Process: web             PID: 3590185 IPv6: ::ffff:127.0.0.1                       :34567-->::ffff:127.0.0.1                       :37170  size: 128B
Process: curl            PID: 3590477 IPv4: 127.0.0.1      :37170<--127.0.0.1      :34567  size: 128B
```

其中web server收到的数据包，被记录为IPv6是因为内核开启了双栈协议。

## 依赖

libbpf主要依赖的两个库分别为：

- zlib

- libelf

编译器依赖为clang12以上。

## start

### 工程目录

先建立必要的工程目录，如下所示：

```bash
(base) root@ubuntu:~/tcpVision# tree
.
├── 3rdparty
├── build
├── src
└── tools
    └── cmake
```

### 引入第三方库

```bash
cd 3rdparty/
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool/src
make
```

编译指令会同时编译出`libbpf库`和`bpftool工具`。

在使用libbpf库时，需要使用bpftool工具进行中间文件的编译。在cmake中，被包装为`bpf_object`函数，该函数通过`FindBpfObject.cmake`引入。 该文件是手动引入的，具体引入地址为：https://github.com/libbpf/libbpf-bootstrap/blob/master/tools/cmake/FindBpfObject.cmake

```bash
cd tools/cmake/
vim FindBpfObject.cmake
```

```cmake
if(NOT BPFOBJECT_BPFTOOL_EXE)
  find_program(BPFOBJECT_BPFTOOL_EXE NAMES bpftool DOC "Path to bpftool executable")
endif()

if(NOT BPFOBJECT_CLANG_EXE)
  find_program(BPFOBJECT_CLANG_EXE NAMES clang DOC "Path to clang executable")

  execute_process(COMMAND ${BPFOBJECT_CLANG_EXE} --version
    OUTPUT_VARIABLE CLANG_version_output
    ERROR_VARIABLE CLANG_version_error
    RESULT_VARIABLE CLANG_version_result
    OUTPUT_STRIP_TRAILING_WHITESPACE)

  # Check that clang is new enough
  if(${CLANG_version_result} EQUAL 0)
    if("${CLANG_version_output}" MATCHES "clang version ([^\n]+)\n")
      # Transform X.Y.Z into X;Y;Z which can then be interpreted as a list
      set(CLANG_VERSION "${CMAKE_MATCH_1}")
      string(REPLACE "." ";" CLANG_VERSION_LIST ${CLANG_VERSION})
      list(GET CLANG_VERSION_LIST 0 CLANG_VERSION_MAJOR)

      # Anything older than clang 10 doesn't really work
      string(COMPARE LESS ${CLANG_VERSION_MAJOR} 10 CLANG_VERSION_MAJOR_LT10)
      if(${CLANG_VERSION_MAJOR_LT10})
        message(FATAL_ERROR "clang ${CLANG_VERSION} is too old for BPF CO-RE")
      endif()

      message(STATUS "Found clang version: ${CLANG_VERSION}")
    else()
      message(FATAL_ERROR "Failed to parse clang version string: ${CLANG_version_output}")
    endif()
  else()
    message(FATAL_ERROR "Command \"${BPFOBJECT_CLANG_EXE} --version\" failed with output:\n${CLANG_version_error}")
  endif()
endif()

if(NOT LIBBPF_INCLUDE_DIRS OR NOT LIBBPF_LIBRARIES)
  find_package(LibBpf)
endif()

if(BPFOBJECT_VMLINUX_H)
  get_filename_component(GENERATED_VMLINUX_DIR ${BPFOBJECT_VMLINUX_H} DIRECTORY)
elseif(BPFOBJECT_BPFTOOL_EXE)
  # Generate vmlinux.h
  set(GENERATED_VMLINUX_DIR ${CMAKE_CURRENT_BINARY_DIR})
  set(BPFOBJECT_VMLINUX_H ${GENERATED_VMLINUX_DIR}/vmlinux.h)
  execute_process(COMMAND ${BPFOBJECT_BPFTOOL_EXE} btf dump file /sys/kernel/btf/vmlinux format c
    OUTPUT_FILE ${BPFOBJECT_VMLINUX_H}
    ERROR_VARIABLE VMLINUX_error
    RESULT_VARIABLE VMLINUX_result)
  if(${VMLINUX_result} EQUAL 0)
    set(VMLINUX ${BPFOBJECT_VMLINUX_H})
  else()
    message(FATAL_ERROR "Failed to dump vmlinux.h from BTF: ${VMLINUX_error}")
  endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(BpfObject
  REQUIRED_VARS
    BPFOBJECT_BPFTOOL_EXE
    BPFOBJECT_CLANG_EXE
    LIBBPF_INCLUDE_DIRS
    LIBBPF_LIBRARIES
    GENERATED_VMLINUX_DIR)

# Get clang bpf system includes
execute_process(
  COMMAND bash -c "${BPFOBJECT_CLANG_EXE} -v -E - < /dev/null 2>&1 |
          sed -n '/<...> search starts here:/,/End of search list./{ s| \\(/.*\\)|-idirafter \\1|p }'"
  OUTPUT_VARIABLE CLANG_SYSTEM_INCLUDES_output
  ERROR_VARIABLE CLANG_SYSTEM_INCLUDES_error
  RESULT_VARIABLE CLANG_SYSTEM_INCLUDES_result
  OUTPUT_STRIP_TRAILING_WHITESPACE)
if(${CLANG_SYSTEM_INCLUDES_result} EQUAL 0)
  separate_arguments(CLANG_SYSTEM_INCLUDES UNIX_COMMAND ${CLANG_SYSTEM_INCLUDES_output})
  message(STATUS "BPF system include flags: ${CLANG_SYSTEM_INCLUDES}")
else()
  message(FATAL_ERROR "Failed to determine BPF system includes: ${CLANG_SYSTEM_INCLUDES_error}")
endif()

# Get target arch
execute_process(COMMAND uname -m
  COMMAND sed -e "s/x86_64/x86/" -e "s/aarch64/arm64/" -e "s/ppc64le/powerpc/" -e "s/mips.*/mips/" -e "s/riscv64/riscv/"
  OUTPUT_VARIABLE ARCH_output
  ERROR_VARIABLE ARCH_error
  RESULT_VARIABLE ARCH_result
  OUTPUT_STRIP_TRAILING_WHITESPACE)
if(${ARCH_result} EQUAL 0)
  set(ARCH ${ARCH_output})
  message(STATUS "BPF target arch: ${ARCH}")
else()
  message(FATAL_ERROR "Failed to determine target architecture: ${ARCH_error}")
endif()

# Public macro
macro(bpf_object name input)
  set(BPF_C_FILE ${CMAKE_CURRENT_SOURCE_DIR}/${input})
  foreach(arg ${ARGN})
    list(APPEND BPF_H_FILES ${CMAKE_CURRENT_SOURCE_DIR}/${arg})
  endforeach()
  set(BPF_O_FILE ${CMAKE_CURRENT_BINARY_DIR}/${name}.bpf.o)
  set(BPF_SKEL_FILE ${CMAKE_CURRENT_BINARY_DIR}/${name}.skel.h)
  set(OUTPUT_TARGET ${name}_skel)

  # Build BPF object file
  add_custom_command(OUTPUT ${BPF_O_FILE}
    COMMAND ${BPFOBJECT_CLANG_EXE} -g -O2 -target bpf -D__TARGET_ARCH_${ARCH}
            ${CLANG_SYSTEM_INCLUDES} -I${GENERATED_VMLINUX_DIR}
            -isystem ${LIBBPF_INCLUDE_DIRS} -c ${BPF_C_FILE} -o ${BPF_O_FILE}
    COMMAND_EXPAND_LISTS
    VERBATIM
    DEPENDS ${BPF_C_FILE} ${BPF_H_FILES}
    COMMENT "[clang] Building BPF object: ${name}")

  # Build BPF skeleton header
  add_custom_command(OUTPUT ${BPF_SKEL_FILE}
    COMMAND bash -c "${BPFOBJECT_BPFTOOL_EXE} gen skeleton ${BPF_O_FILE} > ${BPF_SKEL_FILE}"
    VERBATIM
    DEPENDS ${BPF_O_FILE}
    COMMENT "[skel]  Building BPF skeleton: ${name}")

  add_library(${OUTPUT_TARGET} INTERFACE)
  target_sources(${OUTPUT_TARGET} INTERFACE ${BPF_SKEL_FILE})
  target_include_directories(${OUTPUT_TARGET} INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
  target_include_directories(${OUTPUT_TARGET} SYSTEM INTERFACE ${LIBBPF_INCLUDE_DIRS})
  target_link_libraries(${OUTPUT_TARGET} INTERFACE ${LIBBPF_LIBRARIES} -lelf -lz)
endmacro()
```

这个cmak引入 的elf和zlib库是动态引入的，如果需要修改为静态引入，需要对其做一定的修改。

```cmake
  # 动态连接
  # target_link_libraries(${OUTPUT_TARGET} INTERFACE ${LIBBPF_LIBRARIES} -lelf -lz)
  # 静态连接
set(LIBELF_STATIC_LIB /usr/lib/x86_64-linux-gnu/libelf.a)
set(LIBZ_STATIC_LIB /usr/lib/x86_64-linux-gnu/libz.a)
target_link_libraries(${OUTPUT_TARGET} INTERFACE ${LIBBPF_LIBRARIES} ${LIBELF_STATIC_LIB} ${LIBZ_STATIC_LIB} -static)	
```

其实这段cmake主要做的事情，就是生成BPF skeleton header头文件。它用于简化 BPF 程序（eBPF 程序）与其用户空间应用程序之间的交互。具体来说，BPF Skeleton 提供了一种标准化的方法来加载、管理和与 eBPF 程序进行通信，使得开发者可以更容易地集成和使用 eBPF 技术。

核心功能可以用以下三行命令展示(假设我们的程序源代码文件为minimal.bpf.c)：

```bash
clang -g -O2 -target bpf -c minimal.bpf.c -o minimal.tmp.bpf.o
bpftool gen object minimal.bpf.o minimal.tmp.bpf.o
bpftool gen skeleton minimal.bpf.o > minimal.skel.h
```

### Cmake

在`src`目录再新建一个`nonCore`文件夹，并分别创建`CMakeLists.txt`.

```bash
# /tcpVision/src
.
├── CMakeLists.txt
└── nonCore
    ├── CMakeLists.txt
    ├── tcpVision.bpf.c
    ├── tcpVision.c
    └── tcpVision.h
```

其中`src/CMakeLists.txt`的内容为：

```cmake
cmake_minimum_required(VERSION 3.10)
project(tcpVision)
set(CMAKE_C_STANDARD 11)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../tools/cmake)

set(BPFOBJECT_BPFTOOL_EXE ${CMAKE_CURRENT_SOURCE_DIR}/../3rdparty/bpftool/src/bpftool)
set(LIBBPF_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../3rdparty/bpftool/src/libbpf/include)
set(LIBBPF_LIBRARIES ${CMAKE_CURRENT_SOURCE_DIR}/../3rdparty/bpftool/src/libbpf/libbpf.a)

find_package(BpfObject REQUIRED)

add_subdirectory(nonCore)
```

其中`src/nonCore/CMakeLists.txt`的内容为：

```cmake
cmake_minimum_required(VERSION 3.10)
project(tcpVisionNonCore)

set(app_stem "tcpVision")

bpf_object(${app_stem} ${app_stem}.bpf.c)
add_dependencies(${app_stem}_skel libbpf-build bpftool-build)

add_executable(${app_stem} ${app_stem}.c)
target_link_libraries(${app_stem} ${app_stem}_skel)
```

## nonCore

实现一个简单的ebpf程序，通常只需要3个基本的c文件。例如在我们的例子中，只有三个文件。

- tcpVision.bpf.c，注册到内核中hook点的函数，实现与内核态的交互
- tcpVision.h，头文件，定义一些数据结构
- tcpVision.c，包含main函数，实现与用户态的交互

### tcpVision.h

**tcpVision.h**中主要定义一些需要用到的数据结构，例如在本例子中，需要定义存储ip、端口、进程名称的结构体。

源代码为：

```c
#ifndef __TCPVERSION_H
#define __TCPVERSION_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define TASK_COMM_LEN 16

struct pt_regs
{
  // 此处后文有具体描述
  ……
};

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
```

我们定义了一个结构体`tcp_event`，用于在收发tcp包时，记录我们想要存储的数据。

需要注意的是，在Linux内核中，在`sock`结构体中似乎不会区分一个数据包的源IP和目标IP，而是通过本地IP和外部IP来区分的。

例如在内核函数`tcp_cleanup_rbuf`在收到数据，清空缓冲区的时候会被调用，`tcp_sendmsg`在发送tcp包的时候会被调用。

这两个函数的参数都使用了`sock`结构体。

在`tcp_cleanup_rbuf`中，数据包的流向是 `外部IP->本地IP`，而在在`tcp_sendmsg`中，数据包的流向是 `本地IP->外部IP`。

### tcpVision.bpf.c

`tcpVision.bpf.c`是整个ebpf的核心，其实现了与内核态的交互。

源码为：

```c
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
	
	// 所有的IP都是大端存储的，但是不需要进行特殊处理。因为IP是使用bit位存储的。
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
```

在上述的源码中，主要做了这么几件事情：

1. 定义与内核中`sock_common`结构体相同的简化版的结构体
2. 定义环形缓冲区map
3. 定义通用的处理函数，处理`sock`结构体数据
4. 在`tcp_cleanup_rbuf`和`tcp_sendmsg`函数hook点注册钩子函数
5.  声明该ebpf程序license

下面对这几件事情做解释说明，顺序与上面稍有不同。

#### 5.声明license

声明该ebpf程序license，当加载 eBPF 程序时，Linux 内核会检查 `"license"` 段中的内容。如果该段存在并且包含有效的许可证信息（如 `"GPL"` 或其他受支持的许可证），内核会允许加载该 BPF 程序。

#### 4. 注册钩子函数

在`tcp_cleanup_rbuf`和`tcp_sendmsg`函数hook点注册钩子函数。

这两个函数都是内核函数，ebpf的`kprobe`类型的探针允许在任意内核函数的入口处添加钩子函数。

```c
// rference https://elixir.bootlin.com/linux/v5.15.115/source/net/ipv4/tcp.c#L1457
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, void *sk, void *msg, size_t size)
{
	return sock_handle(false, ctx, sk, size);
}
```

`SEC` 是一个由 BPF 编译工具链提供的宏，用于将代码或数据放置到特定的 ELF 段中。

`"kprobe/tcp_sendmsg"` 这个字符串指定了一个特殊的段名，用于标识这是一个 kprobe 类型的 BPF 程序，并且它关联的是名为 `tcp_sendmsg` 的内核函数。内核加载器会根据这个段名识别出这是一个 kprobe 探针，并将其附加到相应的内核函数上。

当编译并加载这个 eBPF 程序时，内核会查找所有以 `"kprobe/"` 开头的段，并将这些段中的 BPF 程序作为探针附加到对应的内核函数上。在这个例子中，`"kprobe/tcp_sendmsg"` 表示该 BPF 程序会在 `tcp_sendmsg` 内核函数被调用时触发。

#### 4. BPF_KPROBE

`BPF_KPROBE` 是由 `libbpf` 提供的一个宏，用于定义一个内核探针（Kprobe），这个探针会在指定的内核函数被调用时执行。它会自动处理一些底层细节，如段名设置、参数传递等。

```c
int BPF_KPROBE(tcp_sendmsg, void *sk, void *msg, size_t size);
```

`BPF_KPROBE` 返回值类型为 `int` 是为了与内核函数的设计保持一致，允许 eBPF 程序通过返回 `0` 或非零值来控制内核函数的行为。返回 `0` 表示 eBPF 程序成功执行且不干预内核函数的继续执行，返回非零值则可能表示错误或中止当前操作。

在这行代码中，`tcp_sendmsg`是钩子函数名，**通常**与内核函数同名。后面紧跟的`void *sk, void *msg, size_t size`表示钩子函数的参数，此处应该与内核函数的定义完全相同。

在我们的例子中，两个钩子函数的定义：

```c
int BPF_KPROBE(tcp_cleanup_rbuf, void *sk, int copied);
int BPF_KPROBE(tcp_sendmsg, void *sk, void *msg, size_t size);
```

最后一个形参的定义都表示当前收发包的大小，但是一个是int类型(可能为负)，一个是size_t类型。

这是因为，在内核中，这两个函数就是这么定义的，内核源码如下：

```c
// https://elixir.bootlin.com/linux/v5.15.115/source/net/ipv4/tcp.c#L1549
// int BPF_KPROBE(tcp_cleanup_rbuf, void *sk, int copied);
void tcp_cleanup_rbuf(struct sock *sk, int copied)
{
	// ......
}

// https://elixir.bootlin.com/linux/v5.15.115/source/net/ipv4/tcp.c#L1457
// int BPF_KPROBE(tcp_sendmsg, void *sk, void *msg, size_t size);
int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
	int ret;

	lock_sock(sk);
	ret = tcp_sendmsg_locked(sk, msg, size);
	release_sock(sk);

	return ret;
}
```

由于在这两个内核函数的参数中，关键信息都使用了同一个数据结构，即内存中的`sock`结构体，因此我们可以用一个通用的处理函数来处理，而不用为每一个钩子函数单独实现。

仍然以`SEC("kprobe/tcp_sendmsg")`为例，其返回值为`return sock_handle(false, ctx, sk, size);`，多了一个**`ctx`**。

这个`ctx`实质上是`BPF_KPROBE`隐式传递了第一个参数。如果把`BPF_KPROBE`宏展开，会发现其第一个参数是ctx，用于表示当前的上下文。

这个`ctx`实质上是`struct pt_regs *ctx`指针，而这个`pt_regs`（即 **process/thread registers**）是一个结构体，用于存储 CPU 寄存器的当前状态。`pt_regs`取决于CPU Arch，具体后文有说明。

#### 1 sock_common结构体

上文说到，内核函数`tcp_sendmsg`的参数使用的结构体是`struct sock`，它是一个非常重要的网络层结构体，用于表示一个套接字（socket）。`struct sock` 是所有协议（如 TCP、UDP 等）的通用部分，而每个具体协议可能会在此基础上扩展自己的特定信息。

其内内核的定义为：

```c
// https://elixir.bootlin.com/linux/v5.15.115/source/include/net/sock.h#L352
struct sock {
	/*
	 * Now struct inet_timewait_sock also uses sock_common, so please just
	 * don't add nothing before this first member (__sk_common) --acme
	 */
	struct sock_common	__sk_common;
	// ......
}
```

我们关心的一些数据都存在`struct sock_common`中，并且sock_common在`sock`中的偏移量为0，因此可以直接把`sock`指针当作`sock_common`指针使用。

而`sock_common`在内核中的定义为：

```c
// https://elixir.bootlin.com/linux/v5.15.115/source/include/net/sock.h#L163
struct sock_common {
	union {
		__addrpair	skc_addrpair;
		struct {
			__be32	skc_daddr;		 // 外部IPv4
			__be32	skc_rcv_saddr; // 本地IPv4
		};
	};
	union  {
		unsigned int	skc_hash;
		__u16		skc_u16hashes[2];
	};
	/* skc_dport && skc_num must be grouped as well */
	union {
		__portpair	skc_portpair;
		struct {
			__be16	skc_dport;  // 外部端口
			__u16	skc_num;			// 内部端口
		};
	};

	unsigned short		skc_family;       // 协议族 
	volatile unsigned char	skc_state;
	unsigned char		skc_reuse:4;
	unsigned char		skc_reuseport:1;
	unsigned char		skc_ipv6only:1;
	unsigned char		skc_net_refcnt:1;
	int			skc_bound_dev_if;
	union {
		struct hlist_node	skc_bind_node;
		struct hlist_node	skc_portaddr_node;
	};
	struct proto		*skc_prot;
	possible_net_t		skc_net;

#if IS_ENABLED(CONFIG_IPV6)
	struct in6_addr		skc_v6_daddr;     // 外部IPv6
	struct in6_addr		skc_v6_rcv_saddr; // 本地IPv6
#endif
// ......
}
```

 `sock_common` 结构体定义在 `net/sock.h` 中，这是内核内部的头文件，不是标准的用户空间 API 的一部分，因此我们在ebpf程序中直接引用这个头文件，获取 `sock_common` 结构体的定义，因此，我们需要自己实现 `sock_common` 结构体的定义。

在本文中，我们自己定义的结构体源码为：

```c
struct sk_common_regs
{
	// rference https://elixir.bootlin.com/linux/v5.15.115/source/include/net/sock.h#L163
	char skc_daddr[4];	   // 外部IPv4
	char skc_rcv_saddr[4]; // 本地IPv4
	char _1[4];			   		 // 不关心字段
	char skc_dport[2];	   // 外部端口
	char skc_num[2];	     // 内部端口
	short family;		   		 // 协议族
	char _2[6];
	char _3[4 * sizeof(void *)];
	struct in6_addr skc_v6_daddr;	  // 外部IPv6
	struct in6_addr skc_v6_rcv_saddr; // 本地IPv6
};
```

其结构上(偏移量)与内核保持完全一致，这样才能正确的解引指针。

需要注意的是，在IPv6的数据结构上，我们直接使用了`struct in6_addr`结构体，`in6_addr` 结构体定义在 `linux/in6.h` 中，这个头文件是用户空间程序可以直接使用的公共 API 的一部分。

其与区别在于：

- `in6_addr` 是网络协议栈的基础结构，其定义是稳定的，因为它需要兼容网络协议标准

- `sock_common` 是内核内部使用的结构体，可能会随着内核版本变化而改变，不属于稳定的 ABI

- eBPF 编译器（如 Clang）在编译 eBPF 程序时，不能直接访问所有内核头文件，它只能访问一些基本的、专门为用户空间暴露的头文件

#### 网络字节序

在网络传输中，使用的都是网络字节序，即大端序。而本机存储使用的往往都是主机字节序，通常是小端存储。

在记录网络流量的时候，需要进行适当的转换。

查看`sock_common` 结构体在内核中的定义，我们只关注IP和端口信息：

```c
// https://elixir.bootlin.com/linux/v5.15.115/source/include/net/sock.h#L163
struct sock_common {
// ......
			__be32	skc_daddr;		 // 外部IPv4
			__be32	skc_rcv_saddr; // 本地IPv4
// ......
			__be16	skc_dport;  // 外部端口
			__u16	skc_num;			// 内部端口
// ......
}
```

其中内部端口的数据类型是`__u16`，是一个普通的 16 位无符号整数类型，而外部端口的数据类型是`__be16`。

而进一步查看`__be16`的数据类型，仍然是`__u16`。

```c
// https://elixir.bootlin.com/linux/v5.15.115/source/include/uapi/linux/types.h#L30
typedef __u16 __bitwise __be16;
typedef __u32 __bitwise __be32;
```

那么都是`__u16`，为什么还要"多次一举"的使用`__be16`呢？

实际上，这是在表明，`skc_dport`属性是大端存储的16 位无符号整数类型。

`__be16`代表*big-endian*的意思。

#### 2. 环形缓冲区

`BPF_MAP_TYPE_PERF_EVENT_ARRAY`主要用于从内核空间向用户空间高效地传输大量事件数据。它利用了 Linux 的性能事件子系统 (`perf_event`)，允许将事件数据以异步的方式发送到用户空间。用户空间可以通过 `perf_buffer__consume()` 等 API 获取和处理这些事件数据。

- 支持多 CPU 并发写入，每个 CPU 核心有自己的缓冲区，避免了跨 CPU 的竞争。
- 数据传输是异步的，适合处理高频率或大批量的数据流。
- 适用于需要快速、高效地将大量事件数据（如网络包捕获、跟踪点等）从内核传输到用户空间的应用。

其key是cpu id，value是缓冲区文件描述符，每个cpu都有自己的缓冲区，避免了竞争问题。而缓冲区的大小，需要在ebpf程序加载的时候确定，在后文有描述。

#### 3. 通用的处理函数

由于在本例中使用的两个内核函数的参数使用了相同的数据结构`sock_common`，因此我们可以定义一个通用的处理函数，来统一进行处理。

该函数主要做了四件事情：

1. 定义一个空的`struct tcp_event`用于记录本次tcp包事件
2. 调用`bpf_probe_read_kernel`函数从内核空间中读取数据，添加到事件中
3. 对外部端口做字节转换(大端->小端)
4. 将事件发送到环形缓冲区

```c
static int sock_handle(bool receiving, void *ctx, struct sk_common_regs *sk, size_t size);
```

这个函数接受4个参数，分别是：

- receiving，表明是tcp_cleanup_rbuf还是tcp_sendmsg函数
- ctx，上文提到的寄存器上下文数据(pt_regs)
- sk_common_regs，自定义的sk_common结构体指针
- size，数据包大小，单位是Byte

`bpf_probe_read_kernel`是 Linux 内核提供的一个辅助函数（helper function），用于 eBPF 程序在内核空间中安全地读取内存。这个函数允许 eBPF 程序访问内核地址空间的数据，同时确保操作的安全性和稳定性。

> 某些低版本的内核可能需要替换为
>
> bpf_probe_read

函数签名为：

```c
long bpf_probe_read_kernel(void *dst, u32 size, const void *unsafe_ptr);
// dst：指向用户提供的缓冲区的指针，用于存放读取的数据。
// size：要读取的字节数。
// unsafe_ptr：指向内核空间中希望读取数据的源地址的指针。
```

`bpf_ntohs`是 Linux 内核提供的，用于在网络字节序（大端序，big-endian）和主机字节序之间转换 16 位无符号整数的 eBPF 辅助函数。

### tcpVision.c

`tcpVision.c`包含了`main`函数，实现了ebpf程序的加载、与用户交互等功能。

源码为：

```c
#include "tcpVision.h"
#include "tcpVision.skel.h"
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>

// 配置了环形缓冲区的大小，其单位是页（Page）。在大多数系统上，页面大小为 4 KB
#define PERF_BUFFER_PAGES 16
// 超时时间，以毫秒为单位。
#define PERF_POLL_TIMEOUT_MS 50

static volatile sig_atomic_t exiting = 0;

static void handle_event(void *ctx, int cpu, void *data, __u32 size)
{
    struct tcp_event *event = data;
    const char *directStr = event->direct_input_flag == 1 ? "<--" : "-->";
    if (event->af == AF_INET)
    {
        char local_ip[INET_ADDRSTRLEN];
        char extal_ip[INET_ADDRSTRLEN];
        // 字节序转换
        inet_ntop(AF_INET, &event->L_ip_v4, local_ip, sizeof(local_ip));
        inet_ntop(AF_INET, &event->R_ip_v4, extal_ip, sizeof(extal_ip));
        printf("Process: %-15s PID: %-6d IPv4: %-15s:%-5d%s%-15s:%-5d  size: %dB\n",
               event->comm, event->tgid, local_ip, event->L_port, directStr, extal_ip, event->R_port, event->pkt_len);
    }
    else if (event->af == AF_INET6)
    {
        char local_ip[INET6_ADDRSTRLEN];
        char extal_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &event->L_ip_v6, local_ip, sizeof(local_ip));
        inet_ntop(AF_INET6, &event->R_ip_v6, extal_ip, sizeof(extal_ip));
        printf("Process: %-15s PID: %-6d IPv6: %-39s:%-5d%s%-39s:%-5d  size: %dB\n",
               event->comm, event->tgid, local_ip, event->L_port, directStr, extal_ip, event->R_port, event->pkt_len);
    }
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
    fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}


int main(int argc, char **argv)
{
    struct tcpVision_bpf *obj;
    struct perf_buffer *pb = NULL;
    int err;

    // 打开eBPF对象
    obj = tcpVision_bpf__open();
    if (libbpf_get_error(obj))
    {
        fprintf(stderr, "Failed to open eBPF object.\n");
        return 1;
    }

    // 加载和验证eBPF程序
    err = tcpVision_bpf__load(obj);
    if (err)
    {
        fprintf(stderr, "Failed to load eBPF object.\n");
        goto cleanup;
    }

    // 挂载eBPF程序
    err = tcpVision_bpf__attach(obj);
    if (err)
    {
        fprintf(stderr, "Failed to load eBPF object.\n");
        goto cleanup;
    }

    pb = perf_buffer__new(bpf_map__fd(obj->maps.events),
                          PERF_BUFFER_PAGES,
                          handle_event,
                          handle_lost_events,
                          NULL, NULL);
    if (!pb)
    {
        fprintf(stderr, "failed to open perf buffer: %d\n", errno);
        goto cleanup;
    }

    while (!exiting)
    {
        err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
        if (err < 0 && err != -EINTR)
        {
            fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
            goto cleanup;
        }
        err = 0;
    }

cleanup:
    perf_buffer__free(pb);
    tcpVision_bpf__destroy(obj);

    return err != 0;
}
```

在该文件中，引入了一个头文件`#include "tcpVision.skel.h"`这个头文件，是`tcpVision.bpf.c`文件经过`bpftool`工具生成的对象文件。

`tcpVision.skel.h`头文件中就包含了 `tcpVision.bpf.c` 对应的elf文件数据，以及用户层需要的 open, load, attach 等接口。

#### eBPF程序的生命周期

eBPF程序的生命周期主要有四个阶段，`open`、`load`、`attach`和`destroy`。

- open 阶段
  从 clang 编译器编译得到的eBPF程序elf文件中抽取 maps, eBPF程序, 全局变量等；但是还未在内核中创建，所以还可以对 maps, 全局变量 进行必要的修改。

  ````c
  // 打开eBPF对象
  struct tcpVision_bpf *obj;
  obj = tcpVision_bpf__open();
  /* 还可以通过 bpf_map__set_value_size 和 bpf_map__set_max_entries 2个接口对eBPF内核层代码中
   * 定义的 maps 进行修改;
   */
  ````

- load 阶段

  maps，全局变量 在内核中被创建，eBPF字节码程序加载到内核中，并进行校验；但这个阶段，eBPF程序虽然存在内核中，但还不会被运行，还可以对内核中的maps进行初始状态的赋值。

  ```c
  // 加载和验证eBPF程序
  err = tcpVision_bpf__load(obj);
  ```

- attach 阶段

  eBPF程序被attach到挂载点，eBPF相关功能开始运行，比如：eBPF程序被触发运行，更新maps, 全局变量等。

  ```c
  // 挂载eBPF程序
  err = tcpVision_bpf__attach(obj);
  ```

- destroy 阶段
  eBPF程序被 detached，eBPF用到的资源将会被释放。

  ```c
  tcpVision_bpf__destroy(obj);
  ```

在 libbpf中，4个阶段对应的用户层接口：

```c
// open 阶段，xxx：根据eBPF程序文件名而定
xxx_bpf__open(...);

// load 阶段，xxx：根据eBPF程序文件名而定
xxx_bpf__load(...);

// attach 阶段，xxx：根据eBPF程序文件名而定
xxx_bpf__attach(...);

// destroy 阶段，xxx：根据eBPF程序文件名而定
xxx_bpf__destroy(...);
```

> eBPF程序生命周期更详细的介绍：
>
> https://nakryiko.com/posts/bcc-to-libbpf-howto-guide/#bpf-skeleton-and-bpf-app-lifecycle

#### 创建perf buffer

```c
  pb = perf_buffer__new(bpf_map__fd(obj->maps.events),
                        PERF_BUFFER_PAGES,
                        handle_event,
                        handle_lost_events,
                        NULL, NULL);
```

这段代码在用户空间创建一个新的 **perf buffer**，用于从内核中的 `BPF_MAP_TYPE_PERF_EVENT_ARRAY` 类型的 map 接收事件数据。

1. `perf_buffer__new` 函数
   `perf_buffer__new` 是 libbpf 库中的一个函数，用于创建一个新的 `perf_buffer`，并设置相关参数。`perf_buffer` 是一个用于从内核获取事件数据的缓冲区，通常与 `BPF_MAP_TYPE_PERF_EVENT_ARRAY` 类型的 eBPF map 一起使用。
2. `bpf_map__fd(obj->maps.events)`
   - `bpf_map__fd(obj->maps.events)` 获取与 `obj->maps.events` 相关联的文件描述符。`obj->maps.events` 是指向一个 `BPF_MAP_TYPE_PERF_EVENT_ARRAY` 类型的 eBPF map 的指针，通过它，我们可以访问到这个 map 存储的事件数据。
   - `bpf_map__fd` 是 libbpf 提供的一个函数，它返回与 `BPF_MAP_TYPE_PERF_EVENT_ARRAY` 类型的 eBPF map 对应的文件描述符。这个文件描述符在内核和用户空间之间传递事件数据时起到了桥梁作用。
3. PERF_BUFFER_PAGES
   表示为 perf buffer 分配的内存页数。通常来说，perf buffer 会使用内存页来存储事件数据，`PERF_BUFFER_PAGES` 代表了要为事件缓冲区分配多少内存页（每页通常是 4KB）。
4. handle_event
   是一个回调函数，用于处理从内核传递过来的事件数据。当内核事件到达用户空间时，`handle_event` 会被调用。
5. handle_lost_events
   是另一个回调函数，用于处理在事件传输过程中丢失的事件。如果事件在内核和用户空间之间传输时发生丢失（通常因为缓冲区溢出或其他原因），这个函数会被调用。

#### perf_buffer轮询

```c
  while (!exiting)
  {
      err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
      if (err < 0 && err != -EINTR)
      {
          fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
          goto cleanup;
      }
      err = 0;
  }
```

这段代码 从 `perf_buffer` 中轮询事件的函数调用，常用于处理内核通过 `BPF_MAP_TYPE_PERF_EVENT_ARRAY` 类型的 eBPF map 发送到用户空间的事件数据。

1. `perf_buffer__poll` 函数
   `perf_buffer__poll` 是 libbpf 库中的一个函数，用于从 perf buffer 中读取数据。其会等待事件的到来，并在有事件到达时调用相应的回调函数进行处理。如果在指定的超时时间内没有事件到达，它将返回超时的错误代码。

   ```c
   int perf_buffer__poll(struct perf_buffer *pb, unsigned int timeout_ms);
   // pb：指向 perf_buffer 的指针，表示要从中轮询数据的 perf_buffer 实例
   // timeout_ms：轮询的超时时间，单位为毫秒。timeout_ms 设置了最大等待时间，如果在这个时间内没有事件到达，则会返回。
   // 置为 -1 表示无限期等待，直到有事件发生；0 表示立即返回，不等待。
   // 返回值
   // 如果有新的事件可以处理，返回正数，表示可读取的文件描述符数量。
   // 如果超时或没有任何事件，返回 0。
   // 如果发生错误，返回负的 errno 值。
   ```

2. `pb`（`perf_buffer` 实例）
   `pb` 是一个指向 `perf_buffer` 数据结构的指针。这个 `perf_buffer` 是通过 `perf_buffer__new` 创建的，作为从内核传递到用户空间的事件数据缓冲区。

### pt_regs

在`tcpVision.h`中我们留了一个坑。

```c
struct pt_regs
{
  // 此处后文有具体描述
  ……
};
```

`pt_regs`（Processor Trace Registers）是保存处理器寄存器状态的结构体。在 eBPF 程序中，尤其是使用 kprobes 时，经常需要访问这个结构体来获取函数调用的参数和上下文信息。

- `pt_regs` 结构体的定义是与 CPU 架构强相关的（x86、ARM、MIPS 等都不同）

- 由于 eBPF 程序需要在不同架构上运行，我们需要明确指定当前目标架构的寄存器布局
- 与 `sock_common` 类似，内核中的 `pt_regs` 定义对 eBPF 程序不直接可见

因此我们需要手动实现pt_regs的定义。

其内容只跟cpu架构相关，可以在https://github.com/libbpf/vmlinux.h/tree/main/include中找到与当前cpu架构相同的pt_regs的定义。

例如x86的定义可以在https://github.com/libbpf/vmlinux.h/blob/83a228cf37fc65f2d14e4896a04922b5ee531a94/include/x86/vmlinux_6.6.h#L14142查看。

## CORE

在上一节的`tcpVision.bpf.c`节，我们花了大量的篇幅描述如何自定义结构体，但是在不同版本的内核中，结构体的定义是可能变化的，这导致ebpf程序的兼容性问题。

eBPF 的 CORE（CO-RE，Compile Once – Run Everywhere）是一种旨在提高 eBPF 程序可移植性和兼容性的技术。它允许开发者编写一次 eBPF 程序，并在不同的内核版本和架构上运行，而不需要为每个目标环境重新编译或手动调整代码。

CORE依赖内核BTF 支持 (5.2+)

```bash
// 检查内核是否开启BTF支持
cat /boot/config-$(uname -r) | grep CONFIG_DEBUG_INFO_BTF=y
```

> Linux 5.2 虽然支持了 CONFIG_DEBUG_INFO_BTF，但对 CO-RE 的支持还不完整。主要原因包括：
>
> 1. 5.2 版本的 BTF 信息还不够完整，缺少一些重要的类型信息，特别是对函数、指针等复杂类型的支持还不完善，某些内核结构体的关键信息可能缺失。
> 2. 对多级结构体访问的重定位支持不完整，某些复杂的重定位场景可能会失败。
>
> 技术上可以在 5.2 版本上使用一些基本的 CO-RE 功能，但会遇到很多限制和兼容性问题。为了获得完整的 CO-RE 体验，建议使用 5.6 或更高版本的内核。

在本节，我们将会介绍，如何开发core支持的ebpf程序。

### 引入vmlinux.h

引入vmlinux.h是实现CORE的关键所在。vmlinux.h 是 Linux 内核中一个非常重要的头文件，它包含了内核的 BTF (BPF Type Format) 信息。

- vmlinux.h 本质上是将内核的 BTF 数据转换成 C 语言的类型定义

- 它包含了内核中所有的结构体定义、类型信息、函数原型等这使得用户态程序可以直接访问和使用内核数据结构，而不需要手动重新定义
- 它是 eBPF (Extended Berkeley Packet Filter) 程序开发的基础
- 允许 eBPF 程序直接使用内核数据结构，无需维护单独的头文件确保了类型信息的准确性和完整性

使用vmlinux.h的优点主要是：

- 类型安全
  - 确保 eBPF 程序使用正确的数据结构
  - 减少由于手动定义结构体导致的错误
- 维护简便
  - 自动跟随内核更新
  - 无需手动同步头文件
- 开发效率
  - 简化了 eBPF 程序的开发流程
  - 提供了完整的内核符号信息

vmlinux.h可以通过bpftool工具本地生成。

```bash
# https://github.com/libbpf/libbpf-bootstrap/blob/master/tools/gen_vmlinux_h.sh

#/bin/sh
$(dirname "$0")/bpftool btf dump file ${1:-/sys/kernel/btf/vmlinux} format c
```

这个头文件必须要和cpu arch完全匹配，但是对内核版本并没有严格的要求，我们可以通过本地生成，也可以直接从GitHub上引入。

```bash
cd 3rdparty
git clone https://github.com/libbpf/vmlinux.h.git
mkdir vmlinux
mv vmlinux.h/include/* vmlinux/
rm -rf vmlinux.h/
```

在`3rdparty`路径中引入了libbpf官方在GitHub上整理好的vmlinux.h头文件。

同时还需要对cmake文件做一定的修改。

> 上文提到的FindBpfObject.cmake默认会在本地使用bpftool工具创建vmlinux.h头文件

### cmake

在`src`目录再新建一个`nonCore`文件夹，并分别创建`CMakeLists.txt`.

```bash
# /tcpVision/src
.
├── CMakeLists.txt
├── core
│   ├── CMakeLists.txt
│   ├── tcpVision.bpf.c
│   ├── tcpVision.c
│   └── tcpVision.h
└── nonCore
    ├── CMakeLists.txt
    ├── tcpVision.bpf.c
    ├── tcpVision.c
    └── tcpVision.h
```

其中`src/CMakeLists.txt`的要做一定的修改，内容为：

```cmake
cmake_minimum_required(VERSION 3.10)
project(tcpVision)
set(CMAKE_C_STANDARD 11)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../tools/cmake)

if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "x86_64")
  set(ARCH "x86")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm")
  set(ARCH "arm")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "aarch64")
  set(ARCH "arm64")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "ppc64le")
  set(ARCH "powerpc")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "mips")
  set(ARCH "mips")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "riscv64")
  set(ARCH "riscv")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "loongarch64")
  set(ARCH "loongarch")
endif()
set(BPFOBJECT_VMLINUX_H ${CMAKE_CURRENT_SOURCE_DIR}/../3rdparty/vmlinux/${ARCH}/vmlinux.h)


set(BPFOBJECT_BPFTOOL_EXE ${CMAKE_CURRENT_SOURCE_DIR}/../3rdparty/bpftool/src/bpftool)
set(LIBBPF_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../3rdparty/bpftool/src/libbpf/include)
set(LIBBPF_LIBRARIES ${CMAKE_CURRENT_SOURCE_DIR}/../3rdparty/bpftool/src/libbpf/libbpf.a)

find_package(BpfObject REQUIRED)

# add_subdirectory(nonCore)
add_subdirectory(core)
```

主要做了三件事情：

1. 设置当前的CPU ARCH信息
2. 设置 `BPFOBJECT_VMLINUX_H`变量(FindBpfObject.cmake会查找这个变量)
3. 注释`nonCore`子文件夹并添加`core`(主要是因为文件名称冲突了)

其中`src/core/CMakeLists.txt`的内容为：

```cmake
cmake_minimum_required(VERSION 3.10)
project(tcpVisionNonCore)

set(app_stem "tcpVision")

bpf_object(${app_stem} ${app_stem}.bpf.c)
add_dependencies(${app_stem}_skel libbpf-build bpftool-build)

add_executable(${app_stem} ${app_stem}.c)
target_link_libraries(${app_stem} ${app_stem}_skel)
```

> `src/core/CMakeLists.txt`和`src/nonCore/CMakeLists.txt`的内容以及文件名是完全一样的。
>
> 这才导致了在`src/CMakeLists.txt`中不能同时编译`add_subdirectory(nonCore)`和`add_subdirectory(core)`。

### 源码

core的版本与nonCore的版本，在`tcpVision.c`文件上，没有任何区别。

在`tcpVision.h`文件上，唯一的区别在于core的版本删除了`struct pt_regs`结构体的定义。

> 因为引入了 vmlinux.h，里面有完整的`pt_regs`的定义

因此我们重点关注`tcpVision.bpf.c`文件。

```c
#define __KERNEL__
#include <vmlinux.h>  // 引入vmlinux.h
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "tcpVision.h"

#define AF_INET 2
#define AF_INET6 10

struct
{
	// 创建环形缓冲区map
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));   // cpu id
	__uint(value_size, sizeof(__u32)); // 文件描述符fd
	__uint(max_entries, 128);		   // 最多支持128个cpu
} events SEC(".maps");

static int sock_handle(bool receiving, void *ctx, struct sock *sk, size_t size)
{
	__u16 family;
	__u16 R_port;
	__u32 pid;
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;
	struct tcp_event event = {};
	// bpf_get_current_pid_tgid 返回 pid 和 tid
	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));	
	event.tgid = pid;
	event.pkt_len = size;
	event.L_port = BPF_CORE_READ(sk, __sk_common.skc_num);
	event.R_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	event.af = family;
	event.proto = 1;		// TCP
	if (event.L_port == 22) // 过滤本地22端口(ssh开发背景流量过多)
		return 0;
	
	// 所有的IP都是大端存储的，但是在此处没有进行转换，而是放在了用户空间进行转换
	if (family == AF_INET)
	{
		BPF_CORE_READ_INTO(&event.L_ip_v4, sk, __sk_common.skc_rcv_saddr);
		BPF_CORE_READ_INTO(&event.R_ip_v4, sk, __sk_common.skc_daddr);
	}
	else
	{
		BPF_CORE_READ_INTO(&event.L_ip_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&event.R_ip_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
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
```

由于引入了vmlinux.h的缘故，我们可以访问内核中所有的结构体的定义，自然不再需要手动定义`sk_common_regs`结构体。我们可以直接访问`sock`和`sk_common`结构体。

同时`in6_addr`结构体也包含在vmlinux.h中，我们也不再需要引入`linux/in6.h`头文件。

其余最大的改变在于从内核中读取数据的部分。

我们在core的版本中，主要使用了两个宏：

```c
BPF_CORE_READ
BPF_CORE_READ_INTO
```

这两个宏没什么本质的区别，只是一个直接返回值，另一个通过指针直接将数据写入缓冲区的区别。

**`BPF_CORE_READ`**是 libbpf 提供的一个重要宏，它的主要作用是实现 CO-RE (Compile Once - Run Everywhere) 中的结构体成员访问。

下面列出了在core和nonCore版本下，读取内核数据关键代码的差别：

```c
family = BPF_CORE_READ(sk, __sk_common.skc_family);
// bpf_probe_read_kernel(&family, sizeof(family), &sk->family);

event.L_port = BPF_CORE_READ(sk, __sk_common.skc_num);
event.R_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
// bpf_probe_read_kernel(&event.L_port, sizeof(event.L_port), &sk->skc_num);
// bpf_probe_read_kernel(&event.R_port, sizeof(event.R_port), &sk->skc_dport);
// event.R_port = bpf_ntohs(event.R_port);

BPF_CORE_READ_INTO(&event.L_ip_v4, sk, __sk_common.skc_rcv_saddr);
BPF_CORE_READ_INTO(&event.R_ip_v4, sk, __sk_common.skc_daddr);
// bpf_probe_read_kernel(&event.L_ip_v4, sizeof(event.L_ip_v4), &sk->skc_rcv_saddr);
// bpf_probe_read_kernel(&event.R_ip_v4, sizeof(event.R_ip_v4), &sk->skc_daddr);

BPF_CORE_READ_INTO(&event.L_ip_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
BPF_CORE_READ_INTO(&event.R_ip_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
// bpf_probe_read_kernel(&event.L_ip_v6, sizeof(event.L_ip_v6), &sk->skc_v6_rcv_saddr.in6_u.u6_addr32);
// bpf_probe_read_kernel(&event.R_ip_v6, sizeof(event.R_ip_v6), &sk->skc_v6_daddr.in6_u.u6_addr32);
```


## 源码

```bash
tree
.
├── CMakeLists.txt
├── core
│   ├── CMakeLists.txt
│   ├── tcpVision.bpf.c
│   ├── tcpVision.c
│   └── tcpVision.h
├── nat
│   ├── CMakeLists.txt
│   ├── nat.bpf.c
│   ├── nat.c
│   └── nat.h
└── nonCore
    ├── CMakeLists.txt
    ├── tcpVision.bpf.c
    ├── tcpVision.c
    └── tcpVision.h
```

[src](/downloads/2024-12-26/src)

