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
add_subdirectory(nat)