cmake_minimum_required(VERSION 3.10)
project(nat)

set(app_stem "nat")

bpf_object(${app_stem} ${app_stem}.bpf.c)
add_dependencies(${app_stem}_skel libbpf-build bpftool-build)

add_executable(${app_stem} ${app_stem}.c)
target_link_libraries(${app_stem} ${app_stem}_skel)