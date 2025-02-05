#include "nat.h"
#include "nat.skel.h"
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
    struct nat *event = data;
    char src_ip_old[INET_ADDRSTRLEN];
    char dst_ip_old[INET_ADDRSTRLEN];
    char src_ip_new[INET_ADDRSTRLEN];
    char dst_ip_new[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &event->src_ip_old, src_ip_old, sizeof(src_ip_old));
    inet_ntop(AF_INET, &event->dst_ip_old, dst_ip_old, sizeof(dst_ip_old));
    inet_ntop(AF_INET, &event->src_ip_new, src_ip_new, sizeof(src_ip_new));
    inet_ntop(AF_INET, &event->dst_ip_new, dst_ip_new, sizeof(dst_ip_new));
    
    printf("Process: %-16s\nold: %-15s:%-5d  -->> %-15s:%-5d\nnew: %-15s:%-5d  -->> %-15s:%-5d\n------\n", 
        event->comm,
        src_ip_old, ntohs(event->src_port_old),  dst_ip_old, ntohs(event->dst_port_old), 
        src_ip_new, ntohs(event->src_port_new),  dst_ip_new, ntohs(event->dst_port_new)
    );
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
    fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}


int main(int argc, char **argv)
{
    struct nat_bpf *obj;
    struct perf_buffer *pb = NULL;
    int err;

    // 打开eBPF对象
    obj = nat_bpf__open();
    if (libbpf_get_error(obj))
    {
        fprintf(stderr, "Failed to open eBPF object.\n");
        return 1;
    }

    // 加载和验证eBPF程序
    err = nat_bpf__load(obj);
    if (err)
    {
        fprintf(stderr, "Failed to load eBPF object.\n");
        goto cleanup;
    }

    // 挂载eBPF程序
    err = nat_bpf__attach(obj);
    if (err)
    {
        fprintf(stderr, "Failed to load eBPF object.\n");
        goto cleanup;
    }

    pb = perf_buffer__new(bpf_map__fd(obj->maps.nat_sessions),
                          PERF_BUFFER_PAGES,
                          handle_event,
                          handle_lost_events,
                          NULL, NULL);
    if (!pb)
    {
        fprintf(stderr, "failed to open perf buffer: %d\n", errno);
        goto cleanup;
    }
    fprintf(stdout, "running start...\n");
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
    nat_bpf__destroy(obj);

    return err != 0;
}
