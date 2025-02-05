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
