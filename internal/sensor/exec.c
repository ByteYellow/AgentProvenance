//go:build ignore

// eBPF programs for the self-owned system-telemetry sensor (CO-RE, compiled by
// bpf2go with clang). Three probes -> one ring buffer:
//   - sched_process_exec   -> execve
//   - sys_enter_connect     -> network_connect (AF_INET)
//   - sys_enter_openat      -> file_open
// Each event carries pid/tgid/ppid/comm + the kernel cgroup id; the userspace
// loader (sensor_linux.go) enriches container_id from /proc/<pid>/cgroup and
// maps to the normalized telemetry schema. Linux-only.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define EVENT_EXEC 1
#define EVENT_CONNECT 2
#define EVENT_OPEN 3
#define AF_INET 2

struct sensor_event {
	__u32 kind;
	__u32 pid;
	__u32 tgid;
	__u32 ppid;
	__u64 cgroup_id;
	__u32 daddr; // connect: dst IPv4, network byte order
	__u16 dport; // connect: dst port, network byte order
	__u8 comm[16];
	__u8 path[256]; // exec filename / open path
};

// Force bpf2go to emit the Go struct type for sensor_event.
struct sensor_event *unused_sensor_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline void fill_common(struct sensor_event *e) {
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u64 id = bpf_get_current_pid_tgid();
	e->pid = (__u32)(id >> 32);
	e->tgid = (__u32)id;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->cgroup_id = bpf_get_current_cgroup_id();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	e->kind = EVENT_EXEC;
	e->daddr = 0;
	e->dport = 0;
	fill_common(e);
	unsigned int off = ctx->__data_loc_filename & 0xffff;
	bpf_probe_read_kernel_str(&e->path, sizeof(e->path), (void *)ctx + off);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx) {
	struct sockaddr_in sa = {};
	void *uaddr = (void *)ctx->args[1];
	if (bpf_probe_read_user(&sa, sizeof(sa), uaddr))
		return 0;
	if (sa.sin_family != AF_INET)
		return 0;
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	e->kind = EVENT_CONNECT;
	fill_common(e);
	e->daddr = sa.sin_addr.s_addr;
	e->dport = sa.sin_port;
	e->path[0] = 0;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// O_WRONLY|O_RDWR|O_CREAT|O_TRUNC — only writes/creates, to avoid the firehose
// of read-only opens. (Sensitive-read detection is a separate, filtered probe.)
#define OPEN_WRITE_MASK (00000001 | 00000002 | 00000100 | 00001000)

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
	long flags = (long)ctx->args[2];
	if (!(flags & OPEN_WRITE_MASK))
		return 0;
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	e->kind = EVENT_OPEN;
	e->daddr = 0;
	e->dport = 0;
	fill_common(e);
	bpf_probe_read_user_str(&e->path, sizeof(e->path), (void *)ctx->args[1]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
