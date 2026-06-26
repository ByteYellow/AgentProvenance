//go:build ignore

// eBPF program: capture process exec (execve) via the sched_process_exec
// tracepoint and push a compact event to a ring buffer. CO-RE (uses vmlinux.h),
// compiled by bpf2go with clang. Linux-only; loaded by sensor_linux.go.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct exec_event {
	__u32 pid;
	__u32 ppid;
	__u8 comm[16];
	__u8 filename[256];
};

// Force bpf2go to emit the Go struct type for exec_event.
struct exec_event *unused_exec_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
	struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	unsigned int fname_off = ctx->__data_loc_filename & 0xffff;
	bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
