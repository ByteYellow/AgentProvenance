//go:build ignore

// eBPF programs for the self-owned system-telemetry sensor (CO-RE, compiled by
// bpf2go with clang). Process, file, network and TLS probes share a ring buffer.
// Each event carries pid/tgid/ppid/comm + the kernel cgroup id; the userspace
// loader (sensor_linux.go) enriches container_id from /proc/<pid>/cgroup and
// maps to the normalized telemetry schema. Linux-only.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
// bpf2go selects the register layout from its explicit amd64/arm64 target.
// Endianness alone is insufficient for uprobes: C and Go arguments are held
// in architecture-specific registers.
#if !defined(__TARGET_ARCH_arm64) && !defined(__TARGET_ARCH_x86)
#error "generate the sensor with an explicit amd64 or arm64 bpf2go target"
#endif
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EVENT_EXEC 1
#define EVENT_CONNECT 2
#define EVENT_OPEN 3
#define EVENT_EXIT 4
#define EVENT_SSL 5      // SSL_write: plaintext the agent sent (LLM request)
#define EVENT_SSL_READ 6 // SSL_read: plaintext the agent received (LLM response)
#define EVENT_SETUID 7   // setuid/setgid: privilege change (daddr: 0=uid,1=gid)
#define EVENT_PTRACE 8   // ptrace: process injection/inspection
#define EVENT_RENAME 9   // renameat2: file move/tamper
#define EVENT_UNLINK 10  // unlinkat: file delete
#define EVENT_DNS 11     // getaddrinfo uprobe: resolved hostname (egress by name)
#define EVENT_FORK 12
#define EVENT_SSL_RESET 13
#define EVENT_SSL_RELEASE 14
#define EVENT_SYSCALL_RESULT 15
#define EVENT_THREAD_EXIT 16
#define AF_INET 2

// argv is captured as fixed-size slots (constant offsets keep the BPF verifier
// happy on the per-arg write); each slot holds one NUL-terminated, possibly
// truncated arg. Userspace rejoins non-empty slots with spaces.
#define ARG_SLOT 32
#define MAX_ARGS 16
#define ARGS_BUF (ARG_SLOT * MAX_ARGS)
#define SSL_CHUNK 256      // bytes captured per TLS chunk (= sizeof path[])
#define SSL_MAX_CHUNKS 16  // cap: up to SSL_CHUNK*SSL_MAX_CHUNKS bytes per SSL call

struct sensor_event {
	__u32 kind;
	__u32 pid;
	__u32 tid;
	__u32 ppid;
	__u64 cgroup_id;
	__u64 ktime_ns;  // capture time, independent of userspace/ingest backlog
	__u64 process_start_ns;
	__u64 parent_start_ns;
	__u64 thread_start_ns;
	__u64 syscall_start_ns;
	__s64 syscall_nr;
	__s64 syscall_result;
	__u32 syscall_kind;
	__u32 raw_exit_status;
	__u64 conn;      // tls: the SSL* pointer identifying the connection (reassembly key)
	__u64 conn_epoch; // OpenSSL capture generation; zero for untracked TLS stacks
	__u32 daddr;     // connect: dst IPv4 (net order); tls: valid bytes in this chunk
	__u16 dport;     // connect: dst port (net order); tls: 1 if the message was truncated at the chunk cap
	__s32 exit_code; // exit: process exit code; tls: total plaintext length of the call
	__u8 comm[16];
	__u8 path[256];      // exec filename / open path
	__u8 args[ARGS_BUF]; // exec: MAX_ARGS fixed slots of argv
};

// drops counts capture failures (including bounded read-context overflow), so
// userspace can surface a coverage gap instead of going silently blind.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

static __always_inline void count_drop(void) {
	__u32 z = 0;
	__u64 *d = bpf_map_lookup_elem(&drops, &z);
	if (d)
		__sync_fetch_and_add(d, 1);
}

// A process can have several simultaneous TLS readers. Keep independent,
// bounded stacks per pid_tgid, with task lifetime guarding against TID reuse.
#define SSL_READ_DEPTH 4
struct ssl_read_ctx {
	__u64 buf;
	__u64 ssl;
	__u64 capacity;
	__u64 readbytes;
	__u64 epoch;
};
struct ssl_read_stack {
	__u64 task_start;
	__u32 depth;
	__u32 reserved;
	struct ssl_read_ctx frames[SSL_READ_DEPTH];
};
#define SSL_READ_MAP(name) \
struct { \
	__uint(type, BPF_MAP_TYPE_HASH); \
	__uint(max_entries, 4096); \
	__type(key, __u64); \
	__type(value, struct ssl_read_stack); \
} name SEC(".maps")
SSL_READ_MAP(ssl_read_bufs);
SSL_READ_MAP(ssl_read_ex_bufs);

struct ssl_conn_key {
	__u64 start;
	__u64 conn;
	__u32 pid;
	__u32 reserved;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct ssl_conn_key);
	__type(value, __u64);
} ssl_epochs SEC(".maps");

// argv_scratch stashes a process's argv (captured at sys_enter_execve) keyed by
// pid, so the successful sched_process_exec emit can attach the real command
// line. exec doesn't change the pid between the two probes.
struct argv_val {
	__u8 args[ARGS_BUF];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct argv_val);
} argv_scratch SEC(".maps");

// Per-CPU scratch to build argv off the 512-byte BPF stack.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct argv_val);
} argv_build SEC(".maps");

// Force bpf2go to emit the Go struct type for sensor_event.
struct sensor_event *unused_sensor_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// One in-flight syscall per thread. Lifetime and syscall checks prevent a
// missing return/exec/exit from pairing a later call with a stale entry.
struct syscall_ctx {
	__u64 task_start_ns;
	__u64 start_ns;
	__s64 nr;
	__u64 path_ptr;
	__u64 flags;
	__u32 kind;
	__u32 daddr;
	__u16 dport;
	__u8 path_retry;
	__u8 reserved;
	char path[256];
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct syscall_ctx);
} syscall_calls SEC(".maps");

struct process_exit_key {
	__u64 start_ns;
	__u32 pid;
	__u32 reserved;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct process_exit_key);
	__type(value, __u8);
} exited_groups SEC(".maps");

#if defined(__TARGET_ARCH_x86)
// Cache the cgroup's kernel name while the task still exists. A short-lived Pod
// can lose BOTH /proc/PID and its cgroup directory before userspace drains the
// ring buffer. Retaining a bounded identity map makes late informer attribution
// possible without delaying the workload or guessing from timestamps.
struct cgroup_identity {
	char names[3][96];
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct cgroup_identity);
} cgroup_names SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cgroup_identity);
} cgroup_name_scratch SEC(".maps");

static __always_inline void capture_cgroup_identity(struct task_struct *task, __u64 id) {
	if (bpf_map_lookup_elem(&cgroup_names, &id))
		return;
	__u32 zero = 0;
	struct cgroup_identity *value = bpf_map_lookup_elem(&cgroup_name_scratch, &zero);
	if (!value)
		return;
	__builtin_memset(value, 0, sizeof(*value));
	struct cgroup *group = BPF_CORE_READ(task, cgroups, dfl_cgrp);
	// A different task can migrate this task between cgroups while we read
	// it. Never publish the new group's name under an earlier captured ID.
	if (!group || BPF_CORE_READ(group, kn, id) != id)
		return;
#pragma unroll
	for (int i = 0; i < 3; i++) {
		if (!group)
			break;
		const char *name = BPF_CORE_READ(group, kn, name);
		// Do not retain a failed/incomplete read as a permanent negative cache
		// entry. A valid empty root name returns 1 and can safely be cached.
		if (bpf_probe_read_kernel_str(value->names[i], sizeof(value->names[i]), name) <= 0)
			return;
		group = BPF_CORE_READ(group, self.parent, cgroup);
	}
	bpf_map_update_elem(&cgroup_names, &id, value, BPF_NOEXIST);
}
#endif

static __always_inline void fill_common(struct sensor_event *e) {
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u64 id = bpf_get_current_pid_tgid();
	e->pid = (__u32)(id >> 32);
	e->tid = (__u32)id;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->ktime_ns = bpf_ktime_get_ns();
	e->process_start_ns = BPF_CORE_READ(task, group_leader, start_time);
	e->parent_start_ns = BPF_CORE_READ(task, real_parent, group_leader, start_time);
	e->thread_start_ns = BPF_CORE_READ(task, start_time);
	e->syscall_start_ns = 0;
	e->syscall_nr = 0;
	e->syscall_result = 0;
	e->syscall_kind = 0;
	e->raw_exit_status = 0;
	e->conn_epoch = 0;
#if defined(__TARGET_ARCH_x86)
	capture_cgroup_identity(task, e->cgroup_id);
#endif
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// Capture process birth before a child can migrate or exit between polls.
// Thread clones share the leader identity and need no separate scope binding.
SEC("raw_tp/sched_process_fork")
int handle_fork(struct bpf_raw_tracepoint_args *ctx) {
	struct task_struct *child = (struct task_struct *)ctx->args[1];
	__u32 pid = BPF_CORE_READ(child, tgid);
	if (pid != BPF_CORE_READ(child, pid))
		return 0;
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) { count_drop(); return 0; }
	__builtin_memset(e, 0, sizeof(*e));
	fill_common(e);
	e->kind = EVENT_FORK;
	e->pid = pid;
	e->tid = pid;
	e->ppid = BPF_CORE_READ(child, real_parent, tgid);
	e->process_start_ns = BPF_CORE_READ(child, group_leader, start_time);
	e->thread_start_ns = BPF_CORE_READ(child, start_time);
	e->parent_start_ns = BPF_CORE_READ(child, real_parent, group_leader, start_time);
	// clone3(CLONE_INTO_CGROUP) can place the child in a different cgroup
	// before this tracepoint. The current task is still the parent here.
	struct cgroup *group = BPF_CORE_READ(child, cgroups, dfl_cgrp);
	e->cgroup_id = BPF_CORE_READ(group, kn, id);
#if defined(__TARGET_ARCH_x86)
	capture_cgroup_identity(child, e->cgroup_id);
#endif
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// Capture argv at execve entry into the per-pid scratch map. The space-joined
// command line is attached on the matching successful sched_process_exec.
SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
	__u32 zero = 0;
	struct argv_val *val = bpf_map_lookup_elem(&argv_build, &zero);
	if (!val)
		return 0;
	__builtin_memset(val->args, 0, sizeof(val->args));
	const char *const *argv = (const char *const *)ctx->args[1];
#pragma unroll
	for (int i = 0; i < MAX_ARGS; i++) {
		const char *argp = NULL;
		if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) || !argp)
			break;
		// Constant offset (i unrolled) and constant size -> verifier-safe.
		bpf_probe_read_user_str(&val->args[i * ARG_SLOT], ARG_SLOT, argp);
	}
	__u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	bpf_map_update_elem(&argv_scratch, &pid, val, BPF_ANY);
	return 0;
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
	// A successful exec replaces the address space without returning from TLS.
	// A non-leader exec also changes TID, so clear the pre-exec identity too.
	__u64 id = bpf_get_current_pid_tgid();
	__u64 old_id = (id & 0xffffffff00000000ULL) | (__u32)BPF_CORE_READ(ctx, old_pid);
	bpf_map_delete_elem(&syscall_calls, &id);
	bpf_map_delete_elem(&ssl_read_bufs, &id);
	bpf_map_delete_elem(&ssl_read_ex_bufs, &id);
	if (old_id != id) {
		bpf_map_delete_elem(&syscall_calls, &old_id);
		bpf_map_delete_elem(&ssl_read_bufs, &old_id);
		bpf_map_delete_elem(&ssl_read_ex_bufs, &old_id);
	}
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	e->exit_code = 0;
	e->kind = EVENT_EXEC;
	e->daddr = 0;
	e->dport = 0;
	fill_common(e);
	unsigned int off = ctx->__data_loc_filename & 0xffff;
	bpf_probe_read_kernel_str(&e->path, sizeof(e->path), (void *)ctx + off);
	struct argv_val *val = bpf_map_lookup_elem(&argv_scratch, &e->pid);
	if (val) {
		__builtin_memcpy(e->args, val->args, sizeof(e->args));
		bpf_map_delete_elem(&argv_scratch, &e->pid);
	} else {
		e->args[0] = 0;
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline void fill_syscall(struct sensor_event *e, struct syscall_ctx *call) {
	e->syscall_start_ns = call->start_ns;
	e->syscall_nr = call->nr;
	e->syscall_kind = call->kind;
}

SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&syscall_calls, &id);
	struct sockaddr_in sa = {};
	void *uaddr = (void *)ctx->args[1];
	if (bpf_probe_read_user(&sa, sizeof(sa), uaddr))
		return 0;
	if (sa.sin_family != AF_INET)
		return 0;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct syscall_ctx call = {
		.task_start_ns = BPF_CORE_READ(task, start_time),
		.start_ns = bpf_ktime_get_ns(), .nr = ctx->id,
		.kind = EVENT_CONNECT, .daddr = sa.sin_addr.s_addr, .dport = sa.sin_port,
	};
	if (bpf_map_update_elem(&syscall_calls, &id, &call, BPF_ANY))
		count_drop();
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	e->exit_code = 0;
	e->kind = EVENT_CONNECT;
	fill_common(e);
	fill_syscall(e, &call);
	e->daddr = sa.sin_addr.s_addr;
	e->dport = sa.sin_port;
	e->path[0] = 0;
	e->args[0] = 0;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// O_WRONLY|O_RDWR|O_CREAT|O_TRUNC -- only writes/creates, to avoid the firehose
// of read-only opens. (Sensitive-read detection is a separate, filtered probe.)
#define OPEN_WRITE_MASK (00000001 | 00000002 | 00000100 | 00001000)

// noise_read_prefix drops the high-volume read paths (shared libs, procfs, sysfs,
// device nodes, etc.) in-kernel so capturing READS does not firehose the ring
// buffer. It is a coarse NEGATIVE filter on the first path bytes (cheap, verifier
// friendly); userspace then POSITIVELY matches the small sensitive set. Writes
// are never dropped here.
static __always_inline int noise_read_prefix(const char *p) {
	if (p[0] != '/')
		return 0;
	char a = p[1], b = p[2], c = p[3];
	if (a == 'u' && b == 's' && c == 'r') return 1; // /usr
	if (a == 'l' && b == 'i' && c == 'b') return 1; // /lib
	if (a == 'p' && b == 'r' && c == 'o') return 1; // /proc
	if (a == 's' && b == 'y' && c == 's') return 1; // /sys
	if (a == 'd' && b == 'e' && c == 'v') return 1; // /dev
	if (a == 'r' && b == 'u' && c == 'n') return 1; // /run
	if (a == 's' && b == 'n' && c == 'a') return 1; // /snap
	return 0;
}

// noise_file_prefix extends noise_read_prefix with /var and /tmp: the container
// runtime (containerd/runc) does a storm of unlink/rename under /var/lib/docker,
// /run/containerd, /tmp/containerd-mount during setup/teardown. Without this the
// ring buffer floods and drops real events. Agent-relevant tamper is in
// /home,/root,/workspace,/app, which are kept.
static __always_inline int noise_file_prefix(const char *p) {
	if (noise_read_prefix(p))
		return 1;
	if (p[0] != '/')
		return 0;
	char a = p[1], b = p[2], c = p[3];
	if (a == 'v' && b == 'a' && c == 'r') return 1; // /var
	if (a == 't' && b == 'm' && c == 'p') return 1; // /tmp
	return 0;
}

static __always_inline int emit_open(const char *path, long flags, long nr) {
	__u64 id = bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&syscall_calls, &id);
	int is_write = (flags & OPEN_WRITE_MASK) != 0;
	// Filter noise reads BEFORE reserving: a discarded ringbuf record still
	// occupies space until drained, so the prefix check must precede reserve.
	if (!is_write) {
		char pfx[8] = {};
		bpf_probe_read_user(pfx, sizeof(pfx), path);
		if (noise_read_prefix(pfx))
			return 0;
	}
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct syscall_ctx call = {
		.task_start_ns = BPF_CORE_READ(task, start_time),
		.start_ns = bpf_ktime_get_ns(), .nr = nr, .kind = EVENT_OPEN,
		.path_ptr = (__u64)path, .flags = flags,
	};
	call.path_retry = bpf_probe_read_user_str(call.path, sizeof(call.path), path) <= 0;
	if (bpf_map_update_elem(&syscall_calls, &id, &call, BPF_ANY))
		count_drop();
	// The kernel may fault the pathname in before return. Keep that later
	// observation separate from paths already read at entry.
	if (call.path_retry)
		return 0;
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	e->kind = EVENT_OPEN;
	e->daddr = 0;
	e->dport = 0;
	fill_common(e);
	fill_syscall(e, &call);
	e->args[0] = 0;
	__builtin_memcpy(e->path, call.path, sizeof(e->path));
	e->exit_code = is_write ? 0 : 1; // 0 = write, 1 = read
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
	return emit_open((const char *)ctx->args[1], (long)ctx->args[2], ctx->id);
}

static __always_inline int emit_syscall_result(struct trace_event_raw_sys_exit *ctx, __u32 kind) {
	__u64 id = bpf_get_current_pid_tgid();
	struct syscall_ctx *p = bpf_map_lookup_elem(&syscall_calls, &id);
	if (!p)
		return 0;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (p->task_start_ns != BPF_CORE_READ(task, start_time) || p->nr != ctx->id || p->kind != kind) {
		bpf_map_delete_elem(&syscall_calls, &id);
		return 0;
	}
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		bpf_map_delete_elem(&syscall_calls, &id);
		return 0;
	}
	fill_common(e);
	fill_syscall(e, p);
	e->kind = EVENT_SYSCALL_RESULT;
	e->syscall_result = ctx->ret;
	e->exit_code = (p->flags & OPEN_WRITE_MASK) ? 0 : 1;
	e->daddr = p->daddr;
	e->dport = p->dport;
	e->args[0] = 0;
	__builtin_memcpy(e->path, p->path, sizeof(e->path));
	if (kind == EVENT_OPEN && p->path_retry) {
		// Retain the existing combined entry/retry record, with both timestamps.
		e->kind = EVENT_OPEN;
		e->dport = 1;
		e->conn = (__u64)ctx->ret;
		if (bpf_probe_read_user_str(e->path, sizeof(e->path), (void *)p->path_ptr) <= 0) {
			count_drop();
			bpf_ringbuf_discard(e, 0);
			bpf_map_delete_elem(&syscall_calls, &id);
			return 0;
		}
	}
	bpf_map_delete_elem(&syscall_calls, &id);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int handle_open_return(struct trace_event_raw_sys_exit *ctx) {
	return emit_syscall_result(ctx, EVENT_OPEN);
}

SEC("tp/syscalls/sys_exit_connect")
int handle_connect_return(struct trace_event_raw_sys_exit *ctx) {
	return emit_syscall_result(ctx, EVENT_CONNECT);
}

#if defined(__TARGET_ARCH_x86)
SEC("tp/syscalls/sys_enter_open")
int handle_open(struct trace_event_raw_sys_enter *ctx) {
	return emit_open((const char *)ctx->args[0], (long)ctx->args[1], ctx->id);
}
#endif

// A leader can exit while worker threads continue. Close the process lifetime
// only after all threads have left userspace; retain other exits as thread facts.
SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&syscall_calls, &id);
	bpf_map_delete_elem(&ssl_read_bufs, &id);
	bpf_map_delete_elem(&ssl_read_ex_bufs, &id);
	__u32 pid = (__u32)(id >> 32);
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u32 kind = EVENT_THREAD_EXIT;
	if (BPF_CORE_READ(task, signal, live.counter) == 0) {
		struct process_exit_key key = {.start_ns = BPF_CORE_READ(task, group_leader, start_time), .pid = pid};
		__u8 seen = 1;
		if (!bpf_map_update_elem(&exited_groups, &key, &seen, BPF_NOEXIST))
			kind = EVENT_EXIT;
		bpf_map_delete_elem(&argv_scratch, &pid);
	}
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	e->kind = kind;
	e->daddr = 0;
	e->dport = 0;
	fill_common(e);
	e->path[0] = 0;
	e->args[0] = 0;
	e->raw_exit_status = BPF_CORE_READ(task, exit_code);
	if (kind == EVENT_EXIT) {
		if (BPF_CORE_READ(task, signal, flags) & 0x4) // SIGNAL_GROUP_EXIT
			e->raw_exit_status = BPF_CORE_READ(task, signal, group_exit_code);
		else
			e->raw_exit_status = BPF_CORE_READ(task, group_leader, exit_code);
	}
	e->exit_code = (e->raw_exit_status >> 8) & 0xff;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// Privilege change: setuid/setgid. setuid(0) is the classic root escalation; a
// sandboxed agent that calls it is a red flag. daddr distinguishes uid vs gid.
SEC("tp/syscalls/sys_enter_setuid")
int handle_setuid(struct trace_event_raw_sys_enter *ctx) {
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	e->kind = EVENT_SETUID;
	e->daddr = 0; // uid
	e->dport = 0;
	fill_common(e);
	e->path[0] = 0;
	e->args[0] = 0;
	e->exit_code = (int)ctx->args[0]; // target uid
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_setgid")
int handle_setgid(struct trace_event_raw_sys_enter *ctx) {
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	e->kind = EVENT_SETUID;
	e->daddr = 1; // gid
	e->dport = 0;
	fill_common(e);
	e->path[0] = 0;
	e->args[0] = 0;
	e->exit_code = (int)ctx->args[0]; // target gid
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// ptrace: process injection / memory inspection -- a credential-theft and
// sandbox-escape vector. daddr carries the target pid, exit_code the request.
SEC("tp/syscalls/sys_enter_ptrace")
int handle_ptrace(struct trace_event_raw_sys_enter *ctx) {
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	e->kind = EVENT_PTRACE;
	e->daddr = (__u32)ctx->args[1]; // target pid
	e->dport = 0;
	fill_common(e);
	e->path[0] = 0;
	e->args[0] = 0;
	e->exit_code = (int)ctx->args[0]; // ptrace request
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// File rename/unlink: tampering, trace cleanup, exfil staging. We capture the
// source path (renameat2 oldname / unlinkat pathname).
// renameat/renameat2: oldname is args[1]. (Used by modern libc.)
SEC("tp/syscalls/sys_enter_renameat2")
int handle_rename(struct trace_event_raw_sys_enter *ctx) {
	char pfx[8] = {};
	bpf_probe_read_user(pfx, sizeof(pfx), (void *)ctx->args[1]); // oldname
	if (noise_file_prefix(pfx))
		return 0;
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	e->kind = EVENT_RENAME;
	e->daddr = 0;
	e->dport = 0;
	fill_common(e);
	e->args[0] = 0;
	e->exit_code = 0;
	bpf_probe_read_user_str(&e->path, sizeof(e->path), (void *)ctx->args[1]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// rename(2): oldname is args[0] (busybox/coreutils mv on the same filesystem).
SEC("tp/syscalls/sys_enter_rename")
int handle_rename_plain(struct trace_event_raw_sys_enter *ctx) {
	char pfx[8] = {};
	bpf_probe_read_user(pfx, sizeof(pfx), (void *)ctx->args[0]); // oldname
	if (noise_file_prefix(pfx))
		return 0;
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	e->kind = EVENT_RENAME;
	e->daddr = 0;
	e->dport = 0;
	fill_common(e);
	e->args[0] = 0;
	e->exit_code = 0;
	bpf_probe_read_user_str(&e->path, sizeof(e->path), (void *)ctx->args[0]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline int emit_unlink(const char *path) {
	char pfx[8] = {};
	bpf_probe_read_user(pfx, sizeof(pfx), path);
	if (noise_file_prefix(pfx))
		return 0;
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	e->kind = EVENT_UNLINK;
	e->daddr = 0;
	e->dport = 0;
	fill_common(e);
	e->args[0] = 0;
	e->exit_code = 0;
	bpf_probe_read_user_str(&e->path, sizeof(e->path), path);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_unlinkat")
int handle_unlink(struct trace_event_raw_sys_enter *ctx) {
	return emit_unlink((const char *)ctx->args[1]);
}

#if defined(__TARGET_ARCH_x86)
SEC("tp/syscalls/sys_enter_unlink")
int handle_unlink_plain(struct trace_event_raw_sys_enter *ctx) {
	return emit_unlink((const char *)ctx->args[0]);
}
#endif

// Universal DNS: a UDP query to port 53 carries the DNS message in the sendto
// buffer. We copy the raw bytes (exit_code = length) and parse the qname in
// userspace. This catches musl/busybox, Go's own resolver, and any app doing
// raw UDP:53 -- including INSIDE containers, which the libc uprobe below cannot.
SEC("tp/syscalls/sys_enter_sendto")
int handle_sendto(struct trace_event_raw_sys_enter *ctx) {
	void *buf = (void *)ctx->args[1];
	long len = (long)ctx->args[2];
	void *dest = (void *)ctx->args[4];
	if (!buf || !dest || len < 13)
		return 0;
	struct sockaddr_in sa = {};
	if (bpf_probe_read_user(&sa, sizeof(sa), dest))
		return 0;
	if (sa.sin_family != AF_INET || sa.sin_port != bpf_htons(53))
		return 0;
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	e->kind = EVENT_DNS;
	e->daddr = 0;
	e->dport = 0;
	fill_common(e);
	e->args[0] = 0;
	__u32 n = (__u32)len;
	if (n > 250)
		n = 250; // raw DNS bytes; exit_code carries the length for userspace
	e->exit_code = n;
	bpf_probe_read_user(&e->path, n, buf);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// DNS: a uprobe on libc getaddrinfo(node, ...) captures the HOSTNAME an app
// resolves -- the egress destination by name, not just the IP a connect reveals.
// Covers dynamically-linked glibc apps (Python, Node, curl); musl/static/Go
// resolve via other paths and are not seen here.
SEC("uprobe/getaddrinfo")
int BPF_UPROBE(handle_getaddrinfo, const char *node) {
	if (!node)
		return 0;
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	e->kind = EVENT_DNS;
	e->daddr = 0;
	e->dport = 0;
	fill_common(e);
	e->args[0] = 0;
	e->exit_code = 0;
	bpf_probe_read_user_str(&e->path, sizeof(e->path), node);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// Boundary tracing: uprobes on SSL_write/SSL_read and the modern *_ex variants
// capture the plaintext an agent sends/receives over TLS (the LLM
// request/response) without instrumenting it. Attached to a libssl path only
// when --ssl-lib is given. We emit the FULL buffer as ordered SSL_CHUNK-sized
// chunks keyed by the SSL* pointer (conn); userspace reassembles them into
// complete HTTP/1.1 or HTTP/2 messages.
static __always_inline __u64 ssl_epoch(__u64 conn, int rotate, int release) {
	if (!conn)
		return 0;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct ssl_conn_key key = {
		.start = BPF_CORE_READ(task, group_leader, start_time),
		.conn = conn, .pid = bpf_get_current_pid_tgid() >> 32,
	};
	__u64 *saved = bpf_map_lookup_elem(&ssl_epochs, &key);
	__u64 epoch = saved ? *saved : 0;
	if (release) {
		bpf_map_delete_elem(&ssl_epochs, &key);
		return epoch;
	}
	if (rotate || !epoch) {
		epoch = bpf_ktime_get_ns();
		// Concurrent first reads/writes must converge on one generation.
		long err = bpf_map_update_elem(&ssl_epochs, &key, &epoch, rotate ? BPF_ANY : BPF_NOEXIST);
		if (err && rotate) {
			bpf_map_delete_elem(&ssl_epochs, &key);
			count_drop();
			return 0;
		}
		saved = bpf_map_lookup_elem(&ssl_epochs, &key);
		if (!saved) {
			count_drop();
			return 0;
		}
		epoch = *saved;
	}
	return epoch;
}

static __always_inline void emit_ssl_boundary(__u64 conn, int release) {
	__u64 epoch = ssl_epoch(conn, !release, release);
	if (!epoch)
		return;
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return;
	}
	fill_common(e);
	e->kind = release ? EVENT_SSL_RELEASE : EVENT_SSL_RESET;
	e->conn = conn;
	e->conn_epoch = epoch;
	e->daddr = e->dport = e->exit_code = 0;
	e->path[0] = e->args[0] = 0;
	bpf_ringbuf_submit(e, 0);
}

SEC("uretprobe/SSL_new")
int BPF_URETPROBE(handle_ssl_new, void *ssl) {
	emit_ssl_boundary((__u64)ssl, 0);
	return 0;
}

// Conservatively invalidate at clear/BIO/FD mutation entry, even if the call
// later fails or changes only a reference. This is a capture boundary, not a
// claim that a TCP connection closed. Chunk epochs survive lost boundary events.
SEC("uprobe/SSL_clear")
int BPF_UPROBE(handle_ssl_reset, void *ssl) {
	emit_ssl_boundary((__u64)ssl, 0);
	return 0;
}

SEC("uprobe/SSL_free")
int BPF_UPROBE(handle_ssl_release, void *ssl) {
	emit_ssl_boundary((__u64)ssl, 1);
	return 0;
}

static __always_inline void emit_ssl_chunks(__u32 kind, __u64 conn, __u64 epoch, const char *buf, int total) {
	for (int i = 0; i < SSL_MAX_CHUNKS; i++) {
		int off = i * SSL_CHUNK;
		if (off >= total)
			break;
		// off < total here, so total - off > 0: cast to unsigned so the verifier
		// knows the read size is non-negative, then clamp to the 256B path[].
		__u32 len = (__u32)(total - off);
		if (len > SSL_CHUNK)
			len = SSL_CHUNK; // len in [1, SSL_CHUNK]
		struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (!e) {
			count_drop();
			return;
		}
		e->kind = kind;
		e->conn = conn;
		e->daddr = len; // valid bytes in this chunk's path[]
		e->dport = (total > SSL_CHUNK * SSL_MAX_CHUNKS && i == SSL_MAX_CHUNKS - 1) ? 1 : 0;
		e->exit_code = total;
		fill_common(e);
		e->conn_epoch = epoch;
		e->args[0] = 0;
		if (bpf_probe_read_user(&e->path, len, buf + off)) {
			bpf_ringbuf_discard(e, 0);
			count_drop();
			return;
		}
		bpf_ringbuf_submit(e, 0);
	}
}

SEC("uprobe/SSL_write")
int BPF_UPROBE(handle_ssl_write, void *ssl, const void *buf, int num) {
	if (!buf || num <= 0)
		return 0;
	emit_ssl_chunks(EVENT_SSL, (__u64)ssl, ssl_epoch((__u64)ssl, 0, 0), (const char *)buf, num);
	return 0;
}

#if defined(__TARGET_ARCH_x86)
// Go ABIInternal on amd64 passes (*Conn, []byte) in AX, BX, CX, DI.
// System V C uses DI, SI, DX, so the OpenSSL uprobe cannot be reused here.
// Go goroutine stack movement makes uretprobes unsafe. Read uses ordinary
// uprobes at decoded RET instructions instead; these never change a return PC.
SEC("uprobe/go_tls_write")
int handle_go_tls_write(struct pt_regs *ctx) {
	__u64 conn = ctx->ax;
	const char *buf = (const char *)ctx->bx;
	__u64 len = ctx->cx;
	if (!buf || len == 0 || len > (1u << 20))
		return 0;
	emit_ssl_chunks(EVENT_SSL, conn, 0, buf, (int)len);
	return 0;
}

// R14 holds runtime.g in the supported amd64 Go ABIInternal. Its first two
// words are stack.lo and stack.hi. A goroutine may resume on a different OS
// thread, so a thread ID cannot pair Read entry and completion. Distance from
// stack.hi to the entry SP also stays stable when Go grows/copies the stack,
// distinguishes nested calls, and lets a repeated entry after morestack replace
// the same invocation instead of creating an unmatched extra frame.
struct go_read_key {
	__u64 process;
	__u64 goroutine;
	__u64 frame;
};

struct go_read_ctx {
	__u64 conn;
	__u64 buf;
	__u64 len;
	__u64 stack_buf_offset; // zero for a heap-backed slice
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct go_read_key);
	__type(value, struct go_read_ctx);
} go_read_bufs SEC(".maps");

static __always_inline int go_read_frame(struct pt_regs *ctx,
		struct go_read_key *key, __u64 *lo, __u64 *hi) {
	__u64 g = ctx->r14;
	if (!g || bpf_probe_read_user(lo, sizeof(*lo), (void *)g) ||
		bpf_probe_read_user(hi, sizeof(*hi), (void *)(g + 8)) ||
		ctx->sp < *lo || ctx->sp >= *hi)
		return -1;
	key->process = bpf_get_current_pid_tgid() >> 32;
	key->goroutine = g;
	key->frame = *hi - ctx->sp;
	return 0;
}

SEC("uprobe/go_tls_read_enter")
int handle_go_tls_read_enter(struct pt_regs *ctx) {
	struct go_read_key key = {};
	__u64 lo = 0, hi = 0;
	if (go_read_frame(ctx, &key, &lo, &hi)) {
		count_drop();
		return 0;
	}
	struct go_read_ctx state = {
		.conn = ctx->ax, .buf = ctx->bx, .len = ctx->cx,
	};
	if (state.buf >= lo && state.buf < hi)
		state.stack_buf_offset = hi - state.buf;
	if (bpf_map_update_elem(&go_read_bufs, &key, &state, BPF_ANY))
		count_drop();
	return 0;
}

SEC("uprobe/go_tls_read_return")
int handle_go_tls_read_return(struct pt_regs *ctx) {
	struct go_read_key key = {};
	__u64 lo = 0, hi = 0;
	if (go_read_frame(ctx, &key, &lo, &hi)) {
		count_drop();
		return 0;
	}
	struct go_read_ctx *saved = bpf_map_lookup_elem(&go_read_bufs, &key);
	if (!saved) {
		// Includes bounded-map eviction or attaching during an in-flight Read.
		count_drop();
		return 0;
	}
	struct go_read_ctx state = *saved;
	bpf_map_delete_elem(&go_read_bufs, &key);
	// AX is n, BX/CX are error. n bytes are valid even when error is non-nil.
	__s64 n = (__s64)ctx->ax;
	if (n <= 0)
		return 0;
	if ((__u64)n > state.len || n > 0x7fffffff) {
		count_drop();
		return 0;
	}
	if (state.stack_buf_offset) {
		if (state.stack_buf_offset > hi - lo) {
			count_drop();
			return 0;
		}
		state.buf = hi - state.stack_buf_offset;
	}
	emit_ssl_chunks(EVENT_SSL_READ, state.conn, 0, (const char *)state.buf, (int)n);
	return 0;
}
#endif

#if defined(__TARGET_ARCH_arm64)
// ARM64 Go ABIInternal uses R0/R1/R2 for this receiver and slice. Keep the
// plaintext probe separate from OpenSSL lifecycle tracking.
SEC("uprobe/go_tls_write")
int BPF_UPROBE(handle_go_tls_write, void *conn, const void *buf, __u64 num) {
	if (buf && num > 0 && num <= 0x7fffffff)
		emit_ssl_chunks(EVENT_SSL, (__u64)conn, 0, (const char *)buf, (int)num);
	return 0;
}
#endif

// SSL_write_ex(ssl, buf, num, *written): the size_t-taking variant modern
// OpenSSL 3.x clients use (notably CPython's _ssl, which never calls SSL_write).
// The plaintext is in buf at entry, exactly like SSL_write, so we emit here and
// ignore the *written out-param. num is size_t; clamp before the signed emit.
SEC("uprobe/SSL_write_ex")
int BPF_UPROBE(handle_ssl_write_ex, void *ssl, const void *buf, __u64 num) {
	if (!buf || num == 0 || num > (1u << 20))
		return 0;
	emit_ssl_chunks(EVENT_SSL, (__u64)ssl, ssl_epoch((__u64)ssl, 0, 0), (const char *)buf, (int)num);
	return 0;
}

static __always_inline void push_ssl_read(void *map, struct ssl_read_ctx *call) {
	__u64 id = bpf_get_current_pid_tgid();
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u64 start = BPF_CORE_READ(task, start_time);
	struct ssl_read_stack *stack = bpf_map_lookup_elem(map, &id);
	if (!stack || stack->task_start != start) {
		struct ssl_read_stack fresh = {.task_start = start};
		if (bpf_map_update_elem(map, &id, &fresh, BPF_ANY)) {
			count_drop();
			return;
		}
		stack = bpf_map_lookup_elem(map, &id);
		if (!stack) {
			count_drop();
			return;
		}
	}
	__u32 depth = stack->depth;
	// Retain skipped depth so an overflowing inner return cannot pop an outer
	// buffer. Saturation poisons this thread's stack until exit instead of wrap.
	if (depth == ~0u) {
		count_drop();
		return;
	}
	stack->depth = depth + 1;
	if (depth >= SSL_READ_DEPTH) {
		count_drop();
		return;
	}
	stack->frames[depth] = *call;
}

static __always_inline int pop_ssl_read(void *map, struct ssl_read_ctx *call) {
	__u64 id = bpf_get_current_pid_tgid();
	struct ssl_read_stack *stack = bpf_map_lookup_elem(map, &id);
	if (!stack)
		return 0;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (stack->task_start != BPF_CORE_READ(task, start_time) || !stack->depth) {
		bpf_map_delete_elem(map, &id);
		count_drop();
		return 0;
	}
	if (stack->depth == ~0u)
		return 0;
	__u32 depth = stack->depth - 1;
	stack->depth = depth;
	if (depth >= SSL_READ_DEPTH)
		return 0;
	*call = stack->frames[depth];
	if (!depth)
		bpf_map_delete_elem(map, &id);
	return 1;
}

// SSL_read's return value is the byte count; failed reads still pop a frame.

SEC("uprobe/SSL_read")
int BPF_UPROBE(handle_ssl_read_enter, void *ssl, void *buf, int num) {
	struct ssl_read_ctx c = {
		.buf = (__u64)buf, .ssl = (__u64)ssl,
		.capacity = num > 0 ? (__u64)num : 0,
		.epoch = ssl_epoch((__u64)ssl, 0, 0),
	};
	push_ssl_read(&ssl_read_bufs, &c);
	return 0;
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(handle_ssl_read_exit, int ret) {
	struct ssl_read_ctx c = {};
	if (!pop_ssl_read(&ssl_read_bufs, &c) || ret <= 0)
		return 0;
	if (!c.buf || (__u64)ret > c.capacity) {
		count_drop();
		return 0;
	}
	emit_ssl_chunks(EVENT_SSL_READ, c.ssl, c.epoch, (const char *)c.buf, ret);
	return 0;
}

// SSL_read_ex(ssl, buf, num, *readbytes): the modern variant. Unlike SSL_read,
// the byte count is written to *readbytes (not the return value, which is 1/0
// success), so we stash the out-param pointer at entry and read *readbytes on
// return. Independent stacks keep the legacy and *_ex ABIs separate.

SEC("uprobe/SSL_read_ex")
int BPF_UPROBE(handle_ssl_read_ex_enter, void *ssl, void *buf, __u64 num, __u64 *readbytes) {
	struct ssl_read_ctx c = {
		.buf = (__u64)buf, .ssl = (__u64)ssl,
		.capacity = num, .readbytes = (__u64)readbytes,
		.epoch = ssl_epoch((__u64)ssl, 0, 0),
	};
	push_ssl_read(&ssl_read_ex_bufs, &c);
	return 0;
}

SEC("uretprobe/SSL_read_ex")
int BPF_URETPROBE(handle_ssl_read_ex_exit, int ret) {
	struct ssl_read_ctx c = {};
	if (!pop_ssl_read(&ssl_read_ex_bufs, &c) || ret != 1)
		return 0;
	__u64 n = 0;
	if (!c.buf || bpf_probe_read_user(&n, sizeof(n), (void *)c.readbytes) ||
		n > c.capacity || n > (1u << 20)) {
		count_drop();
		return 0;
	}
	if (n)
		emit_ssl_chunks(EVENT_SSL_READ, c.ssl, c.epoch, (const char *)c.buf, (int)n);
	return 0;
}
