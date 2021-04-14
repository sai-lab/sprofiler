#include "vmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 32

const volatile u64 target_cgid = 51097;

struct sys_enter_event_t {
  uid_t uid;
  __u64 cgid;
  long syscall_nr;
  char comm[TASK_COMM_LEN];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(int));
  __uint(value_size, sizeof(u32));
} sys_enter_events SEC(".maps");

static __always_inline bool is_trace_target() {
  u64 cgid = bpf_get_current_cgroup_id();

  if (target_cgid != 0 && cgid != target_cgid) {
    return false;
  }

  return true;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct trace_event_raw_sys_enter *ctx) {

  if (!is_trace_target())
    return 0;

  struct sys_enter_event_t event = {};

  event.uid = bpf_get_current_uid_gid();
  event.cgid = bpf_get_current_cgroup_id();
  event.syscall_nr = ctx->id;
  bpf_get_current_comm(&event.comm, TASK_COMM_LEN);

  bpf_perf_event_output(ctx, &sys_enter_events, BPF_F_CURRENT_CPU, &event,
                        sizeof(event));
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
