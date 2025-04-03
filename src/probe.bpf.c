#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include <yeet/yeet.h>

#include "exitsnoop.h"

RINGBUF_CHANNEL(exit_event_rb, RINGBUF_SIZE * sizeof(struct exit_event), exit_event);

SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(struct trace_event_raw_sched_process_template* ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();

  struct exit_event* ret = bpf_ringbuf_reserve(&exit_event_rb, sizeof(struct exit_event), 0);
  if (!ret) {
    return EXIT_FAILURE;
  }
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct task_struct* parent = BPF_CORE_READ(task, real_parent);

  const char* name = BPF_CORE_READ(task, cgroups, subsys[memory_cgrp_id], cgroup, kn, name);
  bpf_probe_read_kernel_str(&ret->cgroup_name, sizeof(ret->cgroup_name), name);

  bpf_get_current_comm(&ret->comm, sizeof(ret->comm));

  ret->pid = pid_tgid >> 32;
  ret->tgid = pid_tgid & ONES(32);
  ret->ppid = BPF_CORE_READ(parent, pid);
  ret->uid = bpf_get_current_uid_gid() & ONES(32);
  ret->gid = bpf_get_current_uid_gid() >> 32;
  ret->cgroup_id = bpf_get_current_cgroup_id();
  
  // For the exit code, we need to get it from the task struct
  ret->exit_code = BPF_CORE_READ(task, exit_code) >> 8;  // The exit code is in the high byte

  bpf_ringbuf_submit(ret, 0);
  return EXIT_SUCCESS;
}

LICENSE("Dual BSD/GPL"); 