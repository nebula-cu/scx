/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Rorke: A special purpose scheduler for hypervisors
 * TODO: Add a proper description
 *
 * Copyright(C) 2024 Vahab Jabrayilov<vjabrayilov@cs.columbia.edu>
 * Influenced by the scx_central & scx_bpfland schedulers
 */

#include <scx/common.bpf.h>
#include <scx/ravg_impl.bpf.h>
#include "intf.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>
#include <stdbool.h>

#include "intf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * Following are parameters to scheduler and  set again during initialization.
 * Here we assign values just to pass the verifier.
 */
const volatile u32 nr_cpus = 1;
const volatile u32 nr_vms = 1;
const volatile u64 timer_interval_ns = 100000;
const volatile u64 vms[MAX_VMS];
const volatile u32 debug = 0;

/* Scheduling statistics */
volatile u64 nr_direct_to_idle_dispatches, nr_kthread_dispatches,
    nr_vm_dispatches, nr_running;

/*
 * Timer for preempting CPUs.
 */
struct timer_ctx {
  struct bpf_timer timer;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, MAX_CPUS);
  __type(key, u32);
  __type(value, struct timer_ctx);
} timers SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, struct cpu_ctx);
  __uint(max_entries, 1);
} cpu_ctx_stor SEC(".maps");

/*
 * Return a CPU context.
 */
struct cpu_ctx* try_lookup_cpu_ctx(s32 cpu) {
  const u32 idx = 0;
  return bpf_map_lookup_percpu_elem(&cpu_ctx_stor, &idx, cpu);
}

/*
 * Return true if the target task @p is a kernel thread.
 */
static inline bool is_kthread(const struct task_struct* p) {
  return p->flags & PF_KTHREAD;
}

static s32 pick_idle_cpu(struct task_struct* p, s32 prev_cpu, u64 wake_flags) {
  if (scx_bpf_test_and_clear_cpu_idle(prev_cpu))
    return prev_cpu;

  if (p->nr_cpus_allowed == 1 || p->migration_disabled)
    return -EBUSY;

  return scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
}

s32 BPF_STRUCT_OPS(rorke_select_cpu,
                   struct task_struct* p,
                   s32 prev_cpu,
                   u64 wake_flags) {
  s32 cpu;
  s32 pid = p->pid;
  s32 tgid = p->tgid;
  trace("rorke_select_cpu: VM: %d, vCPU: %d, prev_cpu: %d", tgid, pid,
        prev_cpu);

  cpu = pick_idle_cpu(p, prev_cpu, wake_flags);
  if (cpu >= 0) {
    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_INF, 0);
    __sync_fetch_and_add(&nr_direct_to_idle_dispatches, 1);
    dbg("rorke_select_cpu: VM: %d, vCPU: %d, prev_cpu: %d direct dispatch to "
        "idle cpu: %d",
        p->tgid, p->pid, prev_cpu, cpu);
    return cpu;
  }

  dbg("rorke_enqueue: enqueued VM: %d vCPU: %d", tgid, pid);
  scx_bpf_dsq_insert(p, tgid, SCX_SLICE_INF, 0);
  __sync_fetch_and_add(&nr_vm_dispatches, 1);
  return prev_cpu;
}

/*
 * Wake up an idle CPU for task @p.
 * It triggers scheduling cycle there.
 */
static void kick_task_cpu(struct task_struct* p) {
  s32 cpu = scx_bpf_task_cpu(p);
  cpu = pick_idle_cpu(p, cpu, 0);

  if (cpu >= 0) {
    scx_bpf_kick_cpu(cpu, 0);
    trace("kick_task_cpu: woke up CPU: %d for VM: %d, vCPU: %d", cpu, p->tgid,
          p->pid);
  } else
    trace("kick_task_cpu: no idle CPU for VM: %d, vCPU: %d", p->tgid, p->pid);
}

/*
 * Dispatch all the other tasks that were not dispatched directly in
 * select_cpu().
 */
void BPF_STRUCT_OPS(rorke_enqueue, struct task_struct* p, u64 enq_flags) {
  s32 pid = p->pid;
  s32 tgid = p->tgid;

  /*
   * Push per-cpu kthreads at the head of local dsq's and preempt the
   * corresponding CPU. This ensures that e.g. ksoftirqd isn't blocked
   * behind other threads which is necessary for forward progress
   * guarantee as we depend on the BPF timer which may run from ksoftirqd.
   */
  if (is_kthread(p) && p->nr_cpus_allowed == 1) {
    trace("rorke_enqueue: enqueued local kthread %d", pid);
    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_INF,
                       enq_flags | SCX_ENQ_PREEMPT);
    __sync_fetch_and_add(&nr_kthread_dispatches, 1);
    return;
  }

  scx_bpf_dsq_insert(p, tgid, SCX_SLICE_INF, enq_flags);
  trace("rorke_enqueue: enqueued VM: %d vCPU: %d", tgid, pid);
  __sync_fetch_and_add(&nr_vm_dispatches, 1);

  /*
   * If there is an idle cpu available for the task, wake it up.
   */
  kick_task_cpu(p);
}

void BPF_STRUCT_OPS(rorke_dispatch, s32 cpu, struct task_struct* prev) {
  if (prev)
    trace("rorke_dispatch: CPU: %d VM: %d vCPU: %d", cpu, prev->tgid,
          prev->pid);

  struct cpu_ctx* cctx = try_lookup_cpu_ctx(cpu);
  if (!cctx)
    return;

  s32 vm_id = cctx->vm_id;
  if (vm_id == 0) {
    return;
  }

  if (scx_bpf_dsq_move_to_local(vm_id)) {
    trace("rorke_dispatch: consumed from VM - %d", vm_id);
    return;
  }
  dbg("rorke_dispatch: VM-%d queue empty...", vm_id);
}

void BPF_STRUCT_OPS(rorke_running, struct task_struct* p) {
  trace("rorke_running: VM: %d, vCPU: %d", p->tgid, p->pid);
  __sync_fetch_and_add(&nr_running, 1);

  /* Start the timer for the CPU */

  s32 cpu = scx_bpf_task_cpu(p);
  struct bpf_timer* timer = bpf_map_lookup_elem(&timers, &cpu);
  if (!timer) {
    scx_bpf_error("Failed to lookup timer for cpu - %d", cpu);
    return;
  }

  int ret = bpf_timer_start(timer, timer_interval_ns, BPF_F_TIMER_CPU_PIN);
  if (ret == -EINVAL) {
    scx_bpf_error("Failed to pin timer for cpu - %d", cpu);
    return;
  }
  trace("Started timer for cpu - %d", cpu);
}

void BPF_STRUCT_OPS(rorke_stopping, struct task_struct* p, bool runnable) {
  trace("rorke_stopping: VM: %d, vCPU: %d, runnable: %d", p->tgid, p->pid,
        runnable);
  __sync_fetch_and_sub(&nr_running, 1);
}

static int timer_callback(void* map, int* key, struct bpf_timer* timer) {
  struct cpu_ctx* cctx;

  s32 current_cpu = bpf_get_smp_processor_id();
  cctx = try_lookup_cpu_ctx(current_cpu);
  if (cctx)
    cctx->preempted++;

  scx_bpf_kick_cpu(current_cpu, SCX_KICK_PREEMPT);
  trace("timer_callback: preempted CPU %d", current_cpu);
  return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(rorke_init) {
  int ret;
  u32 i;

  bpf_for(i, 0, nr_vms) {
    ret = scx_bpf_create_dsq(vms[i], -1);
    if (ret) {
      scx_bpf_error("rorke_init: failed to create dsq for VM-%lld", vms[i]);
      return ret;
    }
    info("rorke_init: created dsq for VM-%d", vms[i]);
  }

  struct bpf_timer* timer;
  bpf_for(i, 0, nr_cpus) {
    timer = bpf_map_lookup_elem(&timers, &i);
    if (!timer) {
      scx_bpf_error("rorke_init: failed to lookup timer");
      return -ESRCH;
    }
    bpf_timer_init(timer, &timers, CLOCK_MONOTONIC);
    bpf_timer_set_callback(timer, timer_callback);
    info("rorke_init: initialized timer for cpu - %d\n", i);
  }
  return ret;
}

void BPF_STRUCT_OPS(rorke_exit, struct scx_exit_info* ei) {
  info("Exiting rorke");
  UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(rorke,
               /*
                * We are offloading all scheduling decisions to the central CPU
                * and thus being the last task on a given CPU doesn't mean
                * anything special. Enqueue the last tasks like any other tasks.
                */

               // .flags = SCX_OPS_ENQ_LAST,
               .select_cpu = (void*)rorke_select_cpu,
               .enqueue = (void*)rorke_enqueue,
               .dispatch = (void*)rorke_dispatch,
               .running = (void*)rorke_running,
               .stopping = (void*)rorke_stopping,
               .init = (void*)rorke_init,
               .exit = (void*)rorke_exit,
               .name = "rorke");
