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
 * Followings are parameters to scheduler and set again during initialization.
 * Here we assign values just to pass the verifier.
 */
const volatile u32 central_cpu = 0;
const volatile u32 nr_cpus = 1;
const volatile u32 nr_vms = 1;
const volatile u64 timer_interval_ns = 100000;
const volatile u64 realloc_cycles = 0; // do not realloc by default
const volatile u64 vms[MAX_VMS];
const volatile u32 debug = 0;

/* Scheduling statistics */
volatile u64 nr_direct_to_idle_dispatches, nr_kthread_dispatches,
    nr_vm_dispatches, nr_running;

volatile u64 realloc_cnt = 0;

/*
 * Timer for preempting CPUs.
 */
struct global_timer {
  struct bpf_timer timer;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct global_timer);
} global_timer SEC(".maps");

bool timer_pinned = true;

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
//   s32 pid = p->pid;
//   s32 tgid = p->tgid;

//   // Storing the information about cpu in cpu_ctx seems inefficient, since we need to query that every time.
  
//   struct cpu_ctx* cctx = try_lookup_cpu_ctx(prev_cpu);
//   if (!cctx) {
//     trace("pick_idle_cpu: cpu ctx lookup failed");
//   } else {
//     if (cctx->vm_id == tgid) {
//       return prev_cpu;
//     }
//   }

  

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
    scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_INF, 0);
    __sync_fetch_and_add(&nr_direct_to_idle_dispatches, 1);
    dbg("rorke_select_cpu: VM: %d, vCPU: %d, prev_cpu: %d direct dispatch to "
        "idle cpu: %d",
        p->tgid, p->pid, prev_cpu, cpu);

    return cpu;
  }

  dbg("rorke_enqueue: enqueued VM: %d vCPU: %d", tgid, pid);
  scx_bpf_dispatch(p, tgid, SCX_SLICE_INF, 0);
  __sync_fetch_and_add(&nr_vm_dispatches, 1);

  return prev_cpu;
}

/*
 * Wake up an idle CPU for task @p.
 */
static void kick_task_cpu(struct task_struct* p) {
  s32 cpu = scx_bpf_task_cpu(p);

  cpu = pick_idle_cpu(p, cpu, 0);
  if (cpu >= 0)
    scx_bpf_kick_cpu(cpu, 0);
  else
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
    scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_INF,
                     enq_flags | SCX_ENQ_PREEMPT);
    __sync_fetch_and_add(&nr_kthread_dispatches, 1);
    return;
  }

  trace("rorke_enqueue: enqueued VM: %d vCPU: %d", tgid, pid);
  scx_bpf_dispatch(p, tgid, SCX_SLICE_INF, enq_flags);
  __sync_fetch_and_add(&nr_vm_dispatches, 1);

  /*
   * If there is an idle cpu available for the task, wake it up.
   */
  kick_task_cpu(p);
}

void BPF_STRUCT_OPS(rorke_dispatch, s32 cpu, struct task_struct* prev) {
  /* TODO: replace following with per-cpu context */
  // trace("rorke_dispatch: CPU: %d VM: %d vCPU: %d", cpu, prev->tgid, prev->pid);
  struct cpu_ctx* cctx = try_lookup_cpu_ctx(cpu);
  // u64 now = bpf_ktime_get_ns();

  if (!cctx)
    return;

  // if (now - cctx->last_running < 20000)
  //   return;

  s32 vm_id = cctx->vm_id;
  if (vm_id == 0) {
    return;
  }

  if (scx_bpf_consume(vm_id)) {
    trace("rorke_dispatch: consumed from VM - %d", vm_id);
    return;
  }

  dbg("rorke_dispatch: empty... didn't consumed from VM - %d", vm_id);
}

void BPF_STRUCT_OPS(rorke_running, struct task_struct* p) {
  trace("rorke_running: VM: %d, vCPU: %d", p->tgid, p->pid);
  u64 now = bpf_ktime_get_ns();
  s32 cpu = scx_bpf_task_cpu(p);
  struct cpu_ctx* cctx = try_lookup_cpu_ctx(cpu);

  if (!cctx)
    return;

  cctx->last_running = now;
  __sync_fetch_and_add(&nr_running, 1);
}

void BPF_STRUCT_OPS(rorke_stopping, struct task_struct* p, bool runnable) {
  trace("rorke_stopping: VM: %d, vCPU: %d, runnable: %d", p->tgid, p->pid,
        runnable);
  __sync_fetch_and_sub(&nr_running, 1);
}

#define HYSTERESIS_THRESHOLD 1  // Min difference before reallocating

static void realloc_cpu_to_vm() {
  u32 cpu, vm, total_tasks = 0;
  u64 vm_task_counts[MAX_VMS] = {0};
  u64 vm_cpu_allocs[MAX_VMS] = {0};
  u64 prev_alloc[MAX_VMS] = {0};  // Track previous allocations

  /* Count tasks in each VM queue */
  bpf_for(vm, 0, nr_vms) {
    vm_task_counts[vm] = scx_bpf_dsq_nr_queued(vms[vm]);
    total_tasks += vm_task_counts[vm];
  }

  /* If no tasks, don't change allocations */
  if (total_tasks == 0) {
    return;
  }

  /* Compute new proportional CPU allocations */
  bpf_for(vm, 0, nr_vms) {
    if (vm_task_counts[vm] > 0) {
      vm_cpu_allocs[vm] = (vm_task_counts[vm] * (nr_cpus - 1)) / total_tasks;
    }
  }

  /* Apply hysteresis to reduce CPU movement */
  bpf_for(vm, 0, nr_vms) {
    u32 diff = (vm_cpu_allocs[vm] >= prev_alloc[vm]) 
               ? (vm_cpu_allocs[vm] - prev_alloc[vm]) 
               : (prev_alloc[vm] - vm_cpu_allocs[vm]);  // Compute absolute difference manually

    if (diff < HYSTERESIS_THRESHOLD) {
      vm_cpu_allocs[vm] = prev_alloc[vm];  // Keep previous allocation
    } else {
      prev_alloc[vm] = vm_cpu_allocs[vm];  // Update previous allocation
    }
  }

  /* Assign CPUs based on adjusted allocation */
  u32 assigned_cpus = 0;
  bpf_for(cpu, 0, nr_cpus) {
    if (cpu == central_cpu)
      continue;
    struct cpu_ctx* cctx = try_lookup_cpu_ctx(cpu);
    if (!cctx)
      continue;

      bpf_for(vm, 0, nr_vms) {
      if (vm_cpu_allocs[vm] > 0) {
        /* Only assign if the VM ID actually changes */
        if (cctx->vm_id != vms[vm]) {
          cctx->vm_id = vms[vm];
        }
        vm_cpu_allocs[vm]--;
        assigned_cpus++;
        break;
      }
    }
  }

  trace("realloc_cpu_to_vm: Distributed %d CPUs across %d VMs with hysteresis", assigned_cpus, nr_vms);
}


/*
 * TODO: Add description for timer functionality
 */
static int global_timer_fn(void* map, int* key, struct bpf_timer* timer) {

  u64 now = bpf_ktime_get_ns();
  s32 current_cpu = bpf_get_smp_processor_id();
  struct cpu_ctx* cctx;
  u64 delta;

  if (timer_pinned && (current_cpu != central_cpu)) {
    scx_bpf_error("Central Timer ran on CPU %d, not central CPU %d\n",
                  current_cpu, central_cpu);
    return 0;
  }

  bpf_for(current_cpu, 0, nr_cpus) {
    if (current_cpu == central_cpu)
      continue;

    cctx = try_lookup_cpu_ctx(current_cpu);
    if (!cctx) {
      trace("global_timer_fn: cpu ctx lookup failed");
      continue;
    }

    now = bpf_ktime_get_ns();
    delta = now - cctx->last_running + 5000; // Why 5000?
    // if (delta < timer_interval_ns - 5000) {
    if (delta < timer_interval_ns) {
      trace("global_timer_fn: CPU %d ran %d (< interval - %d) ago, skipping",
            current_cpu, delta, timer_interval_ns);
      continue;
    }
//
    if (scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | current_cpu))
      trace("global_timer_fn: local non-empty, will kick CPU %d", current_cpu); // Most probably for the some locally pinned tasks, e.x. some kthreads
    else if (scx_bpf_dsq_nr_queued(cctx->vm_id))
      trace("global_timer_fn: VM %d queue non-empty, will kick CPU %d",
            cctx->vm_id, current_cpu);
    else {
      // trace("global_timer_fn: nothing to do... skipping CPU %d", current_cpu);
      continue;
    }

    scx_bpf_kick_cpu(current_cpu, SCX_KICK_PREEMPT);
    cctx->preempted++;
    trace("global_timer_fn: preempted CPU %d", current_cpu);
  }

  if (realloc_cycles > 0) {
    if (realloc_cnt >= realloc_cycles) {
      realloc_cnt = 0;
      realloc_cpu_to_vm();  // Trigger CPU reallocation
    } else {
      realloc_cnt++;  // Increment counter if threshold not reached
    }
  }

  bpf_timer_start(timer, timer_interval_ns, BPF_F_TIMER_CPU_PIN);
  return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(rorke_init) {
  int ret;

  /* Create DSQ per VM */
  u32 i;
  bpf_for(i, 0, nr_vms) {
    ret = scx_bpf_create_dsq(vms[i], -1);
    if (ret) {
      scx_bpf_error("Failed to create DSQ for VM %lld", vms[i]);
      return ret;
    }
    info("Created DSQ for VM %d", vms[i]);
  }

  /* Setup timer */
  struct bpf_timer* timer;
  u32 key = 0;
  timer = bpf_map_lookup_elem(&global_timer, &key);
  if (!timer) {
    info("Failed to lookup timer");
    return -ESRCH;
  }

  if (bpf_get_smp_processor_id() != central_cpu) {
    scx_bpf_error("Fatal: init on non-central CPU");
    return EINVAL;
  }

  bpf_timer_init(timer, &global_timer, CLOCK_MONOTONIC);
  bpf_timer_set_callback(timer, global_timer_fn);
  info("Initialized timer\n");

  ret = bpf_timer_start(timer, timer_interval_ns, BPF_F_TIMER_CPU_PIN);
  /*
   * BPF_F_TIMER_CPU_PIN is not supported in all kernels (>= 6.7). If we're
   * running on an older kernel, it'll return -EINVAL
   * Retry w/o BPF_F_TIMER_CPU_PIN
   */
  if (ret == -EINVAL) {
    timer_pinned = false;
    ret = bpf_timer_start(timer, timer_interval_ns, 0);
  }
  if (ret)
    scx_bpf_error("bpf_timer_start failed (%d)", ret);
  info("Started timer -- rorke_init successfully finished");

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

               .flags = SCX_OPS_ENQ_LAST,
               .select_cpu = (void*)rorke_select_cpu,
               .enqueue = (void*)rorke_enqueue,
               .dispatch = (void*)rorke_dispatch,
               .running = (void*)rorke_running,
               .stopping = (void*)rorke_stopping,
               .init = (void*)rorke_init,
               .exit = (void*)rorke_exit,
               .name = "rorke");
