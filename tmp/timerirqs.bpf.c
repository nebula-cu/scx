// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "timerirqs.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

#define MAX_ENTRIES	256

const volatile bool filter_cg = false;
const volatile bool targ_dist = false;
const volatile bool targ_ns = false;
const volatile bool cpu = false;
const volatile int targ_cpu = -1;

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct irq_key);
	__type(value, struct info);
} infos SEC(".maps");

static struct info zero;

static __always_inline bool is_target_cpu() {
	if (targ_cpu < 0)
		return true;

	return targ_cpu == bpf_get_smp_processor_id();
}

static int handle_entry(int irq)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;
	if (!is_target_cpu())
		return 0;

	u64 ts = bpf_ktime_get_ns();
	u32 key = 0;

    switch (irq) {
        case IRQ_ID_LOCAL_TIMER:
            key = 0;
            break;
        case IRQ_ID_HRTIMER:
            key = 1;
            break;
        default:
            bpf_printk("unknown irq id: %d\n", irq);
            return -1;
    }
	bpf_map_update_elem(&start, &key, &ts, BPF_ANY);

	return 0;
}

static int handle_exit(int irq)
{
	struct irq_key ikey = {};
	struct info *info;
	u32 key;
	u64 delta;
	u64 *tsp;

	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	if (!is_target_cpu())
		return 0;

    switch (irq) {
        case IRQ_ID_LOCAL_TIMER:
            key = 0;
            break;
        case IRQ_ID_HRTIMER:
            key = 1;
            break;
        default:
            bpf_printk("unknown irq id: %d\n", irq);
            return -1;
    }
	tsp = bpf_map_lookup_elem(&start, &key);
	if (!tsp)
		return 0;

	delta = bpf_ktime_get_ns() - *tsp;
	if (!targ_ns)
		delta /= 1000U;

    ikey.id = irq;
	if (cpu)
		ikey.cpu = bpf_get_smp_processor_id();
	info = bpf_map_lookup_or_try_init(&infos, &ikey, &zero);
	if (!info)
		return 0;

	info->count += 1;

	if (!targ_dist) {
		info->total_time += delta;
		if (delta > info->max_time)
			info->max_time = delta;
	} else {
		u64 slot;

		slot = log2l(delta);
		if (slot >= MAX_SLOTS)
			slot = MAX_SLOTS - 1;
		info->slots[slot]++;
	}

	return 0;
}
//
SEC("tp_btf/local_timer_entry")
int BPF_PROG(local_timer_entry_btf, int irq)
{
	return handle_entry(irq);
}

SEC("tp_btf/local_timer_exit")
int BPF_PROG(local_timer_exit_btf, int irq)
{
	return handle_exit(irq);
}

SEC("raw_tp/local_timer_entry")
int BPF_PROG(local_timer_entry, int irq)
{
	return handle_entry(irq);
}

SEC("raw_tp/local_timer_exit")
int BPF_PROG(local_timer_exit, int irq)
{
	return handle_exit(irq);
}

SEC("tp_btf/hrtimer_expire_entry")
int BPF_PROG(hrtimer_expire_entry_btf, struct hrtimer *hrtimer, ktime_t *now)
{
	return handle_entry(IRQ_ID_HRTIMER);
}

SEC("tp_btf/hrtimer_expire_exit")
int BPF_PROG(hrtimer_expire_exit_btf, ktime_t *now)
{
	return handle_exit(IRQ_ID_HRTIMER);
}

SEC("raw_tp/hrtimer_expire_entry")
int BPF_PROG(hrtimer_expire_entry, struct hrtimer *hrtimer, ktime_t *now)
{
	return handle_entry(IRQ_ID_HRTIMER);
}

SEC("raw_tp/hrtimer_expire_exit")
int BPF_PROG(hrtimer_expire_exit, ktime_t *now)
{
	return handle_exit(IRQ_ID_HRTIMER);
}

char LICENSE[] SEC("license") = "GPL";
