/* Copyright (c) Meta Platforms, Inc. and affiliates. */
#ifndef __LAYERED_TIMER_H
#define __LAYERED_TIMER_H
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

enum timer_consts {
	// kernel definitions
	CLOCK_BOOTTIME		= 7,
};

struct layered_timer {
	// if set to 0 the timer will only be scheduled once
	int interval_ns;
	u64 init_flags;
	u64 start_flags;
};

enum layer_timer_callbacks {
	NOOP_TIMER,
	MAX_TIMERS,
};
#endif /* __LAYERED_TIMER_H */
