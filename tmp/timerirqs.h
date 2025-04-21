/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TIMERIRQS_H
#define __TIMERIRQS_H

#define MAX_SLOTS	20
#define IRQ_ID_LOCAL_TIMER 0xEC
#define IRQ_ID_HRTIMER 1

struct irq_key {
	__u32 id;
	__u32 cpu;
};

struct info {
	__u64 count;
	__u64 total_time;
	__u64 max_time;
	__u32 slots[MAX_SLOTS];
};

#endif /* __TIMERIRQS_H */
