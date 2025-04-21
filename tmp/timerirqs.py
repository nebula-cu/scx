#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# timerirqs  Summarize timer IRQ (interrupt) event time.
#            For Linux, uses BCC, eBPF.
#
# USAGE: timerirqs [-h] [-T] [-N] [-C] [-d] [-c CPU] [interval] [outputs]

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import sys

# arguments
examples = """examples:
    ./timerirqs            # sum timer irq event time
    ./timerirqs -d         # show timer irq event time as histograms
    ./timerirqs 1 10       # print 1 second summaries, 10 times
    ./timerirqs -NT 1      # 1s summaries, nanoseconds, and timestamps
    ./timerirqs -c 1       # sum timer irq event time on CPU 1 only
"""
parser = argparse.ArgumentParser(
    description="Summarize timer irq event time as histograms",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-N", "--nanoseconds", action="store_true",
    help="output in nanoseconds")
parser.add_argument("-C", "--count", action="store_true",
    help="show event counts instead of timing")
parser.add_argument("-d", "--dist", action="store_true",
    help="show distributions as histograms")
parser.add_argument("-c", "--cpu", type=int,
    help="trace this CPU only")
parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("outputs", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
countdown = int(args.outputs)
if args.count and (args.dist or args.nanoseconds):
    print("The --count option can't be used with time-based options")
    exit()
if args.count:
    factor = 1
    label = "count"
elif args.nanoseconds:
    factor = 1
    label = "nsecs"
else:
    factor = 1000
    label = "usecs"
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/interrupt.h>

const u32 LOCAL_TIMER = 0;
const u32 HRTIMER = 1;
// Add cpu_id as part of key for irq entry event to handle the case which irq
// is triggered while idle thread(swapper/x, tid=0) for each cpu core.
// Please see more detail at pull request #2804, #3733.
typedef struct entry_key {
    u32 tid;
    u32 cpu_id;
} entry_key_t;

typedef struct hist_key {
    u32 type;
    u64 slot;
} hist_key_t;

BPF_HASH(start, entry_key_t);
// TODO: rename hrtimer_start is conflic
//BPF_HASH(hrtimer_start, entry_key_t);
BPF_HISTOGRAM(dist, hist_key_t);
"""

bpf_text_count = """
# TRACEPOINT_PROBE(irq_vectors, local_timer_entry)
# {
#     struct entry_key key = {};
#     u32 cpu = bpf_get_smp_processor_id();
#
#     FILTER_CPU
#
#     key.tid = bpf_get_current_pid_tgid();
#     key.cpu_id = cpu;
#     return 0;
# }

TRACEPOINT_PROBE(irq_vectors, local_timer_exit)
{
    struct entry_key key = {};
    u32 cpu = bpf_get_smp_processor_id();

    FILTER_CPU

    key.tid = bpf_get_current_pid_tgid();
    key.cpu_id = cpu;

    hist_key_t hist_key = {.slot = 0, .type = LOCAL_TIMER};
    dist.atomic_increment(hist_key);
    return 0;
}
"""

bpf_text_time = """
TRACEPOINT_PROBE(irq_vectors, local_timer_entry)
{
    u64 ts = bpf_ktime_get_ns();
    struct entry_key key = {};
    u32 cpu = bpf_get_smp_processor_id();

    FILTER_CPU

    key.tid = bpf_get_current_pid_tgid();
    key.cpu_id = cpu;

    start.update(&key, &ts);
    return 0;
}

TRACEPOINT_PROBE(irq_vectors, local_timer_exit)
{
    u64 *tsp, delta;
    struct entry_key key = {};
    u32 cpu = bpf_get_smp_processor_id();

    key.tid = bpf_get_current_pid_tgid();
    key.cpu_id = cpu;

    // fetch timestamp and calculate delta
    tsp = start.lookup(&key);
    if (tsp == 0) {
        return 0;   // missed start
    }

    delta = bpf_ktime_get_ns() - *tsp;

    // store as sum or histogram
    hist_key_t hist_key = {.slot = 0, .type = LOCAL_TIMER};
    STORE

    start.delete(&key);
    return 0;
}
"""

if args.count:
    bpf_text += bpf_text_count
else:
    bpf_text += bpf_text_time

# code substitutions
if args.dist:
    bpf_text = bpf_text.replace('STORE',
        'hist_key.slot = bpf_log2l(delta / %d);' % factor +
        'dist.atomic_increment(hist_key);')
else:
    bpf_text = bpf_text.replace('STORE',
        'dist.atomic_increment(hist_key, delta);')
if args.cpu is not None:
    bpf_text = bpf_text.replace('FILTER_CPU',
        'if (cpu != %d) { return 0; }' % int(args.cpu))
else:
    bpf_text = bpf_text.replace('FILTER_CPU', '')
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# load BPF program
b = BPF(text=bpf_text)

if args.count:
    print("Tracing timer irq events... Hit Ctrl-C to end.")
else:
    print("Tracing timer irq event time... Hit Ctrl-C to end.")

# output
exiting = 0 if args.interval else 1
dist = b.get_table("dist")
while (1):
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = 1

    print()
    if args.timestamp:
        print("%-8s\n" % strftime("%H:%M:%S"), end="")

    if args.dist:
        # dist.print_log2_hist(label, "timerirq", section_print_fn=bytes.decode)
        dist.print_log2_hist(label, "source", lambda v: "local_timer" if v==0 else "hrtimer")
    else:
        print("%-26s %11s" % ("Timer Type","Total " + label))
        for k, v in sorted(dist.items(), key=lambda dist: -dist[1].value):
            print("%-26s %11d" % ("local_timer" if k.type==0 else "hrtimer", v.value / factor))
    dist.clear()

    sys.stdout.flush()

    countdown -= 1
    if exiting or countdown == 0:
        exit()
