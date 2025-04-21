// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Based on hardirq(8) from BCC by Brendan Gregg.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "timerirqs.h"
#include "timerirqs.skel.h"
#include "trace_helpers.h"

struct env {
	bool cpu;
	bool distributed;
	bool nanoseconds;
	time_t interval;
	int times;
	bool timestamp;
	bool verbose;
	char *cgroupspath;
	bool cg;
	int targ_cpu;
} env = {
	.interval = 99999999,
	.times = 99999999,
	.targ_cpu = -1,
};

static volatile bool exiting;

const char *argp_program_version = "timerirqs 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Summarize timer irq event time as histograms.\n"
"\n"
"USAGE: timerirqs [--help] [-T] [-N] [-d] [-C] [interval] [count] [-c CG]\n"
"\n"
"EXAMPLES:\n"
"    timerirqs            # sum timer irq event time\n"
"    timerirqs -d         # show timer irq event time as histograms\n"
"    timerirqs 1 10       # print 1 second summaries, 10 times\n"
"    timerirqs -c CG      # Trace process under cgroupsPath CG\n"
"    timerirqs --cpu 1    # only stat irq on cpu 1\n"
"    timerirqs -C         # display separately by CPU\n"
"    timerirqs -NT 1      # 1s summaries, nanoseconds, and timestamps\n";

static const struct argp_option opts[] = {
	{ "CPU", 'C', NULL, 0, "Display separately by CPU", 0 },
	{ "distributed", 'd', NULL, 0, "Show distributions as histograms", 0 },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path", 0 },
	{ "cpu", 's', "CPU", 0, "Only stat irq on selected cpu", 0 },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output", 0 },
	{ "nanoseconds", 'N', NULL, 0, "Output in nanoseconds", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		env.distributed = true;
		break;
	case 'C':
		env.cpu = true;
		break;
	case 's':
		errno = 0;
		env.targ_cpu = atoi(arg);
		if (errno || env.targ_cpu < 0) {
			fprintf(stderr, "invalid cpu: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'c':
		env.cgroupspath = arg;
		env.cg = true;
		break;
	case 'N':
		env.nanoseconds = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			env.interval = strtol(arg, NULL, 10);
			if (errno) {
				fprintf(stderr, "invalid internal\n");
				argp_usage(state);
			}
		} else if (pos_args == 1) {
			env.times = strtol(arg, NULL, 10);
			if (errno) {
				fprintf(stderr, "invalid times\n");
				argp_usage(state);
			}
		} else {
			fprintf(stderr,
				"unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = true;
}

static int print_map(struct bpf_map *map)
{
	struct irq_key lookup_key = {}, next_key;
	struct info info;
	const char *units = env.nanoseconds ? "nsecs" : "usecs";
    char name[64];
	int fd, err;

	if (!env.distributed) {
		printf("%-33s %11s %6s%5s %6s%5s %7s%5s", "Timerirq", "Total_count",
			"Total_", units, "Avg_", units, "Max_", units);
		if (env.cpu)
			printf(" %6s\n", "CPU");
		else
			printf("\n");
	}

	fd = bpf_map__fd(map);

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &info);
		if (err < 0) {
			fprintf(stderr, "failed to lookup infos: %d\n", err);
			return -1;
		}

        switch (next_key.id) {
                case IRQ_ID_LOCAL_TIMER:
                    snprintf(name, sizeof(name), "local_timer");
                break;
            case IRQ_ID_HRTIMER:
                    snprintf(name, sizeof(name), "hrtimer");
                break;
            default:
                fprintf(stderr, "unknown key id: %d\n", next_key.id);
                return -1;
                break;
        }
		if (!env.distributed){
            printf("%-33s %11llu %11llu %12lf %11llu", name, info.count, info.total_time,
                                                    1.*info.total_time/info.count, info.max_time);
			if (env.cpu)
				printf(" %5u", next_key.cpu);
            printf("\n");
        } else {
			if (env.cpu)
				printf("cpu = %u ", next_key.cpu);
			printf("timerirq = %s\n", name);
			print_log2_hist(info.slots, MAX_SLOTS, units);
		}
		lookup_key = next_key;
	}

	memset(&lookup_key, 0, sizeof(lookup_key));

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			fprintf(stderr, "failed to cleanup infos: %d\n", err);
			return -1;
		}
		lookup_key = next_key;
	}

	return 0;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct timerirqs_bpf *obj;
	struct tm *tm;
	char ts[32];
	time_t t;
	int err;
	int idx, cg_map_fd;
	int cgfd = -1;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = timerirqs_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	if (probe_tp_btf("irq_handler_entry")) {
		bpf_program__set_autoload(obj->progs.local_timer_entry, false);
		bpf_program__set_autoload(obj->progs.local_timer_exit, false);
	} else {
		bpf_program__set_autoload(obj->progs.local_timer_entry_btf, false);
		bpf_program__set_autoload(obj->progs.local_timer_exit_btf, false);
	}

    if (probe_tp_btf("hrtimer_expire_entry")) {
        bpf_program__set_autoload(obj->progs.hrtimer_expire_entry, false);
        bpf_program__set_autoload(obj->progs.hrtimer_expire_exit, false);
    } else {
        bpf_program__set_autoload(obj->progs.hrtimer_expire_entry_btf, false);
        bpf_program__set_autoload(obj->progs.hrtimer_expire_exit_btf, false);
    }


	/* initialize global data (filtering options) */
	obj->rodata->filter_cg = env.cg;
	obj->rodata->cpu = env.cpu;
	obj->rodata->targ_cpu = env.targ_cpu;
	obj->rodata->targ_dist = env.distributed;
	obj->rodata->targ_ns = env.nanoseconds;

	err = timerirqs_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	/* update cgroup path fd to map */
	if (env.cg) {
		idx = 0;
		cg_map_fd = bpf_map__fd(obj->maps.cgroup_map);
		cgfd = open(env.cgroupspath, O_RDONLY);
		if (cgfd < 0) {
			fprintf(stderr, "Failed opening Cgroup path: %s", env.cgroupspath);
			goto cleanup;
		}
		if (bpf_map_update_elem(cg_map_fd, &idx, &cgfd, BPF_ANY)) {
			fprintf(stderr, "Failed adding target cgroup to map");
			goto cleanup;
		}
	}

	err = timerirqs_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF object: %d\n", err);
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	printf("Tracing timer irq event time... Hit Ctrl-C to end.\n");

	/* main: poll */
	while (1) {
		sleep(env.interval);
		printf("\n");

		if (env.timestamp) {
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-8s\n", ts);
		}

		err = print_map(obj->maps.infos);
		if (err)
			break;

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	timerirqs_bpf__destroy(obj);
	if (cgfd > 0)
		close(cgfd);

	return err != 0;
}
