#define _GNU_SOURCE

#include <errno.h>
#include <fnmatch.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <linux/version.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include "../ply.h"
#include "../bpf-syscall.h"
#include "pvdr.h"

static long
perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
		int cpu, int group_fd, unsigned long flags)
{
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
		      group_fd, flags);
	return ret;
}

static int kprobe_event_id(const char *func, FILE *ctrl)
{
	FILE *fp;
	char *ev_id, ev_str[16];

	fprintf(ctrl, "p %s\n", func);
	fflush(ctrl);

	asprintf(&ev_id, "/sys/kernel/debug/tracing/events/kprobes/p_%s_0/id", func);
	fp = fopen(ev_id, "r");
	free(ev_id);
	if (!fp) {
		_pe("unable to create kprobe for \"%s\"", func);
		return -1;
	}

	fgets(ev_str, sizeof(ev_str), fp);
	fclose(fp);
	return strtol(ev_str, NULL, 0);
}

static int kprobe_attach_one(const char *func, int bfd, FILE *ctrl)
{
	struct perf_event_attr attr = {};
	int efd, id;

	id = kprobe_event_id(func, ctrl);
	if (id < 0)
		return id;

	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.sample_period = 1;
	attr.wakeup_events = 1;
	attr.config = id;

	efd = perf_event_open(&attr, -1/*pid*/, 0/*cpu*/, -1/*group_fd*/, 0);
	if (efd < 0) {
		perror("perf_event_open");
		return 1;
	}

	if (ioctl(efd, PERF_EVENT_IOC_ENABLE, 0)) {
		perror("perf enable");
		return 1;
	}

	if (ioctl(efd, PERF_EVENT_IOC_SET_BPF, bfd)) {
		perror("perf attach");
		return 1;
	}

	return 0;
}

static int kprobe_attach_pattern(const char *pattern, int bfd, FILE *ctrl)
{
	FILE *ksyms;
	char *line;
	int err = 0;

	_d("pattern:%s", pattern);

	ksyms = fopen("/proc/kallsyms", "r");
	if (!ksyms) {
		perror("no kernel symbols available");
		return -ENOENT;
	}

	line = malloc(256);
	assert(line);
	while (!err && fgets(line, 256, ksyms)) {
		char *func, *pos;

		pos = strchr(line, ' ') + 1;
		if (*pos != 't' && *pos != 'T')
			continue;

		pos = strchr(pos, ' ') + 1;
		func = strtok(pos, " ");
		if (strchr(func, '.'))
			continue;
		
		if (!fnmatch(pattern, func, 0))
			err = kprobe_attach_one(func, bfd, ctrl);
	}
	free(line);
	fclose(ksyms);
	return err;
}

static int kprobe_setup(node_t *probe, prog_t *prog)
{
	FILE *ctrl;
	int bfd;
	char *func;

	_d("");
	ctrl = fopen("/sys/kernel/debug/tracing/kprobe_events", "a+");
	if (!ctrl) {
		perror("unable to open kprobe_events");
		return 1;
	}

	bfd = bpf_prog_load(prog->insns, prog->ip - prog->insns);
	if (bfd < 0) {
		perror("bpf");
		fprintf(stderr, "bpf verifier:\n%s\n", bpf_log_buf);
		return 1;
	}

	func = strchr(probe->string, ':') + 1;
	if (strchr(func, '?') || strchr(func, '*'))
		return kprobe_attach_pattern(func, bfd, ctrl);
	else
		return kprobe_attach_one(func, bfd, ctrl);
}


static int kprobe_compile(node_t *call, prog_t *prog)
{
	return builtin_compile(call, prog);
}

static int kprobe_loc_assign(node_t *call)
{
	return builtin_loc_assign(call);
}

static int kprobe_annotate(node_t *call)
{
	return builtin_annotate(call);
}

pvdr_t kprobe_pvdr = {
	.name = "kprobe",
	.annotate   = kprobe_annotate,
	.loc_assign = kprobe_loc_assign,
	.compile    = kprobe_compile,
	.setup      = kprobe_setup,
};

__attribute__((constructor))
static void kprobe_pvdr_register(void)
{
	pvdr_register(&kprobe_pvdr);
}
