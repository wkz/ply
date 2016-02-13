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

typedef struct kprobe {
	FILE *ctrl;
	int bfd;

	struct {
		int cap, len;
		int *fds;
	} efds;
} kprobe_t;

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
		return -EIO;
	}

	fgets(ev_str, sizeof(ev_str), fp);
	fclose(fp);
	return strtol(ev_str, NULL, 0);
}

static int kprobe_attach_one(kprobe_t *kp, const char *func)
{
	struct perf_event_attr attr = {};
	int efd, id;

	id = kprobe_event_id(func, kp->ctrl);
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
		return -errno;
	}

	if (ioctl(efd, PERF_EVENT_IOC_ENABLE, 0)) {
		perror("perf enable");
		return -errno;
	}

	if (ioctl(efd, PERF_EVENT_IOC_SET_BPF, kp->bfd)) {
		perror("perf attach");
		return -errno;
	}

	if (kp->efds.len == kp->efds.cap) {
		size_t sz = kp->efds.cap * sizeof(*kp->efds.fds);

		kp->efds.fds = realloc(kp->efds.fds, sz << 1);
		assert(kp->efds.fds);
		memset(&kp->efds.fds[kp->efds.cap], 0, sz);
		kp->efds.cap <<= 1;
	}

	kp->efds.fds[kp->efds.len++] = efd;
	return 1;
}

static int kprobe_attach_pattern(kprobe_t *kp, const char *pattern)
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
	while (err >= 0 && fgets(line, 256, ksyms)) {
		char *func, *pos;

		pos = strchr(line, ' ') + 1;
		if (*pos != 't' && *pos != 'T')
			continue;

		pos = strchr(pos, ' ') + 1;
		func = strtok(pos, " ");
		if (strchr(func, '.'))
			continue;

		pos = strchr(func, '\n');
		if (pos)
			*pos = '\0';

		if (fnmatch(pattern, func, 0))
			continue;

		err = kprobe_attach_one(kp, func);		
	}
	free(line);
	fclose(ksyms);
	return (err < 0) ? err : kp->efds.len;
}

static int kprobe_setup(node_t *probe, prog_t *prog)
{
	kprobe_t *kp;
	char *func;

	kp = calloc(1, sizeof(*kp));
	assert(kp);

	kp->efds.fds = calloc(1, sizeof(*kp->efds.fds));
	assert(kp->efds.fds);
	kp->efds.cap = 1;

	probe->dyn.probe.pvdr_priv = kp;

	_d("");
	kp->ctrl = fopen("/sys/kernel/debug/tracing/kprobe_events", "a+");
	if (!kp->ctrl) {
		perror("unable to open kprobe_events");
		return -EIO;
	}

	kp->bfd = bpf_prog_load(prog->insns, prog->ip - prog->insns);
	if (kp->bfd < 0) {
		perror("bpf");
		fprintf(stderr, "bpf verifier:\n%s\n", bpf_log_buf);
		return -EINVAL;
	}
	
	func = strchr(probe->string, ':') + 1;
	if (strchr(func, '?') || strchr(func, '*'))
		return kprobe_attach_pattern(kp, func);
	else
		return kprobe_attach_one(kp, func);
}

static int kprobe_teardown(node_t *probe)
{
	kprobe_t *kp = probe->dyn.probe.pvdr_priv;
	int i;

	for (i = 0; i < kp->efds.len; i++)
		close(kp->efds.fds[i]);

	free(kp->efds.fds);
	free(kp);
	return 0;
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
	.teardown   = kprobe_teardown,
};

__attribute__((constructor))
static void kprobe_pvdr_register(void)
{
	pvdr_register(&kprobe_pvdr);
}
