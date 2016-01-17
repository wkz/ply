#include <errno.h>
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

#include "../bpf-syscall.h"
#include "pvdr.h"

/* typedef struct evlist { */
/* 	size_t cap, len; */
/* 	uint32_t *ids; */
/* } evlist_t; */

/* static int evlist_init(evlist_t *el, size_t cap) */
/* { */
/* 	if (el->ids) */
/* 		return -EBUSY; */

/* 	el->ids = malloc(cap * sizeof(*el->ids)); */
/* 	if (!el) */
/* 		return -ENOMEM; */

/* 	el->cap = cap; */
/* 	el->len = 0; */
/* } */

static long
perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
		int cpu, int group_fd, unsigned long flags)
{
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
		      group_fd, flags);
	return ret;
}

static int _eventid(char *pspec)
{
	FILE *fp;
	char *func, str[128];

	strtok(pspec, ":");
	func = strtok(NULL, ":");

	sprintf(str, "echo 'p %s' >/sys/kernel/debug/tracing/kprobe_events", func);
	system(str);

	sprintf(str, "/sys/kernel/debug/tracing/events/kprobes/p_%s_0/id", func);
	fp = fopen(str, "r");
	if (!fp)
		return -1;

	fgets(str, sizeof(str), fp);
	fclose(fp);
	return strtol(str, NULL, 0);
}

static int kprobe_setup(node_t *probe, struct ebpf *e)
{
	int bd, ed, eventid;
	struct perf_event_attr attr = {};

	eventid = _eventid(probe->string);
	if (eventid <= 0)
		return eventid;
	
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.sample_period = 1;
	attr.wakeup_events = 1;
	attr.config = eventid;

	bd = bpf_prog_load(e->prog, e->ip - e->prog);
	if (bd < 0) {
		perror("bpf");
		fprintf(stderr, "bpf verifier:\n%s\n", bpf_log_buf);
		return 1;
	}

	ed = perf_event_open(&attr, -1/*pid*/, 0/*cpu*/, -1/*group_fd*/, 0);
	if (ed < 0) {
		perror("perf_event_open");
		return 1;
	}

	if (ioctl(ed, PERF_EVENT_IOC_ENABLE, 0)) {
		perror("perf enable");
		return 1;
	}

	if (ioctl(ed, PERF_EVENT_IOC_SET_BPF, bd)) {
		perror("perf attach");
		return 1;
	}

	return 0;
}


static int kprobe_compile(node_t *call, struct ebpf *e)
{
	return builtin_compile(call, e);
}

static int kprobe_annotate(node_t *call)
{
	return builtin_annotate(call);
}

pvdr_t kprobe_pvdr = {
	.name = "kprobe",
	.annotate = kprobe_annotate,
	.compile  = kprobe_compile,
	.setup    = kprobe_setup,
};

__attribute__((constructor))
static void kprobe_pvdr_register(void)
{
	pvdr_register(&kprobe_pvdr);
}
