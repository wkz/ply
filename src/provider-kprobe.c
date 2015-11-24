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

#include "provider.h"

struct builtin {
	const char *name;

	int (*annotate)(struct provider *p, struct fs_node *n);
	int  (*compile)(struct provider *p, struct ebpf *e, struct fs_node *n);
};


static long
perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
		int cpu, int group_fd, unsigned long flags)
{
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
		      group_fd, flags);
	return ret;
}

static __u64 ptr_to_u64(const void *ptr)
{
        return (__u64) (unsigned long) ptr;
}

#define LOG_BUF_SIZE 0x1000
char bpf_log_buf[LOG_BUF_SIZE];

int bpf_prog_load(const struct bpf_insn *insns, int insn_cnt)
{
	union bpf_attr attr = {
		.prog_type = BPF_PROG_TYPE_KPROBE,
		.insns     = ptr_to_u64(insns),
		.insn_cnt  = insn_cnt,
		.license   = ptr_to_u64("GPL"),
		.log_buf   = ptr_to_u64(bpf_log_buf),
		.log_size  = LOG_BUF_SIZE,
		.log_level = 1,
		.kern_version = LINUX_VERSION_CODE,
	};
	
	return syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
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

static int kprobes_setup(struct provider *p, struct ebpf *e, struct fs_node *n)
{
	int bd, ed, eventid;
	struct perf_event_attr attr = {};

	eventid = _eventid(n->probe.pspecs->string);
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

static int trace_compile(struct provider *p, struct ebpf *e, struct fs_node *n)
{
	struct fs_node *arg, *fmtlen;
	struct reg *r = e->st->reg;
	int err, reg;

	reg = BPF_REG_1;
	arg = n->call.vargs;

	err = ebpf_reg_load(e, &r[reg++], arg);
	RET_ON_ERR(err, "trace/compile/load fmt\n");

	fmtlen = fs_int_new(strlen(arg->string) + 1);
	err = ebpf_reg_load(e, &r[reg++], fmtlen);
	free(fmtlen);
	RET_ON_ERR(err, "trace/compile/load fmtlen\n");

	arg = arg->next;
	for (; !err && arg && reg <= BPF_REG_5; arg = arg->next, reg++)
		err = ebpf_reg_load(e, &r[reg], arg);

	ebpf_emit(e, CALL(BPF_FUNC_trace_printk));
	ebpf_reg_bind(e, &r[0], n);

	reg = BPF_REG_1;
	ebpf_reg_put(e, &r[reg++]);
	ebpf_reg_put(e, &r[reg++]);

	arg = n->call.vargs->next;
	for (; arg && reg <= BPF_REG_5; arg = arg->next, reg++)
		ebpf_reg_put(e, &r[reg]);

	return 0;
}

static int trace_annotate(struct provider *p, struct fs_node *n)
{
	if (!n->call.vargs)
		return -EINVAL;

	if (n->call.vargs->type != FS_STR)
		return -EINVAL;

	return 0;
}

struct builtin kprobes_builtins[] = {
	{
		.name = "trace",
		.annotate = trace_annotate,
		.compile  = trace_compile,
	},

	{ .name = NULL }
};

static int kprobes_compile(struct provider *p, struct ebpf *e, struct fs_node *n)
{
	struct builtin *bi;

	for (bi = kprobes_builtins; bi->name; bi++)
		if (!strcmp(bi->name, n->string))
			return bi->compile(p, e, n);

	return -ENOENT;	
}

static int kprobes_annotate(struct provider *p, struct fs_node *n)
{
	struct builtin *bi;

	for (bi = kprobes_builtins; bi->name; bi++)
		if (!strcmp(bi->name, n->string))
			return bi->annotate(p, n);

	return -ENOENT;
}

struct provider kprobe_provider = {
	.name = "kprobe",
	.annotate = kprobes_annotate,
	.compile  = kprobes_compile,
	.setup    = kprobes_setup,
};
