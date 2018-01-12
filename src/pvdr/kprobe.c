/*
 * Copyright 2015-2017 Tobias Waldekranz <tobias@waldekranz.com>
 *
 * This file is part of ply.
 *
 * ply is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, under the terms of version 2 of the
 * License.
 *
 * ply is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ply.  If not, see <http://www.gnu.org/licenses/>.
 */

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
#include <sys/types.h>

#include <ply/bpf-syscall.h>
#include <ply/module.h>
#include <ply/ply.h>
#include <ply/pvdr.h>

typedef struct kprobe {
	const char *type;
	FILE *ctrl;
	int bfd;

	struct {
		int cap, len;
		int *fds;
	} efds;
} kprobe_t;


static int probe_event_id(kprobe_t *kp, const char *path)
{
	FILE *fp;
	char ev_id[16];

	fp = fopenf("r", "/sys/kernel/debug/tracing/events/%s/id", path);
	if (!fp)
		return -errno;

	if (!fgets(ev_id, sizeof(ev_id), fp))
		return -EIO;

	fclose(fp);
	return strtol(ev_id, NULL, 0);
}

static int probe_attach(kprobe_t *kp, int id)
{
	struct perf_event_attr attr = {};
	int efd, gfd;

	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.sample_period = 1;
	attr.wakeup_events = 1;
	attr.config = id;

	gfd = kp->efds.len ? kp->efds.fds[0] : -1;
	efd = perf_event_open(&attr, -1, 0, gfd, 0);
	if (efd < 0) {
		return -errno;
	}

	if (ioctl(efd, PERF_EVENT_IOC_ENABLE, 0)) {
		close(efd);
		return -errno;
	}

	if (ioctl(efd, PERF_EVENT_IOC_SET_BPF, kp->bfd)) {
		close(efd);
		return -errno;
	}

	if (kp->efds.len == kp->efds.cap) {
		size_t sz = kp->efds.cap * sizeof(*kp->efds.fds);

		kp->efds.fds = realloc(kp->efds.fds, sz << 1);
		assert(kp->efds.fds);
		kp->efds.cap <<= 1;
	}

	kp->efds.fds[kp->efds.len++] = efd;

	return 1;
}

static kprobe_t *probe_load(enum bpf_prog_type type,
			    node_t *probe, prog_t *prog)
{
	kprobe_t *kp;

	kp = malloc(sizeof(*kp));
	assert(kp);

	kp->efds.fds = calloc(1, sizeof(*kp->efds.fds));
	assert(kp->efds.fds);
	kp->efds.cap = 1;
	kp->efds.len = 0;

	kp->bfd = bpf_prog_load(type, prog->insns, prog->ip - prog->insns);
	if (kp->bfd < 0) {
		_eno("%s", probe->string);
		if (!bpf_log_buf[0]) {
			_e("no output from kernel verifier");
			_e("was ply built against the running kernel?");
		} else {
			_e("output from kernel bpf verifier:\n%s", bpf_log_buf);
		}

		free(kp);
		return NULL;
	}

	probe->dyn->probe.pvdr_priv = kp;
	return kp;
}

static int probe_teardown(node_t *probe)
{
	kprobe_t *kp = probe->dyn->probe.pvdr_priv;
	int i;

	for (i = 0; i < kp->efds.len; i++)
		close(kp->efds.fds[i]);

	free(kp->efds.fds);
	free(kp);
	return 0;
}


/* TRACEPOINT provider */
#ifdef LINUX_HAS_TRACEPOINT
static int trace_attach(kprobe_t *kp, const char *func)
{
	int id;

	id = probe_event_id(kp, func);
	if (id < 0)
		return id;

	return probe_attach(kp, id);
}

static int trace_load(node_t *probe, prog_t *prog)
{
	kprobe_t *kp;
	char *func;

	kp = probe_load(BPF_PROG_TYPE_TRACEPOINT, probe, prog);
	if (!kp)
		return -EINVAL;

	func = strchr(probe->string, ':') + 1;
	/* if (strchr(func, '?') || strchr(func, '*')) */
	/* 	return kprobe_attach_pattern(kp, func); */
	/* else */
		return trace_attach(kp, func);
}

const module_t *trace_modules[] = {
	&trace_module,

	&method_module,
	&common_module,

	NULL
};

static int trace_resolve(node_t *call, const func_t **f)
{
	return modules_get_func(trace_modules, call, f);
}

pvdr_t trace_pvdr = {
	.name = "trace",

	.resolve = trace_resolve,

	.setup      = trace_load,
	.teardown   = probe_teardown,
};
#endif


/* KPROBE provider */

static int kprobe_event_id(kprobe_t *kp, const char *func)
{
	char ev_name[0x100];
	const char *offstr;
	long offs = 0;
	int funclen;

	offstr = strchrnul(func, '+');
	if (*offstr) {
		offs = strtol(offstr, NULL, 0);
		if (offs < 0) {
			_e("unknown offset in probe '%s'", func);
			return -EINVAL;
		}
	}

	funclen = (int)(offstr - func);

	fprintf(kp->ctrl, "%s %*.*s+%ld\n", kp->type, funclen, funclen, func, offs);
	fflush(kp->ctrl);

	snprintf(ev_name, sizeof(ev_name), "kprobes/%s_%*.*s_%ld", kp->type,
		 funclen, funclen, func, offs);

	return probe_event_id(kp, ev_name);
}

static int kprobe_attach(kprobe_t *kp, const char *func)
{
	int id;

	id = kprobe_event_id(kp, func);
	if (id < 0)
		return id;

	return probe_attach(kp, id);
}

static int kprobe_attach_pattern(kprobe_t *kp, const char *pattern)
{
	int i, err;

	if (!G.ksyms) {
		_e("probe wildcards not supported without KALLSYMS support");
		return -ENOSYS;
	}

	for (i = 0; i < G.ksyms->cache->hdr.n_syms; i++) {
		const ksym_t *k = &G.ksyms->cache->sym[i];

		if (fnmatch(pattern, k->sym, 0))
			continue;

		err = kprobe_attach(kp, k->sym);
		if (err == -EEXIST || err == -ENOENT) {
			_w("'%s' will not be probed", k->sym);
			err = 0;
		}
	}

	return (err < 0) ? err : kp->efds.len;
}

static int kprobe_load(node_t *probe, prog_t *prog, const char *type)
{
	kprobe_t *kp;
	char *func;

	kp = probe_load(BPF_PROG_TYPE_KPROBE, probe, prog);
	if (!kp)
		return -EINVAL;

	kp->type = type;

	kp->ctrl = fopen("/sys/kernel/debug/tracing/kprobe_events", "a+");
	if (!kp->ctrl) {
		_eno("unable to open kprobe_events");
		return -errno;
	}

	func = strchr(probe->string, ':') + 1;
	if (strchr(func, '?') || strchr(func, '*'))
		return kprobe_attach_pattern(kp, func);
	else
		return kprobe_attach(kp, func);
}


const module_t *kprobe_modules[] = {
	&kprobe_module,

	&method_module,
	&common_module,

	NULL
};

int kprobe_default(node_t *probe, node_t **stmts)
{
	node_t *c, *vargs;
	char *fmt;

	if (asprintf(&fmt, "%s:  pid:%%-5d  comm:%%v  func:%%v\n", probe->string) == -1) {
		return -1;
	}
	vargs = node_str_new(fmt);

	c = node_call_new(strdup("common"), strdup("pid"), NULL);
	insque_tail(c, vargs);

	c = node_call_new(strdup("common"), strdup("comm"), NULL);
	insque_tail(c, vargs);

	c = node_call_new(strdup("kprobe"), strdup("func"), NULL);
	insque_tail(c, vargs);

	*stmts = node_call_new(strdup("common"), strdup("printf"), vargs);

	node_foreach(c, *stmts)
		c->parent = probe;

	return 0;
}

static int kprobe_resolve(node_t *call, const func_t **f)
{
	return modules_get_func(kprobe_modules, call, f);
}

static int kprobe_setup(node_t *probe, prog_t *prog)
{
	return kprobe_load(probe, prog, "p");
}

pvdr_t kprobe_pvdr = {
	.name = "kprobe",

	.dflt    = kprobe_default,
	.resolve = kprobe_resolve,

	.setup      = kprobe_setup,
	.teardown   = probe_teardown,
};


const module_t *kretprobe_modules[] = {
	&kretprobe_module,

	&method_module,
	&common_module,

	NULL
};

int kretprobe_default(node_t *probe, node_t **stmts)
{
	node_t *c, *vargs;
	char *fmt;

	if (asprintf(&fmt, "%s:  pid:%%-5d  comm:%%v  retval:%%d\n", probe->string) == -1) {
		return -1;
	}
	vargs = node_str_new(fmt);

	c = node_call_new(strdup("common"), strdup("pid"), NULL);
	insque_tail(c, vargs);

	c = node_call_new(strdup("common"), strdup("comm"), NULL);
	insque_tail(c, vargs);

	c = node_call_new(strdup("kretprobe"), strdup("retval"), NULL);
	insque_tail(c, vargs);

	*stmts = node_call_new(strdup("common"), strdup("printf"), vargs);

	node_foreach(c, *stmts)
		c->parent = probe;

	return 0;
}

static int kretprobe_resolve(node_t *call, const func_t **f)
{
	return modules_get_func(kretprobe_modules, call, f);
}

static int kretprobe_setup(node_t *probe, prog_t *prog)
{
	return kprobe_load(probe, prog, "r");
}

pvdr_t kretprobe_pvdr = {
	.name = "kretprobe",

	.dflt    = kretprobe_default,
	.resolve = kretprobe_resolve,

	.setup      = kretprobe_setup,
	.teardown   = probe_teardown,
};


/* REGISTRATION */

__attribute__((constructor))
static void kprobe_pvdr_register(void)
{
#ifdef LINUX_HAS_TRACEPOINT
	pvdr_register(    &trace_pvdr);
#endif
	pvdr_register(   &kprobe_pvdr);
	pvdr_register(&kretprobe_pvdr);
}
