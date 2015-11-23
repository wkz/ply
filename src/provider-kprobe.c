#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <linux/bpf.h>

#include "provider.h"

struct builtin {
	const char *name;

	int (*annotate)(struct provider *p, struct fs_node *n);
	int  (*compile)(struct provider *p, struct ebpf *e, struct fs_node *n);
};

static int trace_compile(struct provider *p, struct ebpf *e, struct fs_node *n)
{
	struct fs_node *arg, *fmtlen;
	struct reg *r = e->st->reg;
	int err, reg;

	reg = BPF_REG_1;
	arg = n->call.vargs;

	err = ebpf_reg_load(e, &r[reg++], arg);
	RET_ON_ERR(err, "trace/compile/load fmt\n");

	fmtlen = fs_int_new(arg->annot.size);
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

	if (n->call.vargs->type == FS_STR)
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
};
