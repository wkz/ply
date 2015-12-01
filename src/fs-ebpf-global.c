#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "provider.h"

static int gid_compile(struct provider *p, struct ebpf *e, struct fs_node *n)
{
	ebpf_emit(e, CALL(BPF_FUNC_get_current_uid_gid));
	ebpf_emit(e, ALU_IMM(FS_RSH, BPF_REG_0, 32));
	ebpf_reg_bind(e, &e->st->reg[0], n);
	return 0;
}

static int uid_compile(struct provider *p, struct ebpf *e, struct fs_node *n)
{
	ebpf_emit(e, CALL(BPF_FUNC_get_current_uid_gid));
	ebpf_emit(e, ALU_IMM(FS_AND, BPF_REG_0, 0xffffffff));
	ebpf_reg_bind(e, &e->st->reg[0], n);
	return 0;
}

static int tgid_compile(struct provider *p, struct ebpf *e, struct fs_node *n)
{
	ebpf_emit(e, CALL(BPF_FUNC_get_current_pid_tgid));
	ebpf_emit(e, ALU_IMM(FS_RSH, BPF_REG_0, 32));
	ebpf_reg_bind(e, &e->st->reg[0], n);
	return 0;
}

static int pid_compile(struct provider *p, struct ebpf *e, struct fs_node *n)
{
	ebpf_emit(e, CALL(BPF_FUNC_get_current_pid_tgid));
	ebpf_emit(e, ALU_IMM(FS_AND, BPF_REG_0, 0xffffffff));
	ebpf_reg_bind(e, &e->st->reg[0], n);
	return 0;
}

static int noargs_annotate(struct provider *p, struct fs_node *n)
{
	if (n->call.vargs)
		return -EINVAL;

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

static struct builtin global_builtins[] = {
	{
		.name = "gid",
		.annotate = noargs_annotate,
		.compile  = gid_compile,
	},
	{
		.name = "uid",
		.annotate = noargs_annotate,
		.compile  = uid_compile,
	},
	{
		.name = "tgid",
		.annotate = noargs_annotate,
		.compile  = tgid_compile,
	},
	{
		.name = "pid",
		.annotate = noargs_annotate,
		.compile  = pid_compile,
	},
	{
		.name = "trace",
		.annotate = trace_annotate,
		.compile  = trace_compile,
	},

	{ .name = NULL }
};

int global_compile(struct provider *p, struct ebpf *e, struct fs_node *n)
{
	struct builtin *bi;

	for (bi = global_builtins; bi->name; bi++)
		if (!strcmp(bi->name, n->string))
			return bi->compile(p, e, n);

	return -ENOENT;	
}

int global_annotate(struct provider *p, struct fs_node *n)
{
	struct builtin *bi;

	for (bi = global_builtins; bi->name; bi++)
		if (!strcmp(bi->name, n->string))
			return bi->annotate(p, n);

	return -ENOENT;
}
