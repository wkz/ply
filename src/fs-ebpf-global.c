#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "dtl.h"
#include "provider.h"

enum extract_op {
	EXTRACT_OP_NONE,
	EXTRACT_OP_MASK,
	EXTRACT_OP_SHIFT,
};

static int int32_void_func(enum bpf_func_id func, enum extract_op op,
			   struct ebpf *e, struct fs_node *n)
{
	/* struct reg *dst; */

	/* ebpf_emit(e, CALL(func)); */
	/* switch (op) { */
	/* case EXTRACT_OP_MASK: */
	/* 	ebpf_emit(e, ALU_IMM(FS_AND, BPF_REG_0, 0xffffffff)); */
	/* 	break; */
	/* case EXTRACT_OP_SHIFT: */
	/* 	ebpf_emit(e, ALU_IMM(FS_RSH, BPF_REG_0, 32)); */
	/* 	break; */
	/* default: */
	/* 	break; */
	/* } */

	/* dst = ebpf_reg_get(e); */
	/* if (!dst) */
	/* 	RET_ON_ERR(-EBUSY, "no free regs\n"); */

	/* ebpf_emit(e, MOV(dst->reg, 0)); */
	/* ebpf_reg_bind(e, dst, n);	 */
	return 0;
}

static int gid_compile(struct provider *p, struct ebpf *e, struct fs_node *n)
{
	return int32_void_func(BPF_FUNC_get_current_uid_gid,
			       EXTRACT_OP_SHIFT, e, n);
}

static int uid_compile(struct provider *p, struct ebpf *e, struct fs_node *n)
{
	return int32_void_func(BPF_FUNC_get_current_uid_gid,
			       EXTRACT_OP_MASK, e, n);
}

static int tgid_compile(struct provider *p, struct ebpf *e, struct fs_node *n)
{
	return int32_void_func(BPF_FUNC_get_current_pid_tgid,
			       EXTRACT_OP_SHIFT, e, n);
}

static int pid_compile(struct provider *p, struct ebpf *e, struct fs_node *n)
{
	return int32_void_func(BPF_FUNC_get_current_pid_tgid,
			       EXTRACT_OP_MASK, e, n);
}

static int ns_compile(struct provider *p, struct ebpf *e, struct fs_node *n)
{
	return int32_void_func(BPF_FUNC_ktime_get_ns,
			       EXTRACT_OP_NONE, e, n);
}

static int int_noargs_annotate(struct provider *p, struct ebpf *e, struct fs_node *n)
{
	if (n->call.vargs)
		return -EINVAL;

	n->dyn->type = FS_INT;
	n->dyn->size = 8;
	return 0;
}

/* static int void_noargs_annotate(struct provider *p, struct ebpf *e, struct fs_node *n) */
/* { */
/* 	if (n->call.vargs) */
/* 		return -EINVAL; */

/* 	return 0; */
/* } */

static int comm_compile(struct provider *p, struct ebpf *e, struct fs_node *n)
{
	emit(e, MOV(BPF_REG_1, BPF_REG_10));
	emit(e, ALU_IMM(FS_ADD, BPF_REG_1, n->dyn->loc.addr));
	emit(e, MOV_IMM(BPF_REG_2, n->dyn->ssize));
	emit(e, CALL(BPF_FUNC_get_current_comm));
	return 0;
}

static int comm_annotate(struct provider *p, struct ebpf *e, struct fs_node *n)
{
	if (n->call.vargs)
		return -EINVAL;

	n->dyn->type = FS_STR;
	n->dyn->ssize = 16;
	return 0;
}

static int trace_compile(struct provider *p, struct ebpf *e, struct fs_node *n)
{
	/* struct reg *first = &e->st->reg[BPF_REG_1]; */
	/* struct reg *last  = &e->st->reg[BPF_REG_5]; */

	/* struct fs_node *len, *arg = n->call.vargs; */
	/* struct reg *r; */
	/* int err; */

	/* for (r = first; arg && r <= last; arg = arg->next) { */
	/* 	err = ebpf_reg_load(e, r++, arg); */
	/* 	RET_ON_ERR(err, "load arg\n"); */

	/* 	if (arg->dyn->type != FS_STR) */
	/* 		continue; */

	/* 	if (r > last) */
	/* 		break; */

	/* 	len = fs_int_new(strlen(arg->string) + 1); */
	/* 	err = ebpf_reg_load(e, r++, len); */
	/* 	free(len); */
	/* 	RET_ON_ERR(err, "load arg len\n"); */
	/* } */

	/* if (arg) */
	/* 	RET_ON_ERR(-ENOSPC, "out of arguments\n"); */

	/* ebpf_emit(e, CALL(BPF_FUNC_trace_printk)); */
	/* ebpf_reg_bind(e, &e->st->reg[BPF_REG_0], n); */

	/* for (; r >= first; r--) { */
	/* 	if (r->type == REG_NODE) */
	/* 		ebpf_reg_put(e, r); */
	/* } */

	return 0;
}

static int trace_annotate(struct provider *p, struct ebpf *e, struct fs_node *n)
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
		.annotate = int_noargs_annotate,
		.compile  = gid_compile,
	},
	{
		.name = "uid",
		.annotate = int_noargs_annotate,
		.compile  = uid_compile,
	},
	{
		.name = "tgid",
		.annotate = int_noargs_annotate,
		.compile  = tgid_compile,
	},
	{
		.name = "pid",
		.annotate = int_noargs_annotate,
		.compile  = pid_compile,
	},
	{
		.name = "ns",
		.annotate = int_noargs_annotate,
		.compile  = ns_compile,
	},
	{
		.name = "comm",
		.annotate = comm_annotate,
		.compile  = comm_compile,
	},
	{
		.name = "execname",
		.annotate = comm_annotate,
		.compile  = comm_compile,
	},
	{
		.name = "trace",
		.annotate = trace_annotate,
		.compile  = trace_compile,
	},

	{
		.name = "count",
		.annotate = int_noargs_annotate,
		.compile  = NULL,
	},

	{ .name = NULL }
};

int global_compile(struct provider *p, struct ebpf *e, struct fs_node *n)
{
	struct builtin *bi;
	
	for (bi = global_builtins; bi->name; bi++)
		if (!strcmp(bi->name, n->string))
			return bi->compile(p, e, n);

	_e("'%s' unknown", n->string);
	return -ENOENT;	
}

int global_annotate(struct provider *p, struct ebpf *e, struct fs_node *n)
{
	struct builtin *bi;

	for (bi = global_builtins; bi->name; bi++)
		if (!strcmp(bi->name, n->string))
			return bi->annotate(p, e, n);

	_e("'%s' unknown", n->string);
	return -ENOENT;
}
