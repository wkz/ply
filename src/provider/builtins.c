#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "../ply.h"
#include "provider.h"

enum extract_op {
	EXTRACT_OP_NONE,
	EXTRACT_OP_MASK,
	EXTRACT_OP_SHIFT,
};

static int int32_void_func(enum bpf_func_id func, enum extract_op op,
			   struct ebpf *e, node_t *n)
{
	/* struct reg *dst; */

	emit(e, CALL(func));
	switch (op) {
	case EXTRACT_OP_MASK:
		/* TODO [kernel] cast imm to u32 on bitwise operators */
		emit(e, ALU_IMM(ALU_OP_AND, BPF_REG_0, 0x7fffffff));
		break;
	case EXTRACT_OP_SHIFT:
		emit(e, ALU_IMM(ALU_OP_RSH, BPF_REG_0, 32));
		break;
	default:
		break;
	}

	n->dyn->loc.type = LOC_REG;
	n->dyn->loc.reg = 0;
	return 0;
}

static int gid_compile(struct provider *p, struct ebpf *e, node_t *n)
{
	return int32_void_func(BPF_FUNC_get_current_uid_gid,
			       EXTRACT_OP_SHIFT, e, n);
}

static int uid_compile(struct provider *p, struct ebpf *e, node_t *n)
{
	return int32_void_func(BPF_FUNC_get_current_uid_gid,
			       EXTRACT_OP_MASK, e, n);
}

static int tgid_compile(struct provider *p, struct ebpf *e, node_t *n)
{
	return int32_void_func(BPF_FUNC_get_current_pid_tgid,
			       EXTRACT_OP_SHIFT, e, n);
}

static int pid_compile(struct provider *p, struct ebpf *e, node_t *n)
{
	return int32_void_func(BPF_FUNC_get_current_pid_tgid,
			       EXTRACT_OP_MASK, e, n);
}

static int ns_compile(struct provider *p, struct ebpf *e, node_t *n)
{
	return int32_void_func(BPF_FUNC_ktime_get_ns,
			       EXTRACT_OP_NONE, e, n);
}

static int int_noargs_annotate(struct provider *p, struct ebpf *e, node_t *n)
{
	if (n->call.vargs)
		return -EINVAL;

	n->dyn->type = TYPE_INT;
	n->dyn->size = 8;
	return 0;
}

static int comm_compile(struct provider *p, struct ebpf *e, node_t *n)
{
	size_t i;

	/* TODO [kernel] recognize that argument is an out parameter */
	for (i = 0; i < n->dyn->size; i += 4)
		emit(e, STW_IMM(BPF_REG_10, n->dyn->loc.addr + i, 0));

	emit(e, MOV(BPF_REG_1, BPF_REG_10));
	emit(e, ALU_IMM(ALU_OP_ADD, BPF_REG_1, n->dyn->loc.addr));
	emit(e, MOV_IMM(BPF_REG_2, n->dyn->size));
	emit(e, CALL(BPF_FUNC_get_current_comm));
	n->dyn->loc.type = LOC_STACK;
	return 0;
}

static int comm_annotate(struct provider *p, struct ebpf *e, node_t *n)
{
	if (n->call.vargs)
		return -EINVAL;

	n->dyn->type = TYPE_STR;
	n->dyn->size = 16;
	return 0;
}

static int strcmp_compile(struct provider *p, struct ebpf *e, node_t *n)
{
	node_t *s1 = n->call.vargs, *s2 = n->call.vargs->next;
	ssize_t i, l;

	if ((s1->dyn->loc.type != LOC_STACK) ||
	    (s2->dyn->loc.type != LOC_STACK))
		return -EINVAL;

	l = s1->dyn->size < s2->dyn->size ? s1->dyn->size : s2->dyn->size;
	if (!l)
		emit(e, MOV_IMM(BPF_REG_0, 0));

	for (i = 0; l; i++, l--) {
		emit(e, LDXB(BPF_REG_0, s1->dyn->loc.addr + i, BPF_REG_10));
		emit(e, LDXB(BPF_REG_1, s2->dyn->loc.addr + i, BPF_REG_10));

		emit(e, ALU(ALU_OP_SUB, BPF_REG_0, BPF_REG_1));
		emit(e, JMP_IMM(JMP_JEQ, BPF_REG_1, 0, 5 * (l - 1) + 1));
		emit(e, JMP_IMM(JMP_JNE, BPF_REG_0, 0, 5 * (l - 1) + 0));
	}

	n->dyn->loc.type = LOC_REG;
	n->dyn->loc.reg = BPF_REG_0;
	return 0;
}

static int strcmp_annotate(struct provider *p, struct ebpf *e, node_t *n)
{
	node_t *arg = n->call.vargs;

	
	if (!arg || arg->dyn->type != TYPE_STR)
		return -EINVAL;

	arg = arg->next;
	if (!arg || arg->dyn->type != TYPE_STR)
		return -EINVAL;

	if (arg->next)
		return -EINVAL;

	n->dyn->type = TYPE_INT;
	n->dyn->size = 8;	
	return 0;
}

static int generic_load_arg(struct ebpf *e, node_t *arg, int *reg)
{
	switch (arg->dyn->type) {
	case TYPE_INT:
		switch (arg->dyn->loc.type) {
		case LOC_REG:
			if (arg->dyn->loc.reg != *reg)
				emit(e, MOV(*reg, arg->dyn->loc.reg));
			return 0;
		case LOC_STACK:
			emit(e, LDXDW(*reg, arg->dyn->loc.addr, BPF_REG_10));
			return 0;

		default:
			return -EINVAL;

		}
	case TYPE_STR:
		switch (arg->dyn->loc.type) {
		case LOC_STACK:
			emit(e, MOV(*reg, BPF_REG_10));
			emit(e, ALU_IMM(ALU_OP_ADD, *reg, arg->dyn->loc.addr));

			(*reg)++;
			if (*reg > BPF_REG_5)
				return -ENOMEM;

			if (arg->type == TYPE_STR)
				emit(e, MOV_IMM(*reg, strlen(arg->string) + 1));
			else
				emit(e, MOV_IMM(*reg, arg->dyn->size));

			return 0;

		default:
			return -EINVAL;
		}

	default:
		return -ENOSYS;
	}
}

static int trace_compile(struct provider *p, struct ebpf *e, node_t *n)
{
	node_t *varg;
	int err, reg = BPF_REG_0;

	node_foreach(varg, n->call.vargs) {
		reg++;
		if (reg > BPF_REG_5)
			return -ENOMEM;

		err = generic_load_arg(e, varg, &reg);
		if (err)
			return err;
	}

	emit(e, CALL(BPF_FUNC_trace_printk));
	return 0;
}

static int trace_annotate(struct provider *p, struct ebpf *e, node_t *n)
{
	if (!n->call.vargs)
		return -EINVAL;

	if (n->call.vargs->type != TYPE_STR)
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
		.name = "strcmp",
		.annotate = strcmp_annotate,
		.compile  = strcmp_compile,
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

int global_compile(struct provider *p, struct ebpf *e, node_t *n)
{
	struct builtin *bi;
	
	for (bi = global_builtins; bi->name; bi++)
		if (!strcmp(bi->name, n->string))
			return bi->compile(p, e, n);

	_e("'%s' unknown", n->string);
	return -ENOENT;	
}

int global_annotate(struct provider *p, struct ebpf *e, node_t *n)
{
	struct builtin *bi;

	for (bi = global_builtins; bi->name; bi++)
		if (!strcmp(bi->name, n->string))
			return bi->annotate(p, e, n);

	_e("'%s' unknown", n->string);
	return -ENOENT;
}
