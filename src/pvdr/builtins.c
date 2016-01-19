#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "../ply.h"
#include "arch.h"
#include "pvdr.h"

typedef struct builtin {
	const char *name;

	int (*annotate)  (node_t *call);
	int (*loc_assign)(node_t *call);
	int  (*compile)  (node_t *call, prog_t *prog);
} builtin_t;

enum extract_op {
	EXTRACT_OP_NONE,
	EXTRACT_OP_MASK,
	EXTRACT_OP_SHIFT,
};

static int int32_void_func(enum bpf_func_id func, enum extract_op op,
			   node_t *call, prog_t *prog)
{
	emit(prog, CALL(func));
	switch (op) {
	case EXTRACT_OP_MASK:
		/* TODO [kernel] cast imm to u32 on bitwise operators */
		emit(prog, ALU_IMM(ALU_OP_AND, BPF_REG_0, 0x7fffffff));
		break;
	case EXTRACT_OP_SHIFT:
		emit(prog, ALU_IMM(ALU_OP_RSH, BPF_REG_0, 32));
		break;
	default:
		break;
	}

	return emit_xfer(prog, call, NULL);
}

static int gid_compile(node_t *call, prog_t *prog)
{
	return int32_void_func(BPF_FUNC_get_current_uid_gid,
			       EXTRACT_OP_SHIFT, call, prog);
}

static int uid_compile(node_t *call, prog_t *prog)
{
	return int32_void_func(BPF_FUNC_get_current_uid_gid,
			       EXTRACT_OP_MASK, call, prog);
}

static int tgid_compile(node_t *call, prog_t *prog)
{
	return int32_void_func(BPF_FUNC_get_current_pid_tgid,
			       EXTRACT_OP_SHIFT, call, prog);
}

static int pid_compile(node_t *call, prog_t *prog)
{
	return int32_void_func(BPF_FUNC_get_current_pid_tgid,
			       EXTRACT_OP_MASK, call, prog);
}

static int ns_compile(node_t *call, prog_t *prog)
{
	return int32_void_func(BPF_FUNC_ktime_get_ns,
			       EXTRACT_OP_NONE, call, prog);
}

static int int_noargs_annotate(node_t *call)
{
	if (call->call.vargs)
		return -EINVAL;

	call->dyn.type = TYPE_INT;
	call->dyn.size = 8;
	return 0;
}

static int comm_compile(node_t *call, prog_t *prog)
{
	emit_stack_zero(prog, call);

	emit(prog, MOV(BPF_REG_1, BPF_REG_10));
	emit(prog, ALU_IMM(ALU_OP_ADD, BPF_REG_1, call->dyn.addr));
	emit(prog, MOV_IMM(BPF_REG_2, call->dyn.size));
	emit(prog, CALL(BPF_FUNC_get_current_comm));
	return 0;
}

static int comm_annotate(node_t *call)
{
	if (call->call.vargs)
		return -EINVAL;

	call->dyn.type = TYPE_STR;
	call->dyn.size = 16;
	return 0;
}

/* static int strcmp_compile(struct provider *p, prog_t *prog, node_t *n) */
/* { */
/* 	node_t *s1 = n->call.vargs, *s2 = n->call.vargs->next; */
/* 	ssize_t i, l; */

/* 	if ((s1->dyn->loc.type != LOC_STACK) || */
/* 	    (s2->dyn->loc.type != LOC_STACK)) */
/* 		return -EINVAL; */

/* 	l = s1->dyn->size < s2->dyn->size ? s1->dyn->size : s2->dyn->size; */
/* 	if (!l) */
/* 		emit(e, MOV_IMM(BPF_REG_0, 0)); */

/* 	for (i = 0; l; i++, l--) { */
/* 		emit(e, LDXB(BPF_REG_0, s1->dyn->loc.addr + i, BPF_REG_10)); */
/* 		emit(e, LDXB(BPF_REG_1, s2->dyn->loc.addr + i, BPF_REG_10)); */

/* 		emit(e, ALU(ALU_OP_SUB, BPF_REG_0, BPF_REG_1)); */
/* 		emit(e, JMP_IMM(JMP_JEQ, BPF_REG_1, 0, 5 * (l - 1) + 1)); */
/* 		emit(e, JMP_IMM(JMP_JNE, BPF_REG_0, 0, 5 * (l - 1) + 0)); */
/* 	} */

/* 	n->dyn->loc.type = LOC_REG; */
/* 	n->dyn->loc.reg = BPF_REG_0; */
/* 	return 0; */
/* } */

static int strcmp_annotate(node_t *call)
{
	node_t *arg = call->call.vargs;

	
	if (!arg || arg->dyn.type != TYPE_STR)
		return -EINVAL;

	arg = arg->next;
	if (!arg || arg->dyn.type != TYPE_STR)
		return -EINVAL;

	if (arg->next)
		return -EINVAL;

	call->dyn.type = TYPE_INT;
	call->dyn.size = 8;	
	return 0;
}

/* static int reg_compile(struct provider *p, prog_t *prog, node_t *n) */
/* { */
/* 	node_t *arg = n->call.vargs; */
/* 	int reg_no = arg->type == TYPE_INT ? arg->integer : (intptr_t)n->call.priv; */

/* 	emit(e, STW_IMM(BPF_REG_10, n->dyn->loc.addr, 0)); */
/* 	emit(e, STW_IMM(BPF_REG_10, n->dyn->loc.addr + 4, 0)); */

/* 	emit(e, MOV(BPF_REG_1, BPF_REG_10)); */
/* 	emit(e, ALU_IMM(ALU_OP_ADD, BPF_REG_1, n->dyn->loc.addr)); */
/* 	emit(e, MOV_IMM(BPF_REG_2, n->dyn->size)); */
/* 	emit(e, MOV(BPF_REG_3, BPF_REG_9)); */
/* 	emit(e, ALU_IMM(ALU_OP_ADD, BPF_REG_3, sizeof(uintptr_t)*reg_no)); */
/* 	emit(e, CALL(BPF_FUNC_probe_read)); */

/* 	n->dyn->loc.type = LOC_STACK; */
/* 	return 0; */
/* } */

static int reg_annotate(node_t *call)
{
	node_t *arg = call->call.vargs;
	intptr_t reg;

	if (!arg || arg->next)
		return -EINVAL;

	if (arg->type == TYPE_STR) {
		reg = arch_reg_atoi(arg->string);
		if (reg < 0)
			return reg;

		/* n->call.priv = (void *)reg; */
	} else if (arg->type != TYPE_INT) {
		return -ENOSYS;
	}

	call->dyn.type = TYPE_INT;
	call->dyn.size = 8;
	return 0;
}

static int generic_load_arg(prog_t *prog, node_t *arg, int *reg)
{
	switch (arg->dyn.type) {
	case TYPE_INT:
		switch (arg->dyn.loc) {
		case LOC_REG:
			if (arg->dyn.reg != *reg)
				emit(prog, MOV(*reg, arg->dyn.reg));
			return 0;
		case LOC_STACK:
			emit(prog, LDXDW(*reg, arg->dyn.addr, BPF_REG_10));
			return 0;

		default:
			return -EINVAL;

		}
	case TYPE_STR:
		switch (arg->dyn.loc) {
		case LOC_STACK:
			emit(prog, MOV(*reg, BPF_REG_10));
			emit(prog, ALU_IMM(ALU_OP_ADD, *reg, arg->dyn.addr));

			(*reg)++;
			if (*reg > BPF_REG_5)
				return -ENOMEM;

			if (arg->type == TYPE_STR)
				emit(prog, MOV_IMM(*reg, strlen(arg->string) + 1));
			else
				emit(prog, MOV_IMM(*reg, arg->dyn.size));

			return 0;

		default:
			return -EINVAL;
		}

	default:
		return -ENOSYS;
	}
}

static int trace_compile(node_t *call, prog_t *prog)
{
	node_t *varg;
	int err, reg = BPF_REG_0;

	node_foreach(varg, call->call.vargs) {
		reg++;
		if (reg > BPF_REG_5)
			return -ENOMEM;

		err = generic_load_arg(prog, varg, &reg);
		if (err)
			return err;
	}

	emit(prog, CALL(BPF_FUNC_trace_printk));
	return 0;
}

static int trace_annotate(node_t *call)
{
	if (!call->call.vargs)
		return -EINVAL;

	if (call->call.vargs->type != TYPE_STR)
		return -EINVAL;

	return 0;
}

static builtin_t builtins[] = {
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
		/* .compile  = strcmp_compile, */
	},
	{
		.name = "reg",
		.annotate = reg_annotate,
		/* .compile  = reg_compile, */
	},

	{
		.name = "trace",
		.annotate = trace_annotate,
		.compile  = trace_compile,
	},

	{ .name = NULL }
};

static builtin_t *builtin_find(const char *name)
{
	builtin_t *bi;
	
	for (bi = builtins; bi->name; bi++)
		if (!strcmp(bi->name, name))
			return bi;

	return 0;
}

int builtin_compile(node_t *call, prog_t *prog)
{
	builtin_t *bi = builtin_find(call->string);

	if (!bi) {
		_e("unknown builin '%s'", call->string);
		return -ENOENT;
	}

	if (!bi->compile) {
		_e("unable to compile '%s'", call->string);
		return -ENOSYS;
	}

	return bi->compile(call, prog);
}

static int default_loc_assign(node_t *call)
{
	node_t *varg, *probe = node_get_probe(call);
	int reg = BPF_REG_0;

	node_foreach(varg, call->call.vargs) {
		reg++;
		switch (varg->dyn.type) {
		case TYPE_REC:
		case TYPE_STR:
			varg->dyn.loc  = LOC_STACK;
			varg->dyn.addr = node_probe_stack_get(probe, varg->dyn.size);
			continue;

		case TYPE_INT:
			varg->dyn.loc = LOC_REG;
			varg->dyn.reg = reg;
			continue;

		default:
			_e("argument %d of '%s' is of unknown type '%s'",
			   reg, call->string, type_str(varg->dyn.type));
			return -EINVAL;
		}
	}

	return 0;
}

int builtin_loc_assign(node_t *call)
{
	builtin_t *bi = builtin_find(call->string);

	if (!bi) {
		_e("unknown builin '%s'", call->string);
		return -ENOENT;
	}

	if (!bi->loc_assign) {
		return default_loc_assign(call);
	}

	return bi->loc_assign(call);
}

int builtin_annotate(node_t *call)
{
	builtin_t *bi = builtin_find(call->string);

	if (!bi) {
		_e("unknown builin '%s'", call->string);
		return -ENOENT;
	}

	if (!bi->annotate) {
		_e("unable to annotate '%s'", call->string);
		return -ENOSYS;
	}

	return bi->annotate(call);
}
