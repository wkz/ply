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

	return emit_xfer_dyn(prog, &call->dyn, &dyn_reg[BPF_REG_0]);
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

static int reg_compile(node_t *call, prog_t *prog)
{
	node_t *arg = call->call.vargs;
	int reg_no = arg->type == TYPE_INT ? arg->integer : (intptr_t)call->call.priv;

	emit_stack_zero(prog, call);

	emit(prog, MOV(BPF_REG_1, BPF_REG_10));
	emit(prog, ALU_IMM(ALU_OP_ADD, BPF_REG_1, call->dyn.addr));
	emit(prog, MOV_IMM(BPF_REG_2, arch_reg_width()));
	emit(prog, MOV(BPF_REG_3, BPF_REG_9));
	emit(prog, ALU_IMM(ALU_OP_ADD, BPF_REG_3, sizeof(uintptr_t)*reg_no));
	emit(prog, CALL(BPF_FUNC_probe_read));

	if (call->dyn.loc == LOC_REG) {
		dyn_t src;

		src = call->dyn;
		src.loc = LOC_STACK;
		return emit_xfer_dyn(prog, &call->dyn, &src);
	}

	return 0;
}

static int reg_loc_assign(node_t *call)
{
	node_t *probe;

	/* if the result is going to a register, allocate space on the
	 * stack as a temporary location to probe_read to. */
	if (call->dyn.loc == LOC_REG) {
		probe = node_get_probe(call);

		call->dyn.addr = node_probe_stack_get(probe, call->dyn.size);
	}

	if (call->call.vargs->type == TYPE_STR)
		call->call.vargs->dyn.loc = LOC_VIRTUAL;

	return 0;
}

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

		call->call.priv = (void *)reg;
	} else if (arg->type != TYPE_INT) {
		_e("reg only support literals at the moment, not '%s'",
		   type_str(arg->type));
		return -ENOSYS;
	}

	call->dyn.type = TYPE_INT;
	call->dyn.size = 8;
	return 0;
}

static int trace_compile(node_t *call, prog_t *prog)
{
	node_t *varg = call->call.vargs;
	int err, reg;

	emit(prog, MOV(BPF_REG_1, BPF_REG_10));
	emit(prog, ALU_IMM(ALU_OP_ADD, BPF_REG_1, varg->dyn.addr));
	emit(prog, MOV_IMM(BPF_REG_2, strlen(varg->string) + 1));

	reg = BPF_REG_3;
	node_foreach(varg, varg->next) {
		err = emit_xfer_dyn(prog, &dyn_reg[reg], &varg->dyn);
		if (err)
			return err;

		reg++;
	}

	emit(prog, CALL(BPF_FUNC_trace_printk));
	return 0;
}

static int trace_annotate(node_t *call)
{
	node_t *varg = call->call.vargs;
	int argc;

	if (!varg) {
		_e("format string missing from %s", node_str(call));
		return -EINVAL;
	}

	if (varg->type != TYPE_STR) {
		_e("first arguement to %s must be literal string", node_str(call));
		return -EINVAL;
	}

	for (varg = varg->next, argc = 2; varg; varg = varg->next, argc++) {
		if (varg->dyn.type != TYPE_INT) {
			_e("argument %d to %s must be of type int, but was %s",
			   argc, node_str(call), type_str(varg->dyn.type));
			return -EINVAL;
		}

		if (argc > 4) {
			_e("%s accepts a maximum of 4 arguments", node_str(call));
			return -EINVAL;
		}
	}
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
		.loc_assign = reg_loc_assign,
		.annotate   = reg_annotate,
		.compile    = reg_compile,
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
	node_t *probe = node_get_probe(call), *stmt = node_get_stmt(call);
	node_t *varg;
	int reg;

	node_foreach(varg, call->call.vargs) {
		switch (varg->dyn.type) {
		case TYPE_INT:
			reg = node_stmt_reg_get(stmt);
			if (reg > 0) {
				varg->dyn.loc = LOC_REG;
				varg->dyn.reg = reg;
				continue;
			}
			/* no registers, fall-through and allocate on
			 * the stack */
		case TYPE_REC:
		case TYPE_STR:
			varg->dyn.loc  = LOC_STACK;
			varg->dyn.addr = node_probe_stack_get(probe, varg->dyn.size);
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
