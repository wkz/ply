#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <ply/ast.h>
#include <ply/module.h>
#include <ply/ply.h>

#define COMMON_SIMPLE_FUNC(_name)				\
	static const func_t common_ ## _name ## _func = {	\
		.name       = #_name,				\
		.annotate   = int_noargs_annotate,		\
		.loc_assign = default_loc_assign,		\
		.compile    = common_ ## _name ## _compile,	\
	}

static int int_noargs_annotate(node_t *call)
{
	if (call->call.vargs)
		return -EINVAL;

	call->dyn->type = TYPE_INT;
	call->dyn->size = sizeof(int64_t);
	return 0;
}

enum extract_op {
	EXTRACT_OP_NONE,
	EXTRACT_OP_MASK,
	EXTRACT_OP_SHIFT,
	EXTRACT_OP_DIV_1G,
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
	case EXTRACT_OP_DIV_1G:
		emit(prog, ALU_IMM(ALU_OP_DIV, BPF_REG_0, 1000000000));
		break;
	default:
		break;
	}

	return emit_xfer_dyns(prog, call->dyn, &dyn_reg[BPF_REG_0]);
}

static int common_gid_compile(node_t *call, prog_t *prog)
{
	return int32_void_func(BPF_FUNC_get_current_uid_gid,
			       EXTRACT_OP_SHIFT, call, prog);
}
COMMON_SIMPLE_FUNC(gid);

static int common_uid_compile(node_t *call, prog_t *prog)
{
	return int32_void_func(BPF_FUNC_get_current_uid_gid,
			       EXTRACT_OP_MASK, call, prog);
}
COMMON_SIMPLE_FUNC(uid);

static int common_tgid_compile(node_t *call, prog_t *prog)
{
	return int32_void_func(BPF_FUNC_get_current_pid_tgid,
			       EXTRACT_OP_SHIFT, call, prog);
}
COMMON_SIMPLE_FUNC(tgid);

static int common_pid_compile(node_t *call, prog_t *prog)
{
	return int32_void_func(BPF_FUNC_get_current_pid_tgid,
			       EXTRACT_OP_MASK, call, prog);
}
COMMON_SIMPLE_FUNC(pid);

static int common_nsecs_compile(node_t *call, prog_t *prog)
{
	return int32_void_func(BPF_FUNC_ktime_get_ns,
			       EXTRACT_OP_NONE, call, prog);
}
COMMON_SIMPLE_FUNC(nsecs);

static int common_secs_compile(node_t *call, prog_t *prog)
{
	return int32_void_func(BPF_FUNC_ktime_get_ns,
			       EXTRACT_OP_DIV_1G, call, prog);
}
COMMON_SIMPLE_FUNC(secs);

static int common_cpu_compile(node_t *call, prog_t *prog)
{
	return int32_void_func(BPF_FUNC_get_smp_processor_id,
			       EXTRACT_OP_NONE, call, prog);
}
COMMON_SIMPLE_FUNC(cpu);


static int common_log2_compile(node_t *call, prog_t *prog)
{
	node_t *num = call->call.vargs;
	int src, dst;

	src = (num->dyn->loc == LOC_REG) ? num->dyn->reg : BPF_REG_0;
	emit_xfer_dyn(prog, &dyn_reg[src], num);

	dst = (call->dyn->loc == LOC_REG) ? call->dyn->reg : BPF_REG_1;

	emit_log2_raw(prog, dst, src);

	return emit_xfer_dyns(prog, call->dyn, &dyn_reg[dst]);
}

static int common_log2_annotate(node_t *call)
{
	if (!call->call.vargs ||
	    call->call.vargs->dyn->type != TYPE_INT ||
	    call->call.vargs->next)
		return -EINVAL;

	call->dyn->type = TYPE_INT;
	call->dyn->size = sizeof(int64_t);
	return 0;
}
MODULE_FUNC(common, log2);


static int common_mem_compile(node_t *call, prog_t *prog)
{
	node_t *addr = call->call.vargs;

	emit_stack_zero(prog, call);

	emit(prog, MOV(BPF_REG_1, BPF_REG_10));
	emit(prog, ALU_IMM(ALU_OP_ADD, BPF_REG_1, call->dyn->addr));
	emit(prog, MOV_IMM(BPF_REG_2, call->dyn->size));
	emit_xfer_dyn(prog, &dyn_reg[BPF_REG_3], addr);
	emit(prog, CALL(BPF_FUNC_probe_read));
	return 0;
}

static int common_mem_annotate(node_t *call)
{
	node_t *arg = call->call.vargs;

	if (!arg || arg->dyn->type != TYPE_INT)
		return -EINVAL;

	if (arg->next)
		return -EINVAL;
	
	call->dyn->type = TYPE_STR;
	call->dyn->size = 64;
	return 0;
}
MODULE_FUNC(common, mem);

static int common_int_compile(node_t *call, prog_t *prog)
{
	int err;

	err = common_mem_compile(call, prog);
	if (err)
		return err;

	if (call->dyn->loc == LOC_REG) {
		dyn_t src;

		src = *call->dyn;
		src.loc = LOC_STACK;
		return emit_xfer_dyns(prog, call->dyn, &src);
	}

	return 0;
}

static int common_int_loc_assign(node_t *call)
{
	node_t *probe;

	/* if the result is going to a register, allocate space on the
	 * stack as a temporary location to probe_read to. */
	if (call->dyn->loc == LOC_REG) {
		probe = node_get_probe(call);

		call->dyn->addr = node_probe_stack_get(probe, call->dyn->size);
	}

	return default_loc_assign(call);
}

static int common_int_annotate(node_t *call)
{
	node_t *arg = call->call.vargs;

	if (!arg || arg->dyn->type != TYPE_INT)
		return -EINVAL;

	if (arg->next)
		return -EINVAL;

	call->dyn->type = TYPE_INT;
	call->dyn->size = 8;
	return 0;
}
MODULE_FUNC_LOC(common, int);


static int common_strcmp_compile(node_t *call, prog_t *prog)
{
	node_t *s1 = call->call.vargs, *s2 = call->call.vargs->next;
	ssize_t i, l1, l2, l;
	int dst = call->dyn->loc == LOC_REG ? call->dyn->reg : BPF_REG_0;
	
	l1 = s1->type == TYPE_STR ? strlen(s1->string) + 1 : s1->dyn->size;
	l2 = s2->type == TYPE_STR ? strlen(s2->string) + 1 : s2->dyn->size;
	l  = l1 < l2 ? l1 : l2; 

	for (i = 0; l; i++, l--) {
		emit(prog, LDXB(      dst, s1->dyn->addr + i, BPF_REG_10));
		emit(prog, LDXB(BPF_REG_1, s2->dyn->addr + i, BPF_REG_10));
		emit(prog, ALU(ALU_OP_SUB, dst, BPF_REG_1));

		if (l == 1)
			break;

		emit(prog, JMP_IMM(JMP_JEQ, BPF_REG_1, 0, 5 * (l - 2) + 4));
		emit(prog, JMP_IMM(JMP_JNE,       dst, 0, 5 * (l - 2) + 3));
	}

	return emit_xfer_dyns(prog, call->dyn, &dyn_reg[dst]);
}

static int common_strcmp_annotate(node_t *call)
{
	node_t *arg = call->call.vargs;

	
	if (!arg || arg->dyn->type != TYPE_STR)
		return -EINVAL;

	arg = arg->next;
	if (!arg || arg->dyn->type != TYPE_STR)
		return -EINVAL;

	if (arg->next)
		return -EINVAL;

	call->dyn->type = TYPE_INT;
	call->dyn->size = sizeof(int64_t);	
	return 0;
}
MODULE_FUNC(common, strcmp);

extern const func_t printf_func;

static const func_t *common_funcs[] = {
	&common_gid_func,
	&common_uid_func,
	&common_tgid_func,
	&common_pid_func,
	&common_nsecs_func,
	&common_secs_func,
	&common_cpu_func,

	&common_log2_func,
	&common_mem_func,
	&common_int_func,
	&common_strcmp_func,

	&printf_func,

	NULL
};

int common_get_func(const module_t *m, node_t *call, const func_t **f)
{
	return generic_get_func(common_funcs, call, f);
}

module_t common_module = {
	.name = "common",
	.get_func = common_get_func,
};
