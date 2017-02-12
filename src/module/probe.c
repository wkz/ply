#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <linux/version.h>

#include <ply/arch.h>
#include <ply/ast.h>
#include <ply/bpf-syscall.h>
#include <ply/map.h>
#include <ply/module.h>
#include <ply/ply.h>

static int probe_comm_compile(node_t *call, prog_t *prog)
{
	emit_stack_zero(prog, call);

	emit(prog, MOV(BPF_REG_1, BPF_REG_10));
	emit(prog, ALU_IMM(BPF_ADD, BPF_REG_1, call->dyn->addr));
	emit(prog, MOV_IMM(BPF_REG_2, call->dyn->size));
	emit(prog, CALL(BPF_FUNC_get_current_comm));
	return 0;
}

static int probe_comm_annotate(node_t *call)
{
	if (call->call.vargs)
		return -EINVAL;

	call->dyn->type = TYPE_STR;
	call->dyn->size = 16;
	return 0;
}
MODULE_FUNC(probe, comm);
MODULE_FUNC_ALIAS(probe, execname, comm);


static int probe_reg_compile(node_t *call, prog_t *prog)
{
	node_t *arg = call->call.vargs;

	emit_stack_zero(prog, call);

	emit(prog, MOV(BPF_REG_1, BPF_REG_10));
	emit(prog, ALU_IMM(BPF_ADD, BPF_REG_1, call->dyn->addr));
	emit(prog, MOV_IMM(BPF_REG_2, arch_reg_width()));
	emit(prog, MOV(BPF_REG_3, BPF_REG_9));
	emit(prog, ALU_IMM(BPF_ADD, BPF_REG_3, sizeof(uintptr_t)*arg->integer));
	emit(prog, CALL(BPF_FUNC_probe_read));

	if (call->dyn->loc == LOC_REG) {
		dyn_t src;

		src = *call->dyn;
		src.loc = LOC_STACK;
		return emit_xfer_dyns(prog, call->dyn, &src);
	}

	return 0;
}

static int probe_reg_loc_assign(node_t *call)
{
	node_t *probe;

	/* if the result is going to a register, allocate space on the
	 * stack as a temporary location to probe_read to. */
	if (call->dyn->loc == LOC_REG) {
		probe = node_get_probe(call);

		call->dyn->addr = node_probe_stack_get(probe, call->dyn->size);
	}

	call->call.vargs->dyn->loc = LOC_VIRTUAL;
	return 0;
}

static int probe_reg_annotate(node_t *call)
{
	node_t *arg = call->call.vargs;
	intptr_t reg;

	if (!arg || arg->next)
		return -EINVAL;

	if (arg->type == TYPE_STR) {
		reg = arch_reg_atoi(arg->string);
		if (reg < 0)
			return reg;

		arg->integer = reg;
	} else if (arg->type != TYPE_INT) {
		_e("reg only supports literals at the moment, not '%s'",
		   type_str(arg->type));
		return -ENOSYS;
	}

	call->dyn->type = TYPE_INT;
	call->dyn->size = sizeof(int64_t);
	return 0;
}
MODULE_FUNC_LOC(probe, reg);


static int probe_func_compile(node_t *call, prog_t *prog)
{
	return probe_reg_compile(call, prog);
}

static int probe_func_loc_assign(node_t *call)
{
	return probe_reg_loc_assign(call);
}

static int probe_func_annotate(node_t *call)
{
	node_t *arg = call->call.vargs;
	intptr_t reg;

	if (arg)
		return -EINVAL;

	reg = arch_reg_func();
	if (reg < 0)
		return reg;

	call->call.vargs = node_int_new(reg);
	call->dyn->type = TYPE_INT;
	call->dyn->size = sizeof(int64_t);
	call->dump = dump_sym;
	return 0;
}
MODULE_FUNC_LOC(probe, func);
MODULE_FUNC_ALIAS(probe, probefunc, func);

#ifdef LINUX_HAS_STACKMAP
static int probe_stack_compile(node_t *call, prog_t *prog)
{
	int stackmap_fd = node_map_get_fd(call);

	emit(prog, MOV(BPF_REG_1, BPF_REG_9));
	emit_ld_mapfd(prog, BPF_REG_2, stackmap_fd);
	emit(prog, MOV_IMM(BPF_REG_3, 0));
	emit(prog, CALL(BPF_FUNC_get_stackid));
	return emit_xfer_dyns(prog, call->dyn, &dyn_reg[BPF_REG_0]);
}

static int probe_stack_loc_assign(node_t *call)
{
	mdyn_t *mdyn;

	mdyn = node_map_get_mdyn(call);
	if (!mdyn) {
		mdyn = calloc(1, sizeof(*mdyn));
		assert(mdyn);

		mdyn->type = BPF_MAP_TYPE_STACK_TRACE;
		mdyn->map  = call;

		node_script_mdyn_add(node_get_script(call), mdyn);
	}

	return default_loc_assign(call);
}

static int probe_stack_annotate(node_t *call)
{
	if (call->call.vargs)
		return -EINVAL;

	call->dyn->type = TYPE_STACK;
	call->dyn->size = 8;
	return 0;
}
MODULE_FUNC_LOC(probe, stack);
#endif

static int kprobe_arg_compile(node_t *call, prog_t *prog)
{
	return probe_reg_compile(call, prog);
}

static int kprobe_arg_loc_assign(node_t *call)
{
	return probe_reg_loc_assign(call);
}

static int kprobe_arg_annotate(node_t *call)
{
	node_t *arg = call->call.vargs;
	intptr_t reg;

	if (!arg || arg->next)
		return -EINVAL;

	if (arg->type != TYPE_INT) {
		_e("arg only supports literals at the moment, not '%s'",
		   type_str(arg->type));
		return -ENOSYS;
	}

	reg = arch_reg_arg(arg->integer);
	if (reg < 0)
		return reg;

	arg->integer = reg;
	call->dyn->type = TYPE_INT;
	call->dyn->size = sizeof(int64_t);
	return 0;
}
MODULE_FUNC_LOC(kprobe, arg);


static int kretprobe_retval_compile(node_t *call, prog_t *prog)
{
	return probe_reg_compile(call, prog);
}

static int kretprobe_retval_loc_assign(node_t *call)
{
	return probe_reg_loc_assign(call);
}

static int kretprobe_retval_annotate(node_t *call)
{
	node_t *arg = call->call.vargs;
	intptr_t reg;

	if (arg)
		return -EINVAL;

	reg = arch_reg_retval();
	if (reg < 0)
		return reg;

	call->call.vargs = node_int_new(reg);
	call->call.vargs->parent = call;
	call->dyn->type = TYPE_INT;
	call->dyn->size = sizeof(int64_t);
	call->dump = dump_sym;
	return 0;
}
MODULE_FUNC_LOC(kretprobe, retval);


static const func_t *kprobe_funcs[] = {
	&probe_comm_func,
	&probe_execname_func,
	&probe_reg_func,
	&probe_func_func,
#ifdef LINUX_HAS_STACKMAP
	&probe_stack_func,
#endif

	&kprobe_arg_func,

	NULL
};

int kprobe_get_func(const module_t *m, node_t *call, const func_t **f)
{
	return generic_get_func(kprobe_funcs, call, f);
}

module_t kprobe_module = {
	.name = "kprobe",
	.get_func = kprobe_get_func,
};

static const func_t *kretprobe_funcs[] = {
	&probe_comm_func,
	&probe_execname_func,
	&probe_reg_func,
	&probe_func_func,
#ifdef LINUX_HAS_STACKMAP
	&probe_stack_func,
#endif

	&kretprobe_retval_func,

	NULL
};

int kretprobe_get_func(const module_t *m, node_t *call, const func_t **f)
{
	return generic_get_func(kretprobe_funcs, call, f);
}

module_t kretprobe_module = {
	.name = "kretprobe",
	.get_func = kretprobe_get_func,
};
