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

static int nsecs_compile(node_t *call, prog_t *prog)
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

static int strcmp_compile(node_t *call, prog_t *prog)
{
	node_t *s1 = call->call.vargs, *s2 = call->call.vargs->next;
	ssize_t i, l1, l2, l;
	int dst = call->dyn.loc == LOC_REG ? call->dyn.reg : BPF_REG_0;
	
	l1 = s1->type == TYPE_STR ? strlen(s1->string) + 1 : s1->dyn.size;
	l2 = s2->type == TYPE_STR ? strlen(s2->string) + 1 : s2->dyn.size;
	l  = l1 < l2 ? l1 : l2; 

	for (i = 0; l; i++, l--) {
		emit(prog, LDXB(      dst, s1->dyn.addr + i, BPF_REG_10));
		emit(prog, LDXB(BPF_REG_1, s2->dyn.addr + i, BPF_REG_10));
		emit(prog, ALU(ALU_OP_SUB, dst, BPF_REG_1));

		if (l == 1)
			break;

		emit(prog, JMP_IMM(JMP_JEQ, BPF_REG_1, 0, 5 * (l - 2) + 4));
		emit(prog, JMP_IMM(JMP_JNE,       dst, 0, 5 * (l - 2) + 3));
	}

	return emit_xfer_dyn(prog, &call->dyn, &dyn_reg[dst]);
}

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

static int printf_compile(node_t *call, prog_t *prog)
{
	node_t *rec = call->call.vargs->next;
	int map_fd = node_map_get_fd(call);

	if (call->dyn.size > sizeof(int64_t)) {
		size_t diff = call->dyn.size - sizeof(int64_t);
		ssize_t addr = rec->dyn.addr + rec->dyn.size;

		emit(prog, MOV_IMM(BPF_REG_0, 0));
		for (; diff; addr += sizeof(int64_t), diff -= sizeof(int64_t))
			emit(prog, STXDW(BPF_REG_10, addr, BPF_REG_0));
	}
		
	/* lookup index into print buffer, stored out-of-band after
	 * the last entry */
	emit(prog, MOV_IMM(BPF_REG_0, PRINTF_BUF_LEN));
	emit(prog, STXDW(BPF_REG_10, call->dyn.addr, BPF_REG_0));
	emit_map_lookup_raw(prog, map_fd, call->dyn.addr);

	/* if we get a null pointer, index is 0 */
	emit(prog, JMP_IMM(JMP_JNE, BPF_REG_0, 0, 2));
	emit(prog, STXDW(BPF_REG_10, call->dyn.addr, BPF_REG_0));
	emit(prog, JMP_IMM(JMP_JA, 0, 0, 5));

	/* otherwise, get it from the out-of-band value */
	emit_read_raw(prog, call->dyn.addr, BPF_REG_0, sizeof(int64_t));

	/* at this point call->dyn.addr is loaded with the index of
	 * the buffer */
	emit_map_lookup_raw(prog, map_fd, call->dyn.addr);

	/* lookup SHOULD return NULL, otherwise user-space has not
	 * been able to empty the buffer in time. */
	emit(prog, JMP_IMM(JMP_JEQ, BPF_REG_0, 0, 3));

	/* mark record with the overflow bit so that user-space at
	 * least knows when data has been lost */
	emit(prog, LDXDW(BPF_REG_0, rec->rec.vargs->dyn.addr, BPF_REG_10));
	emit(prog, ALU_IMM(ALU_OP_OR, BPF_REG_0, PRINTF_META_OF));
	emit(prog, STXDW(BPF_REG_10, rec->rec.vargs->dyn.addr, BPF_REG_0));

	/* store record */
	emit_map_update_raw(prog, map_fd, call->dyn.addr, rec->dyn.addr);

	/* calculate next index and store that in the record */
	emit(prog, LDXDW(BPF_REG_0, call->dyn.addr, BPF_REG_10));
	emit(prog, ALU_IMM(ALU_OP_ADD, BPF_REG_0, 1));
	emit(prog, ALU_IMM(ALU_OP_AND, BPF_REG_0, PRINTF_BUF_LEN - 1));
	emit(prog, STXDW(BPF_REG_10, rec->rec.vargs->dyn.addr, BPF_REG_0));

	/* store next index */
	emit(prog, MOV_IMM(BPF_REG_0, PRINTF_BUF_LEN));
	emit(prog, STXDW(BPF_REG_10, call->dyn.addr, BPF_REG_0));
	emit_map_update_raw(prog, map_fd, call->dyn.addr, rec->dyn.addr);
	return 0;
}

static int printf_walk(node_t *n, void *_mdyn)
{
	mdyn_t *mdyn = _mdyn;
	size_t largest, new;

	if (n->type != TYPE_CALL || strcmp(n->string, "printf"))
		return 0;

	if (!mdyn->map)
		mdyn->map = n;
	else {
		/* printf records can be of different sizes, store
		 * pointer to the printf call with the largest record
		 * so that all will fit. */
		largest = mdyn->map->call.vargs->next->dyn.size;
		new = n->call.vargs->next->dyn.size;

		if (new > largest)
			mdyn->map = n;
	}

	return 0;
}

static size_t printf_store_mdyn(node_t *script)
{
	mdyn_t *mdyn;

	mdyn = calloc(1, sizeof(*mdyn));
	assert(mdyn);

	node_walk(script, NULL, printf_walk, mdyn);

	if (!script->script.mdyns)
		script->script.mdyns = mdyn;
	else
		insque_tail(mdyn, script->script.mdyns);

	return mdyn->map->call.vargs->next->dyn.size;
}

static size_t printf_rec_size(node_t *script)
{
	mdyn_t *mdyn;

	for (mdyn = script->script.mdyns; mdyn; mdyn = mdyn->next) {
		if (!strcmp(mdyn->map->string, "printf"))
			return mdyn->map->call.vargs->next->dyn.size;
	}

	printf_store_mdyn(script);

	for (mdyn = script->script.mdyns; mdyn; mdyn = mdyn->next) {
		if (!strcmp(mdyn->map->string, "printf"))
			return mdyn->map->call.vargs->next->dyn.size;
	}

	assert(mdyn);
	return 0;
}

static int printf_loc_assign(node_t *call)
{
	node_t *probe = node_get_probe(call);
	node_t *varg = call->call.vargs;
	node_t *rec  = varg->next;
	/* ssize_t addr; */
	size_t rec_max_size;

	/* no need to store any format strings in the kernel, we can
	 * fetch them from the AST, just store a format id instead. */
	varg->dyn.loc = LOC_VIRTUAL;

	rec_max_size  = printf_rec_size(probe->parent);
	rec->dyn.loc  = LOC_STACK;
	rec->dyn.addr = node_probe_stack_get(probe, rec_max_size);
	/* node_foreach(varg, varg->next) { */
	/* 	varg->dyn.loc  = LOC_STACK; */
	/* 	varg->dyn.addr = addr; */
	/* 	addr += varg->dyn.size; */
	/* } */

	/* allocate storage for printf's map key */
	call->dyn.size = rec_max_size + sizeof(int64_t) - rec->dyn.size;
	call->dyn.addr = node_probe_stack_get(probe, call->dyn.size);
	return 0;
}

static int printf_annotate(node_t *call)
{
	node_t *script = node_get_script(call);
	node_t *varg = call->call.vargs;
	node_t *meta, *rec;

	if (!varg) {
		_e("format string missing from %s", node_str(call));
		return -EINVAL;
	}

	if (varg->type != TYPE_STR) {
		_e("first arguement to %s must be literal string", node_str(call));
		return -EINVAL;
	}

	/* rewrite printf("a:%d b:%d", a(), b())
         *    into printf("a:%d b:%d", [meta, a(), b()])
	 */
	meta = node_int_new(script->script.fmt_id++);
	meta->dyn.type = TYPE_INT;
	meta->dyn.size = 8;
	meta->next = varg->next;
	rec = node_rec_new(meta);
	varg->next = rec;

	rec->parent = call;
	node_foreach(varg, rec->rec.vargs) {
		varg->parent = rec;
	}

	script->script.printf[meta->integer] = call;
	return 0;
}

#define BUILTIN_INT_VOID(_name) {			\
		.name     = #_name,			\
		.annotate = int_noargs_annotate,	\
		.compile  = _name ## _compile,		\
	}

#define BUILTIN(_name) {			\
		.name     = #_name,		\
		.annotate = _name ## _annotate,	\
		.compile  = _name ## _compile,	\
	}

#define BUILTIN_ALIAS(_name, _real) {		\
		.name     = #_name,		\
		.annotate = _real ## _annotate,	\
		.compile  = _real ## _compile,	\
	}

static builtin_t builtins[] = {
	{
		.name = "reg",
		.annotate   = reg_annotate,
		.loc_assign = reg_loc_assign,
		.compile    = reg_compile,
	},

	{
		.name = "printf",
		.annotate   = printf_annotate,
		.loc_assign = printf_loc_assign,
		.compile    = printf_compile,
	},

	BUILTIN_INT_VOID(  gid),
	BUILTIN_INT_VOID(  uid),
	BUILTIN_INT_VOID( tgid),
	BUILTIN_INT_VOID(  pid),
	BUILTIN_INT_VOID(nsecs),

	BUILTIN(comm),
	BUILTIN_ALIAS(execname, comm),

	BUILTIN(strcmp),

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
