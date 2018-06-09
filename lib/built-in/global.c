#define _GNU_SOURCE 		/* asprintf */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ply/ply.h>
#include <ply/internal.h>

#include "built-in.h"


__ply_built_in const struct func block_func = {
	.name = "{}",
	.type = &t_vargs_func,
	.static_ret = 1,
};

static struct type *global_num_type(struct node *n)
{
	if (n->num.unsignd) {
		if (n->num.u64 <= INT_MAX)
			return &t_int;
		else if (n->num.u64 <= UINT_MAX)
			return &t_uint;
		else if (n->num.u64 <= LONG_MAX)
			return &t_long;
		else if (n->num.u64 <= ULONG_MAX)
			return &t_ulong;
		else if (n->num.u64 <= LLONG_MAX)
			return &t_llong;
		else if (n->num.u64 <= ULLONG_MAX)
			return &t_ullong;
	} else {
		if (n->num.s64 >= INT_MIN && n->num.s64 <= INT_MAX)
			return &t_int;
		else if (n->num.s64 >= LONG_MIN && n->num.s64 <= LONG_MAX)
			return &t_long;
		else if (n->num.s64 >= LLONG_MIN && n->num.s64 <= LLONG_MAX)
			return &t_llong;
	}

	assert(0);
	return NULL;
}

static int global_num_ir_post(const struct func *func, struct node *n,
			      struct ply_probe *pb)
{
	struct irstate *irs = &n->sym->irs;

	if ((n->num.unsignd && (n->num.u64 <= INT32_MAX)) ||
	    (n->num.s64 >= INT32_MIN && n->num.s64 <= INT32_MAX)) {
		irs->loc = LOC_IMM;
		irs->imm = n->num.s64;
		irs->size = 4;
		return 0;
	}

	/* we need to load the constant to a register, so ignore any
	 * advise about stack allocation. */
	irs->hint.stack = 0;

	ir_init_sym(pb->ir, n->sym);

	/* use special instruction pair to load 64-bit immediate to
	 * register. second instruction is a dummy except for the
	 * upper 32 bits of the immediate. */
	ir_emit_insn(pb->ir, LDDW_IMM((uint32_t)n->num.u64), irs->reg, 0);
	ir_emit_insn(pb->ir, INSN(0, 0, 0, 0, n->num.u64 >> 32), 0, 0);
	return 0;
}

static const struct func global_num_func = {
	.name = ":num",

	.ir_post = global_num_ir_post,	
};

static int global_string_ir_post(const struct func *func, struct node *n,
				 struct ply_probe *pb)
{
	struct irstate *irs = &n->sym->irs;

	if (node_is(n->up, "."))
		return 0;

	ir_init_sym(pb->ir, n->sym);

	ir_emit_data(pb->ir, irs->stack, n->string.data,
		     type_sizeof(n->sym->type));
	return 0;
}

static struct type *global_string_type(struct node *n)
{
	size_t len = ((strlen(n->string.data) ? : 1) + 7) & ~7;

	return type_array_of(&t_char, len);
}

static const struct func global_string_func = {
	.name = ":string",

	.ir_post = global_string_ir_post,	
};

static const struct func global_ident_func = {
	.name = ":ident",
};

extern const struct func *__start_built_ins;
extern const struct func *__stop_built_ins;

static const struct func *global_func_get(struct node *n)
{
	const struct func *func, *last;
	int err;

	last = &__stop_built_ins;

	for (func = &__start_built_ins; func < last; func++) {
		if (!strcmp(func->name, n->expr.func))
			return func;
	}

	return NULL;
}

int global_sym_alloc(struct ply_probe *pb, struct node *n)
{
	const struct func *func;
	int err;

	switch (n->ntype) {
	case N_EXPR:
		func = global_func_get(n);
		if (func)
			break;

		if (!n->expr.args) {
			n->expr.ident = 1;
			func = &global_ident_func;
		}
		break;
	case N_NUM:
		func = &global_num_func;
		break;
	case N_STRING:
		func = &global_string_func;
		break;
	}

	if (!func)
		return -ENOENT;

	err = func_static_validate(func, n);
	if (err)
		return err;

	n->sym = sym_alloc(&pb->ply->globals, n, func);

	/* infer statically known types early */
	if (n->ntype == N_NUM)
		n->sym->type = global_num_type(n);
	else if (n->ntype == N_STRING)
		n->sym->type = global_string_type(n);
	else if (func->static_ret)
		n->sym->type = func_return_type(func);
	return 0;
}

int global_probe(struct ply_probe *pb)
{
	return 0;
}

struct provider global = {
	.name = "!",

	.sym_alloc = global_sym_alloc,
	.probe = global_probe,
};

__attribute__((constructor))
static void global_init(void)
{
	provider_register(&global);
}
