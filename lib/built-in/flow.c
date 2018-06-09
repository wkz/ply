#include <assert.h>
#include <errno.h>

#include <ply/ply.h>
#include <ply/internal.h>

#include "built-in.h"


struct if_priv {
	int16_t miss_label;
	int16_t end_label;
};


static int iftest_ir_post(const struct func *func, struct node *n,
				 struct ply_probe *pb)
{
	struct node *expr, *estmt, *ifn = n->up;
	struct if_priv *ifp = ifn->sym->priv;
	int reg;

	expr = n->prev;
	estmt = n->next->next->next;

	if (expr->sym->irs.loc == LOC_REG) {
		reg = expr->sym->irs.reg;
	} else {
		reg = BPF_REG_0;
		ir_emit_sym_to_reg(pb->ir, reg, expr->sym);
	}

	ifp->miss_label = ir_alloc_label(pb->ir);
	if (estmt)
		ifp->end_label = ir_alloc_label(pb->ir);

	ir_emit_insn(pb->ir, JMP_IMM(BPF_JEQ, 0, ifp->miss_label), reg, 0);
	return 0;
}

__ply_built_in const struct func iftest_func = {
	.name = ":iftest",
	.type = &t_void,
	.static_ret = 1,

	.ir_post = iftest_ir_post,
};


static int ifjump_ir_post(const struct func *func, struct node *n,
				 struct ply_probe *pb)
{
	struct node *ifn = n->up;
	struct if_priv *ifp = ifn->sym->priv;

	if (ifp->end_label)
		ir_emit_insn(pb->ir, JMP_IMM(BPF_JA, 0, ifp->end_label), 0, 0);

	ir_emit_label(pb->ir, ifp->miss_label);
	return 0;
}

__ply_built_in const struct func ifjump_func = {
	.name = ":ifjump",
	.type = &t_void,
	.static_ret = 1,

	.ir_post = ifjump_ir_post,
};


static int if_ir_post(const struct func *func, struct node *n,
			     struct ply_probe *pb)
{
	struct if_priv *ifp = n->sym->priv;

	if (ifp->end_label)
		ir_emit_label(pb->ir, ifp->end_label);
	return 0;
}

static int if_rewrite(const struct func *func, struct node *n,
			     struct ply_probe *pb)
{
	struct node *expr, *stmt;

	expr = n->expr.args;
	stmt = expr->next;

	node_insert(expr, node_expr(&n->loc, ":iftest", NULL));	
	node_insert(stmt, node_expr(&n->loc, ":ifjump", NULL));
	return 0;
}

static int if_type_infer(const struct func *func, struct node *n)
{
	struct node *expr = n->expr.args;

	if (type_base(expr->sym->type)->ttype != T_SCALAR) {
		_ne(expr, "condition of '%N' must be a scalar value, "
		    "but '%N' is of type '%T'\n", n, expr, expr->sym->type);
		return -EINVAL;
	}

	/* TODO: leaked */
	n->sym->priv = calloc(1, sizeof(struct if_priv));
	assert(n->sym->priv);

	n->sym->type = &t_void;
	return 0;
}

__ply_built_in const struct func if_func = {
	.name = "if",
	.type = &t_vargs_func,
	.static_ret = 1,
	.type_infer = if_type_infer,
	.rewrite = if_rewrite,

	.ir_post = if_ir_post,
};
