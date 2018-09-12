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

static struct evreturn exit_ev_handler(struct event *ev, void *_null)
{
	int *code = (void *)ev->data;

	_d("exit:%d\n", *code);
	return (struct evreturn){ .val = *code, .exit = 1 };
}

static int exit_ir_post(const struct func *func, struct node *n,
			     struct ply_probe *pb)
{
	struct node *ev, *regs;

	ev = n->expr.args;
	regs = ev->next;

	ir_emit_perf_event_output(pb->ir, pb->ply->evp_sym, regs->sym, ev->sym);
	return 0;
}

static int exit_rewrite(const struct func *func, struct node *n,
			struct ply_probe *pb)
{
	struct node *expr, *ev;
	struct evhandler *evh;

	evh = n->sym->priv;

	expr = n->expr.args;

	ev = node_expr(&n->loc, ":struct",
		       __node_num(&n->loc, sizeof(evh->type), NULL, &evh->type),
		       NULL);

	node_replace(expr, ev);
	node_expr_append(&n->loc, ev, expr);
	node_expr_append(&n->loc, n, node_expr(&n->loc, "regs", NULL));
	return 0;
}

static int exit_type_infer(const struct func *func, struct node *n)
{
	struct node *expr = n->expr.args;
	struct evhandler *evh;

	if (n->sym->type)
		return 0;

	if (type_base(expr->sym->type)->ttype != T_SCALAR) {
		_ne(expr, "argument to '%N' must be a scalar value, "
		    "but '%N' is of type '%T'\n", n, expr, expr->sym->type);
		return -EINVAL;
	}

	evh = calloc(1, sizeof(struct evhandler));
	assert(evh);

	evh->handle = exit_ev_handler;
	evhandler_register(evh);

	/* TODO: leaked */
	n->sym->priv = evh;
	n->sym->type = &t_void;
	return 0;
}

__ply_built_in const struct func exit_func = {
	.name = "exit",
	.type = &t_unary_func,
	.type_infer = exit_type_infer,

	.rewrite = exit_rewrite,

	.ir_post = exit_ir_post,
};
