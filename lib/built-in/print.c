#include <assert.h>
#include <errno.h>

#include <ply/ply.h>
#include <ply/internal.h>

#include "built-in.h"

static struct evreturn print_ev_handler(struct event *ev, void *_n)
{
	struct node *n = _n, *evn, *vals;
	struct type *t;
	struct tfield *f;

	evn = n->expr.args;
	vals = evn->expr.args->next;
	t = vals->sym->type;

	tfields_foreach(f, t->sou.fields) {
		if (f != t->sou.fields)
			fputs(", ", stdout);

		type_fprint(f->type, stdout,
			    ev->data + type_offsetof(t, f->name));
	}

	putchar('\n');
	return (struct evreturn){ };
}

static int print_ir_post(const struct func *func, struct node *n,
			     struct ply_probe *pb)
{
	struct node *evn, *regs;

	evn = n->expr.args;
	regs = evn->next;

	ir_emit_perf_event_output(pb->ir, pb->ply->evp_sym, regs->sym, evn->sym);
	return 0;
}

static int print_rewrite(const struct func *func, struct node *n,
			struct ply_probe *pb)
{
	struct node *exprs, *evn;
	struct evhandler *evh;

	evh = n->sym->priv;

	exprs = n->expr.args;

	evn = node_expr(&n->loc, ":struct",
		       __node_num(&n->loc, sizeof(evh->type), NULL, &evh->type),
		       node_expr(&n->loc, ":struct", NULL),
		       NULL);

	node_replace(exprs, evn);
	evn->next = NULL;

	node_expr_append(&n->loc, evn->expr.args->next, exprs);
	node_expr_append(&n->loc, n, node_expr(&n->loc, "regs", NULL));
	return 0;
}

static int print_type_infer(const struct func *func, struct node *n)
{
	struct node *expr = n->expr.args;
	struct evhandler *evh;

	if (n->sym->type)
		return 0;

	evh = calloc(1, sizeof(struct evhandler));
	assert(evh);

	evh->priv = n;
	evh->handle = print_ev_handler;
	evhandler_register(evh);

	/* TODO: leaked */
	n->sym->priv = evh;
	n->sym->type = &t_void;
	return 0;
}

__ply_built_in const struct func print_func = {
	.name = "print",
	.type = &t_vargs_func,
	.type_infer = print_type_infer,

	.rewrite = print_rewrite,

	.ir_post = print_ir_post,
};
