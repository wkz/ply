#include <assert.h>
#include <errno.h>

#include <ply/ply.h>
#include <ply/internal.h>

#include "built-in.h"

static struct ply_return print_ev_handler(struct buffer_ev *ev, void *_n)
{
	struct node *n = _n;
	struct type *t = n->sym->type;
	struct tfield *f;

	tfields_foreach(f, t->sou.fields) {
		if (f != t->sou.fields)
			fputs(", ", stdout);

		type_fprint(f->type, stdout,
			    ev->data + type_offsetof(t, f->name));
	}

	putchar('\n');
	return (struct ply_return){ };
}

static int print_rewrite(const struct func *func, struct node *n,
			struct ply_probe *pb)
{
	struct node *bwrite, *exprs, *ev;
	struct buffer_evh *evh;
	uint64_t id;

	evh = n->sym->priv;
	id = evh->id;

	exprs = n->expr.args;
	n->expr.args = NULL;

	ev = node_expr(&n->loc, ":struct",
		       __node_num(&n->loc, sizeof(evh->id), NULL, &id),
		       node_expr(&n->loc, ":struct", exprs, NULL),
		       NULL);

	bwrite = node_expr(&n->loc, "bwrite",
			   node_expr(&n->loc, "regs", NULL),
			   node_expr(&n->loc, "stdbuf", NULL),
			   ev,
			   NULL);

	node_replace(n, bwrite);
	evh->priv = ev->expr.args->next;
	return 0;
}

static int print_type_infer(const struct func *func, struct node *n)
{
	struct node *expr = n->expr.args;
	struct buffer_evh *evh;

	if (n->sym->type)
		return 0;

	evh = xcalloc(1, sizeof(*evh));

	evh->handle = print_ev_handler;
	buffer_evh_register(evh);

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
};
