#define _GNU_SOURCE 		/* FNM_EXTMATCH */
#include <assert.h>
#include <errno.h>
#include <glob.h>
#include <stdlib.h>
#include <string.h>

#include <linux/ptrace.h>

#include <ply/ply.h>
#include <ply/internal.h>

#include "xprobe.h"
#include "kprobe.h"


/* retval */

static int kretprobe_retval_rewrite(const struct func *func, struct node *n,
				    struct ply_probe *pb)
{
	struct node *new;
	const char *reg;

	n->sym->type->priv = pb->ply->ksyms;

	reg = arch_register_return();

	/* retval => (*regs).REG */
	new = node_expr(&n->loc, ".",
			node_expr(&n->loc, "u*", node_expr_ident(&n->loc, "regs"), NULL),
			node_string(&n->loc, strdup(reg)),
			NULL);

	node_replace(n, new);
	return 0;
}

static const struct func kretprobe_retval_func = {
	.name = "retval",

	/* for now, in the future we could read dwarf symbols to
	 * figure out the real type. */
	.type = &t_long,
	.static_ret = 1,

	.rewrite = kretprobe_retval_rewrite,
};


static int kretprobe_sym_alloc(struct ply_probe *pb, struct node *n)
{
	const struct func *func = NULL;
	int err;

	switch (n->ntype) {
	case N_EXPR:
		if (!strcmp(n->expr.func, "regs")) {
			func = &kprobe_regs_func;
			n->expr.ident = 1;
		} else if (!strcmp(n->expr.func, "retval")) {
			func = &kretprobe_retval_func;
			n->expr.ident = 1;
		}
		break;
	default:
		break;
	}

	if (!func)
		return -ENOENT;

	err = func_static_validate(func, n);
	if (err)
		return err;

	n->sym = sym_alloc(&pb->locals, n, func);

	if (func->static_ret)
		n->sym->type = func_return_type(func);
	return 0;
}



static int kretprobe_probe(struct ply_probe *pb)
{
	struct xprobe *xp;

	xp = xcalloc(1, sizeof(*xp));
	xp->type = 'r';
	xp->ctrl_name = "kprobe_events";
	xp->pattern = strchr(pb->probe, ':');
	assert(xp->pattern);
	xp->pattern++;

	pb->provider_data = xp;
	return 0;
}

__ply_provider struct provider kretprobe = {
	.name = "kretprobe",
	.prog_type = BPF_PROG_TYPE_KPROBE,

	.ir_pre    = kprobe_ir_pre,
	.sym_alloc = kretprobe_sym_alloc,
	.probe     = kretprobe_probe,

	.attach = xprobe_attach,
	.detach = xprobe_detach,
};
