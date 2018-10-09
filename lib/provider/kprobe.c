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

/* regs */

static struct type t_pt_regsp = {
	.ttype = T_POINTER,

	.ptr.type = &t_pt_regs,
};

const struct func kprobe_regs_func = {
	.name = "regs",

	.type = &t_pt_regsp,
	.static_ret = 1,
};

/* caller */

static int caller_fprint(struct type *t, FILE *fp, const void *data)
{
	struct ksyms *ks = t->priv;
	uintptr_t addr;

	addr = *((uintptr_t *)data);

	return ksym_fprint(ks, fp, addr);
}

static struct type t_caller_t = {
	.ttype = T_TYPEDEF,

	.tdef = {
		.name = "caller_t",
		.type = &t_reg_t,
	},

	.fprint = caller_fprint,
};

static int kprobe_caller_rewrite(const struct func *func, struct node *n,
				 struct ply_probe *pb)
{
	struct node *new;
	const char *reg;

	n->sym->type->priv = pb->ply->ksyms;

	reg = arch_register_pc();

	/* argN => (*regs).REG */
	new = node_expr(&n->loc, ".",
			node_expr(&n->loc, "u*", node_expr_ident(&n->loc, "regs"), NULL),
			node_string(&n->loc, strdup(reg)),
			NULL);

	node_replace(n, new);
	return 0;
}

static const struct func kprobe_caller_func = {
	.name = "caller",

	/* for now, in the future we could read dwarf symbols to
	 * figure out the real type. */
	.type = &t_caller_t,
	.static_ret = 1,

	.rewrite = kprobe_caller_rewrite,
};


/* argN */

static inline int is_arg(const char *name)
{
	return (strstr(name, "arg") == name)
		&& (strlen(name) == 4)
		&& (name[3] >= '0' && name[3] <= '9');
}

static int kprobe_arg_rewrite(const struct func *func, struct node *n,
			      struct ply_probe *pb)
{
	struct node *new;
	const char *reg;
	int arg;

	arg = n->expr.func[3] - '0';
	reg = arch_register_argument(arg);
	if (!reg) {
		_e("%#N: the location of %N is unknown\n", n, n);

		/* TODO: add ABI mappings for specifying arguments
		 * passed on the stack. */
		return -EINVAL;
	}

	/* argN => (*regs).REG */
	new = node_expr(&n->loc, ".",
			node_expr(&n->loc, "u*", node_expr_ident(&n->loc, "regs"), NULL),
			node_string(&n->loc, strdup(reg)),
			NULL);

	node_replace(n, new);
	return 0;
}

static const struct func kprobe_arg_func = {
	.name = "argN",

	/* for now, in the future we could read dwarf symbols to
	 * figure out the real type. */
	.type = &t_ulong,
	.static_ret = 1,

	.rewrite = kprobe_arg_rewrite,
};


/*  */

int kprobe_ir_pre(struct ply_probe *pb)
{
	struct sym **sym;

	symtab_foreach(&pb->locals, sym) {
		if ((*sym)->name && (*sym)->func == &kprobe_regs_func) {
			ir_init_sym(pb->ir, *sym);

			/* 'regs' is a pointer, but the kernel
			 * verifier will mark 32-bit accesses as
			 * invalid even on 32-bit ISAs, so we always
			 * treat it as a 64-bit value. */
			(*sym)->irs.size = sizeof(uint64_t);
			
			/* Kernel sets r1 to the address of the
			 * pt_regs struct, which ply denotes as
			 * 'regs'. If we're using it we need to get a
			 * reference to it before it is clobbered. */
			ir_emit_reg_to_sym(pb->ir, *sym, BPF_REG_1);
		}
	}

	return 0;
}

static int kprobe_sym_alloc(struct ply_probe *pb, struct node *n)
{
	const struct func *func = NULL;
	int err;

	switch (n->ntype) {
	case N_EXPR:
		if (!strcmp(n->expr.func, "regs")) {
			func = &kprobe_regs_func;
			n->expr.ident = 1;
		} else if (!strcmp(n->expr.func, "caller")) {
			func = &kprobe_caller_func;
			n->expr.ident = 1;
		} else if (is_arg(n->expr.func)) {
			func = &kprobe_arg_func;
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



static int kprobe_probe(struct ply_probe *pb)
{
	struct xprobe *xp;

	xp = xcalloc(1, sizeof(*xp));
	xp->type = 'p';
	xp->ctrl_name = "kprobe_events";
	xp->pattern = strchr(pb->probe, ':');
	assert(xp->pattern);
	xp->pattern++;

	pb->provider_data = xp;
	return 0;
}

__ply_provider struct provider kprobe = {
	.name = "kprobe",
	.prog_type = BPF_PROG_TYPE_KPROBE,

	.ir_pre    = kprobe_ir_pre,
	.sym_alloc = kprobe_sym_alloc,
	.probe     = kprobe_probe,

	.attach = xprobe_attach,
	.detach = xprobe_detach,
};
