#define _GNU_SOURCE 		/* FNM_EXTMATCH */
#include <assert.h>
#include <errno.h>
#include <fnmatch.h>
#include <stdlib.h>
#include <string.h>

#include <linux/ptrace.h>

#include <ply/ply.h>
#include <ply/internal.h>

struct kprobe {
	FILE *ctrl;
};

/* regs */

static struct type t_pt_regsp = {
	.ttype = T_POINTER,

	.ptr.type = &t_pt_regs,
};

static const struct func kprobe_regs_func = {
	.name = "regs",

	.type = &t_pt_regsp,
	.static_ret = 1,
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
			node_string(&n->loc, (char *)reg),
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

static int kprobe_ir_pre(struct ply_probe *pb)
{
	struct sym **sym;

	symtab_foreach(&pb->locals, sym) {
		if ((*sym)->name && (*sym)->func == &kprobe_regs_func) {
			ir_init_sym(pb->ir, *sym);

			/* kernel sets r1 to the address of the
			 * pt_regs struct, which ply denotes as
			 * 'regs'. if we're using it we need to get a
			 * reference to it before it is clobbered. */
			ir_emit_insn(pb->ir, MOV, (*sym)->irs.reg, BPF_REG_1);
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

static int kprobe_attach_one(struct ply_probe *pb, const char *func)
{
	struct kprobe *kp = pb->provider_data;
	int ret;

	ret = fprintf(kp->ctrl, "p:%s/kprobe_%s %s\n", pb->ply->group, func, func);
	fflush(kp->ctrl);
	if (ret < 0)
		goto err;

	if (perf_event_attach(pb, func) < 0)
		goto err;

	return 0;
err:
	_e("unable to attach to 'kprobe:%s'\n", func);
	return -errno;
}

static int kprobe_attach_pattern(struct ply_probe *pb, const char *pattern)
{
	struct ksym *sym;
	int err;

	if (!pb->ply->ksyms) {
		_w("kprobe pattern without kallsyms cache available.\n");
		return kprobe_attach_one(pb, pattern);
	}

	ksyms_foreach(sym, pb->ply->ksyms) {
		if (fnmatch(pattern, sym->sym, FNM_EXTMATCH))
			continue;

		err = kprobe_attach_one(pb, sym->sym);
		if (err)
			return err;
	}

	return 0;
}

static int kprobe_attach(struct ply_probe *pb)
{
	struct kprobe *kp = pb->provider_data;
	FILE *fp;
	char *func;
	int ret;

	/* TODO: mode should be a+ and we should clean this up on
	 * detach. */
	kp->ctrl = fopen(TRACEPATH "kprobe_events", "w");
	if (!kp->ctrl)
		return -errno;

	func = strchr(pb->probe, ':');
	assert(func);
	func++;

	if (strpbrk(func, "?*[!@"))
		return kprobe_attach_pattern(pb, func);
	else
		return kprobe_attach_one(pb, func);
}

static int kprobe_probe(struct ply_probe *pb)
{
	struct kprobe *kp;

	kp = calloc(1, sizeof(*kp));
	assert(kp);

	pb->provider_data = kp;
	return 0;
}

__ply_provider struct provider kprobe = {
	.name = "kprobe",
	.prog_type = BPF_PROG_TYPE_KPROBE,

	.ir_pre = kprobe_ir_pre,
	.sym_alloc = kprobe_sym_alloc,
	.attach = kprobe_attach,
	.probe = kprobe_probe,
};
