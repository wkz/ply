#define _GNU_SOURCE 		/* FNM_EXTMATCH */
#include <assert.h>
#include <errno.h>
#include <fnmatch.h>
#include <glob.h>
#include <stdlib.h>
#include <string.h>

#include <linux/ptrace.h>

#include <ply/ply.h>
#include <ply/internal.h>

#include "xprobe.h"

struct kprobe {
	FILE *ctrl;
	char *pattern;
	char stem[0x40];

	size_t n_evs;
	int *evfds;
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

/* caller */

static int caller_fprint(struct type *t, FILE *fp, const void *data)
{
	struct ksyms *ks = t->tdef.priv;
	const struct ksym *sym;
	unsigned long addr;

	addr = *((unsigned long *)data);
	if (ks && (sym = ksym_get(ks, addr))) {
		if (sym->addr == addr)
			return fputs(sym->sym, fp);
		else
			return fprintf(fp, "%s+%"PRIuPTR, sym->sym, addr - sym->addr);
	} else {
		int w = (int)(type_sizeof(t) * 2);

		return fprintf(fp, "<%*.*lx>", w, w, *((unsigned long *)data));
	}
}

static struct type t_caller_t = {
	.ttype = T_TYPEDEF,

	.tdef = {
		.name = "caller_t",
		.type = &t_reg_t,
		.fprint = caller_fprint,
	},
};

static int kprobe_caller_rewrite(const struct func *func, struct node *n,
				 struct ply_probe *pb)
{
	struct node *new;
	const char *reg;

	n->sym->type->tdef.priv = pb->ply->ksyms;

	reg = arch_register_pc();

	/* argN => (*regs).REG */
	new = node_expr(&n->loc, ".",
			node_expr(&n->loc, "u*", node_expr_ident(&n->loc, "regs"), NULL),
			node_string(&n->loc, (char *)reg),
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


static int kprobe_detach(struct ply_probe *pb)
{
	struct kprobe *kp = pb->provider_data;
	glob_t gl;
	size_t i, evstart;
	int err, pending;

	if (!kp->ctrl)
		return 0;

	for (i = 0; i < kp->n_evs; i++)
		close(kp->evfds[i]);

	err = xprobe_glob(pb, &gl);
	if (err)
		return err;

	assert(gl.gl_pathc == kp->n_evs);

	evstart = strlen(TRACEPATH "events/");
	pending = 0;

	for (i = 0; i < gl.gl_pathc; i++) {
		fputs("-:", kp->ctrl);
		pending += 2;
		fputs(&gl.gl_pathv[i][evstart], kp->ctrl);
		pending += strlen(&gl.gl_pathv[i][evstart]);
		fputc('\n', kp->ctrl);
		pending++;

		/* The kernel parser doesn't deal with a probe definition
		 * being split across two writes. So if there's less than
		 * 512 bytes left, flush the buffer. */
		if (pending > (0x1000 - 0x200)) {
			err = fflush(kp->ctrl);
			if (err)
				break;

			pending = 0;
		}
	}

	globfree(&gl);
	fclose(kp->ctrl);
	return err;
}


static int kprobe_create_pattern(struct ply_probe *pb)
{
	struct kprobe *kp = pb->provider_data;
	struct ksym *sym;
	int err, pending = 0;

	ksyms_foreach(sym, pb->ply->ksyms) {
		if (fnmatch(kp->pattern, sym->sym, FNM_EXTMATCH))
			continue;

		pending += xprobe_create(kp->ctrl, kp->stem, sym->sym);
		kp->n_evs++;

		/* The kernel parser doesn't deal with a probe definition
		 * being split across two writes. So if there's less than
		 * 512 bytes left, flush the buffer. */
		if (pending > (0x1000 - 0x200)) {
			err = fflush(kp->ctrl);
			if (err)
				return -errno;

			pending = 0;
		}
	}

	return 0;
}	

static int kprobe_create(struct ply_probe *pb)
{
	struct kprobe *kp = pb->provider_data;
	int err = 0;

	xprobe_stem(pb, 'p', kp->stem, sizeof(kp->stem));

	if (strpbrk(kp->pattern, "?*[!@") && pb->ply->ksyms) {
		err = kprobe_create_pattern(pb);
	} else {
		xprobe_create(kp->ctrl, kp->stem, kp->pattern);
		kp->n_evs++;
	}

	if (!err)
		err = fflush(kp->ctrl) ? -errno : 0;
	return err;
}

static int __kprobe_attach(struct ply_probe *pb)
{
	struct kprobe *kp = pb->provider_data;
	glob_t gl;
	int err, i;

	err = xprobe_glob(pb, &gl);
	if (err)
		return err;

	if (gl.gl_pathc != kp->n_evs) {
		_d("n:%d c:%d\n", kp->n_evs, gl.gl_pathc);
		pause();
	}
	
	assert(gl.gl_pathc == kp->n_evs);
	for (i = 0; i < (int)gl.gl_pathc; i++) {
		kp->evfds[i] = perf_event_attach(pb, gl.gl_pathv[i]);
		if (kp->evfds[i] < 0) {
			err = kp->evfds[i];
			break;
		}
	}

	globfree(&gl);
	return err;
}

static int kprobe_attach(struct ply_probe *pb)
{
	struct kprobe *kp = pb->provider_data;
	char *func;
	int err;

	/* TODO: mode should be a+ and we should clean this up on
	 * detach. */
	kp->ctrl = fopen(TRACEPATH "kprobe_events", "a+");
	if (!kp->ctrl)
		return -errno;

	err = setvbuf(kp->ctrl, NULL, _IOFBF, 0x1000);
	if (err) {
		err = -errno;
		goto err_close;
	}

	err = kprobe_create(pb);
	if (err)
		goto err_close;

	kp->evfds = calloc(kp->n_evs, sizeof(kp->evfds));
	if (!kp->evfds) {
		err = -ENOMEM;
		goto err_destroy;
	}

	err = __kprobe_attach(pb);
	if (err)
		goto err_destroy;

	return 0;

err_destroy:
	/* kprobe_destroy(kp); */

err_close:
	fclose(kp->ctrl);
	return err;
}

static int kprobe_probe(struct ply_probe *pb)
{
	struct kprobe *kp;

	kp = calloc(1, sizeof(*kp));
	assert(kp);

	kp->pattern = strchr(pb->probe, ':');
	assert(kp->pattern);
	kp->pattern++;

	pb->provider_data = kp;
	return 0;
}

__ply_provider struct provider kprobe = {
	.name = "kprobe",
	.prog_type = BPF_PROG_TYPE_KPROBE,

	.ir_pre = kprobe_ir_pre,
	.sym_alloc = kprobe_sym_alloc,
	.attach = kprobe_attach,
	.detach = kprobe_detach,
	.probe = kprobe_probe,
};
