#include <assert.h>
#include <byteswap.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <linux/bpf.h>

#include "fs-ast.h"
#include "fs-ebpf.h"

#define RET_ON_ERR(_err, _fmt, ...)					\
	if (_err) {							\
		fprintf(stderr, "error(%d): " _fmt, _err, ##__VA_ARGS__); \
	}


static int ebpf_mov(struct ebpf *e, int dst, struct fs_node *n)
{
	switch (n->type) {
	case FS_INT:
		*(e->ip)++ = MOV_IMM(dst, n->integer);
		break;

	default:
		assert(0);
	}

	return 0;
}

struct ebpf *ebpf_init(struct ebpf *e)
{
	memset(e->prog, 0, sizeof(e->prog));
	e->ip = e->prog;
	return e;
}

struct symtable {
	void *dummy;
};

struct provider {
	void *priv;
	
	int (*annotate)(struct provider *p, struct fs_node *n);
};

static int kprobes_annotate(struct provider *p, struct fs_node *n)
{
	if (!strcmp("pid", n->call.func)) {
		if (n->call.vargs)
			return -EINVAL;

		n->annot.type = FS_INT;
		n->annot.size = sizeof(n->integer);
		return 0;
	}

	return -ENOENT;
}

static struct provider kprobes_provider = {
	.annotate = kprobes_annotate,
};

static int _fs_annotate_pre(struct fs_node *n, void *_st)
{
	/* struct symtable *st = _st; */

	return 0;
}

static int _fs_annotate_post(struct fs_node *n, void *_st)
{
	/* struct symtable *st = _st; */
	struct provider *prov = &kprobes_provider;
	struct fs_node *c;
	int err = 0;
	
	switch (n->type) {
	case FS_STR:
		n->annot.type = FS_STR;
		n->annot.size = strlen(n->string);
		break;
	case FS_INT:
		n->annot.type = FS_INT;
		n->annot.size = sizeof(n->integer);
		break;
	case FS_VAR:
		/* err = symtable_add(st, n); */
		RET_ON_ERR(err, "fs_annotate: var(%s)\n", n->string);
		break;
	case FS_MAP:
		/* err = symtable_add(st, n); */
		RET_ON_ERR(err, "fs_annotate: map(%s)\n", n->map.name);

		fs_foreach(c, n->map.vargs)
			n->annot.key_size += c->annot.size;
		break;
	case FS_NOT:
		n->annot.type = n->not->annot.type;
		n->annot.size = n->not->annot.size;
		break;
	case FS_BINOP:
		if (n->binop.left->annot.type != FS_INT || 
		    n->binop.right->annot.type != FS_INT)
			RET_ON_ERR(-EINVAL, "fs_annotate: binop: expected type int\n");

		n->annot.type = n->binop.left->annot.type;
		n->annot.size = n->binop.left->annot.size;
		break;
	case FS_RETURN:
		if (n->ret->annot.type != FS_INT)
			RET_ON_ERR(-EINVAL, "fs_annotate: return: expected type int\n");
		n->annot.type = n->ret->annot.type;
		n->annot.size = n->ret->annot.size;
		break;
	case FS_ASSIGN:
		/* err = symtable_restrict(st, n->assign.lval, n->assign.expr); */
		RET_ON_ERR(err, "fs_annotate: assign(%s): conflicting types", n->string);
		n->assign.lval->annot.type = n->assign.expr->annot.type;
		n->assign.lval->annot.size = n->assign.expr->annot.size;
		break;
	case FS_CALL:
		err = prov->annotate(prov, n);
		RET_ON_ERR(err, "fs_annotate: call(%s): unknown function or invalid parameters\n",
			   n->call.func);
		break;

	default:
		break;
	}

	return 0;
}

static int fs_annotate(struct fs_node *probe, struct symtable *st)
{
	return fs_walk(probe, _fs_annotate_pre, _fs_annotate_post, st);
}

int fs_compile(struct fs_node *n, struct ebpf *e)
{
	/* struct fs_node *c; */
	/* int err = 0; */

	(void)(ebpf_mov);
	
	return fs_annotate(n, NULL);
	/* switch (n->type) { */
	/* case FS_PROBE: */
	/* 	for (c = n->probe.stmts; !err && c; c = c->next) */
	/* 		err = fs_compile(c, e); */
	/* 	RET_ON_ERR(err, "probe (%s)\n", n->probe.pspecs->string); */

	/* 	if ((e->ip - 1)->code != EXIT.code) { */
	/* 		*(e->ip)++ = MOV_IMM(BPF_REG_0, 0); */
	/* 		*(e->ip)++ = EXIT; */
	/* 	} */
	/* 	break; */

	/* case FS_COND: */
		
	/* case FS_RETURN: */
	/* 	err = fs_compile(n->ret, e); */
	/* 	RET_ON_ERR(err, "return\n"); */

	/* 	ebpf_mov(e, BPF_REG_0, n->ret); */
	/* 	*(e->ip)++ = EXIT; */
	/* 	break; */

	/* case FS_INT: */
	/* 	/\* nop *\/ */
	/* 	break; */

	/* default: */
	/* 	RET_ON_ERR(1, "unsupported node %d\n", n->type); */
	/* } */

	return 0;
}
