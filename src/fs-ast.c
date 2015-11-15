#include <assert.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>

#include "fs-ast.h"

static void _indent(int *indent)
{
	int left = *indent;

	while(left--)
		fputc(' ', stderr);

	*indent += 3;
}

static int _unindent(struct fs_node *n, void *indent)
{
	*((int *)indent) -= 3;
	return 0;
}

static int _fs_ast_dump(struct fs_node *n, void *indent)
{
	_indent((int *)indent);
	
	switch (n->type) {
	case FS_SCRIPT:
		fprintf(stderr, "script");
		break;

	case FS_PROBE:		
		fprintf(stderr, "probe");
		break;

	case FS_PSPEC:
		fprintf(stderr, "pspec(%s)", n->string);
		break;
		
	case FS_CALL:
		fprintf(stderr, "call(%s)", n->call.func);
		break;

	case FS_COND:
		fprintf(stderr, "if");
		break;

	case FS_ASSIGN:
		fprintf(stderr, "assign(%s)", n->assign.op);
		break;

	case FS_BINOP:
		fprintf(stderr, "binop(%s)", n->binop.op);
		break;

	case FS_RETURN:
		fprintf(stderr, "return");
		break;

	case FS_NOT:
		fprintf(stderr, "not");
		break;

	case FS_MAP:
		fprintf(stderr, "map(%s)", n->map.name);
		break;

	case FS_VAR:
		fprintf(stderr, "var(%s)", n->string);
		break;

	case FS_INT:
		fprintf(stderr, "int(%ld)", n->integer);
		break;
		
	case FS_STR:
		fprintf(stderr, "string(\"%s\")", n->string);
		break;

	default:
		fprintf(stderr, "!type:%d", n->type);
		break;
	}

	if (n->annot.type != FS_UNKNOWN) {
		fputs(" $(type:", stderr);

		switch (n->annot.type) {
		case FS_INT:
			fputs("int, ", stderr);
			break;
		case FS_STR:
			fputs("str, ", stderr);
			break;
		default:
			fprintf(stderr, "%d, ", n->annot.type);
			break;
		}

		if (n->type == FS_MAP)
			fprintf(stderr, "key_size:%lu, ", n->annot.key_size);
		
		fprintf(stderr, "size:%lu)", n->annot.size);
	}

	fputc('\n', stderr);
	return 0;
}

void fs_ast_dump(struct fs_node *n)
{
	int indent = 0;

	fs_walk(n, _fs_ast_dump, _unindent, &indent);
}


struct fs_node *fs_str_new(char *val)
{
	struct fs_node *n = fs_node_new(FS_STR);

	n->string = val;
	return n;
}

struct fs_node *fs_int_new(int64_t val)
{
	struct fs_node *n = fs_node_new(FS_INT);

	n->integer = val;
	return n;
}

struct fs_node *fs_var_new(char *name)
{
	struct fs_node *n = fs_node_new(FS_VAR);

	n->string  = name;
	return n;
}

struct fs_node *fs_map_new(char *name, struct fs_node *vargs)
{
	struct fs_node *n = fs_node_new(FS_MAP);

	n->map.name  = name;
	n->map.vargs = vargs;
	return n;
}

struct fs_node *fs_not_new(struct fs_node *expr)
{
	struct fs_node *n = fs_node_new(FS_NOT);

	n->not = expr;
	return n;
}

struct fs_node *fs_return_new(struct fs_node *expr)
{
	struct fs_node *n = fs_node_new(FS_RETURN);

	n->ret = expr;
	return n;
}

struct fs_node *fs_binop_new(struct fs_node *left, char *op, struct fs_node *right)
{
	struct fs_node *n = fs_node_new(FS_BINOP);

	n->binop.left  = left;
	n->binop.op    = op;
	n->binop.right = right;
	return n;
}

struct fs_node *fs_assign_new(struct fs_node *lval, char *op, struct fs_node *expr)
{
	struct fs_node *n = fs_node_new(FS_ASSIGN);

	n->assign.lval = lval;
	n->assign.op   = op;
	n->assign.expr = expr;
	return n;
}

struct fs_node *fs_cond_new(struct fs_node *cond,
			    struct fs_node *yes, struct fs_node *no)
{
	struct fs_node *n = fs_node_new(FS_COND);

	n->cond.cond = cond;
	n->cond.yes  = yes;
	n->cond.no   = no;
	return n;
}

struct fs_node *fs_call_new(char *func, struct fs_node *vargs)
{
	struct fs_node *n = fs_node_new(FS_CALL);

	n->call.func  = func;
	n->call.vargs = vargs;
	return n;
}

struct fs_node *fs_pspec_new(char *spec)
{
	struct fs_node *n = fs_node_new(FS_PSPEC);

	n->string = spec;
	return n;
}

struct fs_node *fs_probe_new(struct fs_node *pspecs, struct fs_node *stmts)
{
	struct fs_node *n = fs_node_new(FS_PROBE);

	n->probe.pspecs = pspecs;
	n->probe.stmts  = stmts;
	return n;
}

struct fs_node *fs_script_new(struct fs_node *probes)
{
	struct fs_node *n = fs_node_new(FS_SCRIPT);

	n->script.probes = probes;
	return n;
}


static int _fs_free(struct fs_node *n, void *ctx)
{
	switch (n->type) {
	case FS_CALL:
		free(n->call.func);
		break;

	case FS_ASSIGN:
		free(n->assign.op);
		break;

	case FS_BINOP:
		free(n->binop.op);
		break;

	case FS_MAP:
		free(n->map.name);
		break;

	case FS_PSPEC:
	case FS_VAR:
	case FS_STR:
		free(n->string);
		break;

	default:
		break;
	}

	free(n);
	return 0;
}

void fs_free(struct fs_node *n)
{
	fs_walk(n, NULL, _fs_free, NULL);
}

static int _fs_walk_list(struct fs_node *head,
			 int (*pre) (struct fs_node *n, void *ctx),
			 int (*post)(struct fs_node *n, void *ctx), void *ctx)
{
	struct fs_node *elem, *next = head;
	int err = 0;
	
	for (elem = next; !err && elem;) {
		next = elem->next;
		err = fs_walk(elem, pre, post, ctx);
		elem = next;
	}

	return err;
}


int fs_walk(struct fs_node *n,
	    int (*pre) (struct fs_node *n, void *ctx),
	    int (*post)(struct fs_node *n, void *ctx), void *ctx)
{
#define do_list(_head) err = _fs_walk_list(_head, pre, post, ctx); if (err) return err
#define do_walk(_node) err =       fs_walk(_node, pre, post, ctx); if (err) return err
	int err = 0;

	err = pre ? pre(n, ctx) : 0;
	if (err)
		return err;
	
	switch (n->type) {
	case FS_SCRIPT:
		do_list(n->script.probes);
		break;

	case FS_PROBE:
		do_list(n->probe.pspecs);
		do_list(n->probe.stmts);
		break;

	case FS_CALL:
		do_list(n->call.vargs);
		break;

	case FS_COND:
		do_walk(n->cond.cond);
		do_walk(n->cond.yes);
		if (n->cond.no)
			do_walk(n->cond.no);
		break;

	case FS_ASSIGN:
		do_walk(n->assign.lval);
		do_walk(n->assign.expr);
		break;

	case FS_RETURN:
		do_walk(n->ret);
		break;

	case FS_BINOP:
		do_walk(n->binop.left);
		do_walk(n->binop.right);
		break;

	case FS_NOT:
		do_walk(n->not);
		break;

	case FS_MAP:
		do_list(n->map.vargs);
		break;

	case FS_UNKNOWN:
		return -1;

	default:
		break;
	}

	return post ? post(n, ctx) : 0;
}

		
