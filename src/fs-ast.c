#include <assert.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>

#include "fs-ast.h"

static void __indent(int indent)
{
	while(indent--)
		fputc(' ', stderr);
}

static void _fs_ast_dump(struct fs_node *n, int indent)
{
	struct fs_node *c;

	__indent(indent);

	switch (n->type) {
	case FS_SCRIPT:
		fprintf(stderr, "script\n");

		for (c = n->script.probes; c; c = c->next)
			_fs_ast_dump(c, indent + 2);
		break;

	case FS_PROBE:		
		fprintf(stderr, "probe(");

		for (c = n->probe.pspecs; c; c = c->next)
			fprintf(stderr, "%s%s", (c == n->probe.pspecs) ? "" : ", ",
				c->string);

		fputs(")\n", stderr);

		for (c = n->probe.stmts; c; c = c->next)
			_fs_ast_dump(c, indent + 2);
		break;

	case FS_CALL:
		fprintf(stderr, "call(%s)\n", n->call.func);
		for (c = n->call.vargs; c; c = c->next)
			_fs_ast_dump(c, indent + 2);
		break;

	case FS_COND:
		fprintf(stderr, "if\n");
		_fs_ast_dump(n->cond.cond, indent + 2);
		__indent(indent + 2); fprintf(stderr, "then\n");
		_fs_ast_dump(n->cond.yes, indent + 4);
		if (n->cond.no) {
			__indent(indent + 2); fprintf(stderr, "else\n");
			_fs_ast_dump(n->cond.no, indent + 4);
		}
		break;

	case FS_ASSIGN:
		fprintf(stderr, "assign\n");
		_fs_ast_dump(n->assign.lval, indent + 2);
		__indent(indent + 2); fprintf(stderr, "%s\n", n->assign.op);
		_fs_ast_dump(n->assign.expr, indent + 2);
		break;

	case FS_BINOP:
		fprintf(stderr, "binop\n");
		_fs_ast_dump(n->binop.left, indent + 2);
		__indent(indent + 2); fprintf(stderr, "%s\n", n->binop.op);
		_fs_ast_dump(n->binop.right, indent + 2);
		break;

	case FS_RETURN:
		fprintf(stderr, "return\n");
		_fs_ast_dump(n->ret, indent + 2);
		break;

	case FS_NOT:
		fprintf(stderr, "not\n");
		_fs_ast_dump(n->not, indent + 2);
		break;

	case FS_VAR:
		fprintf(stderr, "%s(%s)\n", n->var.vargs? "map" : "variable", n->var.name);
		for (c = n->call.vargs; c; c = c->next)
			_fs_ast_dump(c, indent + 2);
		break;

	case FS_INT:
		fprintf(stderr, "int(%ld)\n", n->integer);
		break;
		
	case FS_STR:
		fprintf(stderr, "string(\"%s\")\n", n->string);
		break;

	default:
		fprintf(stderr, "!type:%d\n", n->type);
		break;
	}
}

void fs_ast_dump(struct fs_node *n)
{
	return _fs_ast_dump(n, 0);
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

struct fs_node *fs_var_new(char *name, struct fs_node *vargs)
{
	struct fs_node *n = fs_node_new(FS_VAR);

	n->var.name  = name;
	n->var.vargs = vargs;
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

static void _fs_node_free_list(struct fs_node *head)
{
	struct fs_node *elem, *next = head;

	for (elem = next; elem;) {
		next = elem->next;
		fs_node_free(elem);
		elem = next;
	}
}

void fs_node_free(struct fs_node *n)
{
	switch (n->type) {
	case FS_SCRIPT:
		_fs_node_free_list(n->script.probes);
		break;

	case FS_PROBE:
		_fs_node_free_list(n->probe.pspecs);
		_fs_node_free_list(n->probe.stmts);
		break;

	case FS_CALL:
		free(n->call.func);
		_fs_node_free_list(n->call.vargs);
		break;

	case FS_COND:
		fs_node_free(n->cond.cond);
		fs_node_free(n->cond.yes);
		if (n->cond.no)
			fs_node_free(n->cond.no);
		break;

	case FS_ASSIGN:
		free(n->assign.op);
		fs_node_free(n->assign.lval);
		fs_node_free(n->assign.expr);
		break;

	case FS_RETURN:
		fs_node_free(n->ret);
		break;

	case FS_BINOP:
		free(n->binop.op);
		fs_node_free(n->binop.left);
		fs_node_free(n->binop.right);
		break;

	case FS_NOT:
		fs_node_free(n->not);
		break;

	case FS_VAR:
		free(n->var.name);
		_fs_node_free_list(n->var.vargs);
		break;

	case FS_INT:
		break;

	case FS_PSPEC:
	case FS_STR:
		free(n->string);
		break;

	default:
		assert(0);
	}

	free(n);
}
		
		
