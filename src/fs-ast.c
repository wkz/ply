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
	struct fs_probespec *ps;

	__indent(indent);

	switch (n->type) {
	case FS_NOP:
		fprintf(stderr, "nop\n");
		break;

	case FS_SCRIPT:
		fprintf(stderr, "script\n");

		for (c = n->script.probes; c; c = c->next)
			_fs_ast_dump(c, indent + 2);
		break;

	case FS_PROBE:		
		fprintf(stderr, "probe(");

		for (ps = n->probe.spec; ps; ps = ps->next)
			fprintf(stderr, "%s%s", (ps == n->probe.spec) ? "" : ", ",
				ps->spec);

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

struct fs_probespec *fs_probespec_add(struct fs_probespec *prev, char *spec)
{
	struct fs_probespec *ps = calloc(1, sizeof(*ps));

	assert(ps);
	ps->spec = spec;

	if (prev)
		insque_tail(ps, prev);
		
	return prev ? : ps;
}

struct fs_node *fs_probe_new(struct fs_probespec *spec, struct fs_node *stmts)
{
	struct fs_node *n = fs_node_new(FS_PROBE);

	n->probe.spec = spec;
	n->probe.stmts = stmts;
	return n;
}
