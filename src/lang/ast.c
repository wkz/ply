#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ast.h"

const char *type_str(type_t type)
{
#define TYPE(_type, _typestr) [_type] = _typestr,
	static const char *strs[] = {
		NODE_TYPE_TABLE
	};
#undef TYPE

	return strs[type];
}

void node_dyn_dump(dyn_t *dyn)
{
	fprintf(stderr, "%s [%s/%zx", dyn->string ? : "",
		type_str(dyn->type), dyn->size);

	if (dyn->ksize)
		fprintf(stderr, "/%zx", dyn->ksize);

	fputc(']', stderr);
}

static void _indent(int *indent)
{
	int left = *indent;

	while(left--)
		fputc(' ', stderr);

	*indent += 3;
}

static int _unindent(node_t *n, void *indent)
{
	*((int *)indent) -= 3;
	return 0;
}

static void _fputs_escape(FILE *fp, const char *s)
{
	fputc('\"', fp);
	for (; *s; s++) {
		if (isprint(*s)) {
			fputc(*s, fp);
			continue;
		}

		fputc('\\', fp);

		switch (*s) {
		case '\n':
			fputc('n', fp);
			break;
		case '\r':
			fputc('r', fp);
			break;
		case '\t':
			fputc('t', fp);
			break;
		default:
			fprintf(fp, "x%2.2x", *s);
			break;
		}
	}
	fputc('\"', fp);
}

static int _node_ast_dump(node_t *n, void *indent)
{
	_indent((int *)indent);

	switch (n->type) {
	case TYPE_NONE:
	case TYPE_SCRIPT:
	case TYPE_RETURN:
	case TYPE_NOT:
	case TYPE_MAP:
	case TYPE_REC:
		break;
		
	case TYPE_PROBE:		
	case TYPE_CALL:
	case TYPE_ASSIGN:
	case TYPE_BINOP:
		fprintf(stderr, "%s ", n->string);
		break;

	case TYPE_INT:
		fprintf(stderr, "%" PRIx64 " ", n->integer);
		break;
		
	case TYPE_STR:
		_fputs_escape(stderr, n->string);
		break;
	}

	fprintf(stderr, "(%s) ", type_str(n->type));

	if (n->dyn->type)
		node_dyn_dump(n->dyn);

	if (n->parent)
		fprintf(stderr, "<%s>", type_str(n->parent->type));

	fputc('\n', stderr);
	return 0;
}

void node_ast_dump(node_t *n)
{
	int indent = 3;
	dyn_t *dyn;
	node_t *s;

	fprintf(stderr, "ast:\n");
	node_walk(n, _node_ast_dump, _unindent, &indent);
	fputc('\n', stderr);

	for (s = n; s && s->type != TYPE_SCRIPT; s = s->parent);

	if (!s)
		return;
	
	fprintf(stderr, "stack:\n");
	for (dyn = s->script.dyns; dyn; dyn = dyn->next) {
		if (!dyn->loc.addr)
			continue;

		fprintf(stderr, "-%.2zx ", -dyn->loc.addr);
		node_dyn_dump(dyn);
		fputc('\n', stderr);
	}
}

static inline node_t *node_new(type_t type) {
	node_t *n = calloc(1, sizeof(*n));

	assert(n);
	n->type = type;
	return n;
}

node_t *node_str_new(char *val)
{
	node_t *n = node_new(TYPE_STR);

	n->string = val;
	return n;
}

node_t *node_int_new(int64_t val)
{
	node_t *n = node_new(TYPE_INT);

	n->integer = val;
	return n;
}

node_t *node_rec_new(node_t *vargs)
{
	node_t *c, *n = node_new(TYPE_REC);

	n->rec.vargs = vargs;

	node_foreach(c, vargs)
		c->parent = n;
	return n;
}

node_t *node_map_new(char *name, node_t *rec)
{
	node_t *n = node_new(TYPE_MAP);

	n->string = name;
	n->map.rec = rec;

	rec->parent = n;
	return n;
}

node_t *node_not_new(node_t *expr)
{
	node_t *n = node_new(TYPE_NOT);

	n->not = expr;

	expr->parent = n;
	return n;
}

node_t *node_return_new(node_t *expr)
{
	node_t *n = node_new(TYPE_RETURN);

	n->ret = expr;

	expr->parent = n;
	return n;
}

static alu_op_t alu_op_from_str(const char *opstr)
{
	switch (opstr[0]) {
	case '+':
		return ALU_OP_ADD;
	case '-':
		return ALU_OP_SUB;
	case '*':
		return ALU_OP_MUL;
	case '/':
		return ALU_OP_DIV;
	case '|':
		return ALU_OP_OR;
	case '&':
		return ALU_OP_AND;
	case '<':
		return ALU_OP_LSH;
	case '>':
		return ALU_OP_RSH;
	case '%':
		return ALU_OP_MOD;
	case '^':
		return ALU_OP_XOR;
	case '=':
		return ALU_OP_MOV;
	default:
		assert(0);
		return 0;
	}
}

node_t *node_binop_new(node_t *left, char *opstr, node_t *right)
{
	node_t *n = node_new(TYPE_BINOP);

	n->string = opstr;
	n->binop.op    = alu_op_from_str(opstr);
	n->binop.left  = left;
	n->binop.right = right;
	return n;
}

node_t *node_assign_new(node_t *lval, char *opstr, node_t *expr)
{
	node_t *n = node_new(TYPE_ASSIGN);

	n->string = opstr;
	n->assign.op   = alu_op_from_str(opstr);
	n->assign.lval = lval;
	n->assign.expr = expr;

	lval->parent = n;
	expr->parent = n;
	return n;
}

node_t *node_call_new(char *func, node_t *vargs)
{
	node_t *c, *n = node_new(TYPE_CALL);

	n->string = func;
	n->call.vargs = vargs;

	node_foreach(c, vargs)
		c->parent = n;
	return n;
}

node_t *node_probe_new(char *pspec, node_t *pred,
			     node_t *stmts)
{
	node_t *c, *n = node_new(TYPE_PROBE);

	n->string = pspec;
	n->probe.pred   = pred;
	n->probe.stmts  = stmts;

	pred->parent = n;
	node_foreach(c, stmts)
		c->parent = n;
	return n;
}

node_t *node_script_new(node_t *probes)
{
	node_t *c, *n = node_new(TYPE_SCRIPT);

	n->script.probes = probes;

	node_foreach(c, probes)
		c->parent = n;
	return n;
}


static int _node_free(node_t *n, void *ctx)
{
	dyn_t *dyn, *dyn_next;

	switch (n->type) {
	case TYPE_SCRIPT:
		for (dyn = n->script.dyns; dyn; dyn = dyn_next) {
			if (dyn->string)
				free(dyn->string);
			dyn_next = dyn->next;
			free(dyn);
		}
		break;
	case TYPE_PROBE:
	case TYPE_CALL:
	case TYPE_ASSIGN:
	case TYPE_BINOP:
	case TYPE_MAP:
	case TYPE_STR:
		free(n->string);
		break;

	default:
		break;
	}

	free(n);
	return 0;
}

void node_free(node_t *n)
{
	node_walk(n, NULL, _node_free, NULL);
}

static int _node_walk_list(node_t *head,
			 int (*pre) (node_t *n, void *ctx),
			 int (*post)(node_t *n, void *ctx), void *ctx)
{
	node_t *elem, *next = head;
	int err = 0;
	
	for (elem = next; !err && elem;) {
		next = elem->next;
		err = node_walk(elem, pre, post, ctx);
		elem = next;
	}

	return err;
}


int node_walk(node_t *n,
	    int (*pre) (node_t *n, void *ctx),
	    int (*post)(node_t *n, void *ctx), void *ctx)
{
#define do_list(_head) err = _node_walk_list(_head, pre, post, ctx); if (err) return err
#define do_walk(_node) err =       node_walk(_node, pre, post, ctx); if (err) return err
	int err = 0;

	err = pre ? pre(n, ctx) : 0;
	if (err)
		return err;
	
	switch (n->type) {
	case TYPE_SCRIPT:
		do_list(n->script.probes);
		break;

	case TYPE_PROBE:
		if (n->probe.pred)
			do_walk(n->probe.pred);
		do_list(n->probe.stmts);
		break;

	case TYPE_CALL:
		do_list(n->call.vargs);
		break;

	case TYPE_ASSIGN:
		do_walk(n->assign.lval);
		do_walk(n->assign.expr);
		break;

	case TYPE_RETURN:
		do_walk(n->ret);
		break;

	case TYPE_BINOP:
		do_walk(n->binop.left);
		do_walk(n->binop.right);
		break;

	case TYPE_NOT:
		do_walk(n->not);
		break;

	case TYPE_MAP:
		do_walk(n->map.rec);
		break;

	case TYPE_REC:
		do_list(n->rec.vargs);
		break;

	case TYPE_NONE:
		return -1;

	default:
		break;
	}

	return post ? post(n, ctx) : 0;
}

		
