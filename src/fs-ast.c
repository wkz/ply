#include <assert.h>
#include <inttypes.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fs-ast.h"

const char *fs_typestr(enum fs_type type)
{
#define TYPE(_type, _typestr) [_type] = _typestr,
	static const char *strs[] = {
		FS_TYPE_TABLE
	};
#undef TYPE

	return strs[type];
}

void fs_dyn_dump(struct fs_dyn *dyn)
{
	fprintf(stderr, "%s [%s/%zx", dyn->string ? : "",
		fs_typestr(dyn->type), dyn->size);

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

static int _unindent(struct fs_node *n, void *indent)
{
	*((int *)indent) -= 3;
	return 0;
}

static int _fs_ast_dump(struct fs_node *n, void *indent)
{
	_indent((int *)indent);

	fprintf(stderr, "(%s) ", fs_typestr(n->type));

	switch (n->type) {
	case FS_NONE:
	case FS_SCRIPT:
	case FS_AGG:
	case FS_RETURN:
	case FS_NOT:
	case FS_MAP:
	case FS_VAR:
		break;
		
	case FS_PROBE:		
	case FS_PRED:
	case FS_CALL:
	case FS_ASSIGN:
	case FS_BINOP:
		fprintf(stderr, "%s", n->string);
		break;

	case FS_INT:
		fprintf(stderr, "%" PRIx64, n->integer);
		break;
		
	case FS_STR:
		fprintf(stderr, "\"%s\"", n->string);
		break;
	}

	if (n->dyn->size)
		fs_dyn_dump(n->dyn);

	if (n->parent)
		fprintf(stderr, " <%s>", fs_typestr(n->parent->type));

	fputc('\n', stderr);
	return 0;
}

void fs_ast_dump(struct fs_node *n)
{
	int indent = 3;
	struct fs_dyn *dyn;
	struct fs_node *s;

	fprintf(stderr, "ast:\n");
	fs_walk(n, _fs_ast_dump, _unindent, &indent);
	fputc('\n', stderr);

	for (s = n; s && s->type != FS_SCRIPT; s = s->parent);

	if (!s)
		return;
	
	fprintf(stderr, "syms:\n");
	for (dyn = s->script.dyns; dyn; dyn = dyn->next) {
		if (!dyn->string)
			continue;

		fprintf(stderr, "-%.2zx ", -dyn->loc.addr);
		fs_dyn_dump(dyn);
		fputc('\n', stderr);
	}
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

	n->string = name;
	return n;
}

struct fs_node *fs_map_new(char *name, struct fs_node *vargs)
{
	struct fs_node *n = fs_node_new(FS_MAP);

	n->string = name;
	n->map.vargs = vargs;
	return n;
}

struct fs_node *fs_global_new(char *name)
{
	return fs_map_new(strdup("@$"), fs_str_new(name));
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

static enum fs_op fs_op_from_str(const char *opstr)
{
	switch (opstr[0]) {
	case '+':
		return FS_ADD;
	case '-':
		return FS_SUB;
	case '*':
		return FS_MUL;
	case '/':
		return FS_DIV;
	case '|':
		return FS_OR;
	case '&':
		return FS_AND;
	case '<':
		return FS_LSH;
	case '>':
		return FS_RSH;
	case '%':
		return FS_MOD;
	case '^':
		return FS_XOR;
	case '=':
		return FS_MOV;
	default:
		assert(0);
		return 0;
	}
}

struct fs_node *fs_binop_new(struct fs_node *left, char *opstr, struct fs_node *right)
{
	struct fs_node *n = fs_node_new(FS_BINOP);

	n->string = opstr;
	n->binop.op    = fs_op_from_str(opstr);
	n->binop.left  = left;
	n->binop.right = right;
	return n;
}

struct fs_node *fs_agg_new(struct fs_node *map, struct fs_node *func)
{
	struct fs_node *n = fs_node_new(FS_AGG);

	n->agg.map  = map;
	n->agg.func = func;
	return n;
}

struct fs_node *fs_assign_new(struct fs_node *lval, char *opstr, struct fs_node *expr)
{
	struct fs_node *n = fs_node_new(FS_ASSIGN);

	n->string = opstr;
	n->assign.op   = fs_op_from_str(opstr);
	n->assign.lval = lval;
	n->assign.expr = expr;
	return n;
}

struct fs_node *fs_call_new(char *func, struct fs_node *vargs)
{
	struct fs_node *n = fs_node_new(FS_CALL);

	n->string = func;
	n->call.vargs = vargs;
	return n;
}

struct fs_node *fs_pred_new(struct fs_node *left, char *opstr,
			   struct fs_node *right)
{
	/* TODO: signed or unsigned compares? */
	struct fs_node *n = fs_node_new(FS_PRED);
	int inv = 0;

	n->string = opstr;

	switch (opstr[0]) {
	case '=':
		n->pred.jmp = FS_JEQ;
		break;
	case '!':
		n->pred.jmp = FS_JNE;
		break;
	case '>':
		if (opstr[1] == '=')
			n->pred.jmp = FS_JGE;
		else
			n->pred.jmp = FS_JGT;
		break;
	case '<':
		inv = 1;
		if (opstr[1] == '=')
			n->pred.jmp = FS_JGT;
		else
			n->pred.jmp = FS_JGE;
		break;
	default:
		assert(0);
		break;
	}

	n->pred.left  = inv ? right : left;
	n->pred.right = inv ? left : right;
	return n;
}

struct fs_node *fs_probe_new(char *pspec, struct fs_node *pred,
			     struct fs_node *stmts)
{
	struct fs_node *n = fs_node_new(FS_PROBE);

	n->string = pspec;
	n->probe.pred   = pred;
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
	struct fs_dyn *dyn, *dyn_next;

	switch (n->type) {
	case FS_SCRIPT:
		for (dyn = n->script.dyns; dyn; dyn = dyn_next) {
			if (dyn->string)
				free(dyn->string);
			dyn_next = dyn->next;
			free(dyn);
		}
		break;
	case FS_PROBE:
	case FS_CALL:
	case FS_ASSIGN:
	case FS_BINOP:
	case FS_MAP:
	case FS_PRED:
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
		if (n->probe.pred)
			do_walk(n->probe.pred);
		do_list(n->probe.stmts);
		break;

	case FS_PRED:
		do_walk(n->pred.left);
		do_walk(n->pred.right);
		break;

	case FS_CALL:
		do_list(n->call.vargs);
		break;

	case FS_ASSIGN:
		do_walk(n->assign.lval);
		do_walk(n->assign.expr);
		break;

	case FS_AGG:
		do_walk(n->agg.map);
		do_walk(n->agg.func);
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

	case FS_NONE:
		return -1;

	default:
		break;
	}

	return post ? post(n, ctx) : 0;
}

		
