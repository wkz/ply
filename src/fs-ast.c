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

	fputs(fs_typestr(n->type), stderr);

	switch (n->type) {
	case FS_UNKNOWN:
	case FS_SCRIPT:
	case FS_PROBE:		
	case FS_RETURN:
	case FS_NOT:
		break;
		
	case FS_PSPEC:
	case FS_PRED:
	case FS_CALL:
	case FS_ASSIGN:
	case FS_BINOP:
	case FS_MAP:
	case FS_VAR:
		fprintf(stderr, "(%s)", n->string);
		break;

	case FS_INT:
		fprintf(stderr, "(%" PRIx64 ")", n->integer);
		break;
		
	case FS_STR:
		fprintf(stderr, "(\"%s\")", n->string);
		break;
	}

	if (n->annot.type != FS_UNKNOWN)
		fprintf(stderr, " $(type:%s/%zx parent:%s)",
			fs_typestr(n->annot.type), n->annot.size,
			n->parent? fs_typestr(n->parent->type) : "none");

	fputc('\n', stderr);
	return 0;
}

void fs_ast_dump(struct fs_node *n)
{
	int indent = 0;

	fs_walk(n, _fs_ast_dump, _unindent, &indent);
}

static char *str_escape(char *str)
{
	char *in, *out;

	for (in = out = str; *in; in++, out++) {
		if (*in != '\\')
			continue;

		in++;
		switch (*in) {
		case 'n':
			*out = '\n';
			break;
		case 'r':
			*out = '\r';
			break;
		case 't':
			*out = '\t';
			break;
		case '\\':
			*out = '\\';
			break;
		default:
			break;
		}
	}

	if (out < in)
		*out = '\0';

	return str;
}

struct fs_node *fs_str_new(char *val)
{
	struct fs_node *n = fs_node_new(FS_STR);
	char *escaped = str_escape(val);

	n->annot.size = _ALIGNED(strlen(escaped) + 1);
	n->string = calloc(1, n->annot.size);
	memcpy(n->string, escaped, n->annot.size);
	free(escaped);
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

struct fs_node *fs_pspec_new(char *spec)
{
	struct fs_node *n = fs_node_new(FS_PSPEC);

	n->string = spec;
	return n;
}

struct fs_node *fs_probe_new(struct fs_node *pspecs, struct fs_node *pred,
			     struct fs_node *stmts)
{
	struct fs_node *n = fs_node_new(FS_PROBE);

	n->probe.pspecs = pspecs;
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
	switch (n->type) {
	case FS_CALL:
	case FS_ASSIGN:
	case FS_BINOP:
	case FS_MAP:
	case FS_PSPEC:
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
		do_list(n->probe.pspecs);
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

		
