#include <errno.h>
#include <inttypes.h>
#include <string.h>

#include "ply.h"
#include "lang/ast.h"
#include "provider/provider.h"

#define xor(_a, _b) ((!!(_a)) ^ (!!(_b)))

static int type_sync(node_t *from, node_t *to)
{
	/* if only one side is known, transfer it to the other
	 * side. if both sides are known, they must be equal. */

	if (xor(from->dyn.type, to->dyn.type)) {
		if (from->dyn.type)
			to->dyn.type = from->dyn.type;
		else
			from->dyn.type = to->dyn.type;
	} else if (from->dyn.type != to->dyn.type) {
		_e("%s: type mismatch: %s != %s", from->string,
		   type_str(from->dyn.type), type_str(to->dyn.type));
		return -EINVAL;
	}

	if (xor(from->dyn.size, to->dyn.size)) {
		if (from->dyn.size)
			to->dyn.size = from->dyn.size;
		else
			from->dyn.size = to->dyn.size;
	} else if (from->dyn.size != to->dyn.size) {
		_e("%s: size mismatch: %zx != %zx", from->string,
		   from->dyn.size, to->dyn.size);
		return -EINVAL;		
	}

	return 0;
}

static int type_bubble(node_t *from)
{
	node_t *p = from->parent, *to = NULL;
	int err;

	if (!p)
		return 0;

	switch (p->type) {
	case TYPE_ASSIGN:
		to = (from == p->assign.lval) ? p->assign.expr : p->assign.lval;
		break;
	case TYPE_NOT:
	case TYPE_RETURN:
		to = p;
		break;
	case TYPE_BINOP:
		to = (from == p->binop.left) ? p->binop.right : p->binop.left;
		err = type_sync(from, to);
		if (err)
			return err;

		to = p;
		break;
	default:
		break;
	}

	if (!to)
		return 0;

	err = type_sync(from, to);
	if (err)
		return err;

	return type_bubble(p);
}

static int type_infer_post(node_t *n, void *_null)
{
	if (n->type == TYPE_REC) {
		node_t *c;
		size_t sz = 0;

		node_foreach(c, n->rec.vargs) {
			if (c->dyn.size) {
				sz += c->dyn.size;
			} else {
				sz = 0;
				break;
			}
		}

		if (sz)
			n->dyn.size = sz;
	}

	if (n->dyn.type || n->dyn.size)
		return type_bubble(n);

	return 0;
}

/* static dyn_t *dyn_get(node_t *n) */
/* { */
/* 	dyn_t *dyn; */
/* 	node_t *s, *k; */

/* 	for (s = n; s && s->type != TYPE_SCRIPT; s = s->parent); */
/* 	assert(s); */

/* 	if (n->type != TYPE_MAP) */
/* 		goto new; */

/* 	if (n->type == TYPE_MAP) */
/* 	for (dyn = s->script.dyns; dyn; dyn = dyn.next) */
/* 		if (dyn.string && !strcmp(n->string, dyn.string)) */
/* 			return dyn; */

/* new: */
/* 	dyn = calloc(1, sizeof(*dyn)); */
/* 	if (!s->script.dyns) */
/* 		s->script.dyns = dyn; */
/* 	else */
/* 		insque_tail(dyn, s->script.dyns); */

/* 	dyn.node = n; */

/* 	if (n->type != TYPE_MAP) */
/* 		return dyn; */

/* 	dyn.string = strdup(n->string); */

/* 	node_foreach(k, n->map.rec->rec.vargs) { */
/* 		if (!k->dyn.size) { */
/* 			dyn.ksize = 0; */
/* 			break; */
/* 		} */
/* 		dyn.ksize += k->dyn.size; */
/* 	} */
/* 	return dyn; */
/* } */

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

static int static_post(node_t *n, void *_prov)
{
	struct provider *prov = _prov;
	char *escaped;
	int err;

	switch (n->type) {
	case TYPE_INT:
	case TYPE_NOT:
	case TYPE_RETURN:
		n->dyn.type = TYPE_INT;
		n->dyn.size = 8;
		break;
	case TYPE_STR:
		escaped = str_escape(n->string);

		n->dyn.type = TYPE_STR;
		n->dyn.size = _ALIGNED(strlen(escaped) + 1);

		n->string = calloc(1, n->dyn.size);
		memcpy(n->string, escaped, n->dyn.size);
		free(escaped);
		break;
	case TYPE_REC:
		n->dyn.type = TYPE_REC;
		break;
	case TYPE_CALL:
		err = prov->annotate(prov, NULL, n);
		if (err)
			return err;
		break;
	default:
		break;
	}
	
	return 0;
}

int script_annotate(node_t *script, struct provider *prov)
{
	dyn_t *dyn;
	ssize_t stack = 0;
	int err;

	/* insert all statically known types */
	err = node_walk(script, NULL, static_post, prov);
	if (err) {
		_e("static annotation failed (%d)", err);
		return err;
	}

	/* infer the rest */
	err = node_walk(script, NULL, type_infer_post, NULL);
	if (err) {
		_e("type inference failed (%d)", err);
		return err;
	}

	err = node_walk(script, NULL, type_infer_post, NULL);
	if (err) {
		_e("type inference failed (%d)", err);
		return err;
	}

	/* allocate stack locations for symbols */
	/* for (dyn = script->script.dyns; dyn; dyn = dyn.next) { */
	/* 	switch (dyn.node->type) { */
	/* 	case TYPE_CALL: */
	/* 	case TYPE_STR: */
	/* 		stack -= dyn.size; */
	/* 		break; */
	/* 	case TYPE_MAP: */
	/* 		stack -= dyn.size + dyn.ksize; */
	/* 		break; */
	/* 	default: */
	/* 		continue; */
	/* 	} */

	/* 	dyn.loc.addr = stack; */
	/* } */
	return 0;
}
