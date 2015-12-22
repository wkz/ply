#include <errno.h>
#include <inttypes.h>
#include <string.h>

#include "dtl.h"
#include "fs-ast.h"
#include "provider.h"

static int type_sync(struct fs_node *from, struct fs_node *to)
{	
	if (to->dyn->size) {
		if (from->dyn->size != to->dyn->size) {
			_e("%s: size mismatch: %zx != %zx", from->string,
			   from->dyn->size, to->dyn->size);
			return -EINVAL;
		}
	} else {
		if (to->type != FS_STR)
			to->dyn->size = from->dyn->size;
	}

	if (from->dyn->type && !to->dyn->type) {
		to->dyn->type = from->dyn->type;
		return 0;
	}

	if (to->dyn->type && !from->dyn->type) {
		from->dyn->type = to->dyn->type;
		return 0;
	}

	if (!from->dyn->type && !to->dyn->type)
		return 0;

	
	if (from->dyn->type != to->dyn->type) {
		_e("%s: type mismatch: %s != %s", from->string,
		   fs_typestr(from->dyn->type), fs_typestr(to->dyn->type));
		return -EINVAL;
	}

	return 0;
}

static int type_bubble(struct fs_node *from)
{
	struct fs_node *p = from->parent, *to = NULL;
	int err;

	if (!p)
		return 0;

	switch (p->type) {
	case FS_PRED:
		to = (from == p->pred.left) ? p->pred.right : p->pred.left;
		break;
	case FS_ASSIGN:
		to = (from == p->assign.lval) ? p->assign.expr : p->assign.lval;
		break;
	case FS_AGG:
		to = (from == p->agg.map) ? p->agg.func : p->agg.map;
		break;
	case FS_RETURN:
		to = p;
		break;
	case FS_BINOP:
		to = (from == p->binop.left) ? p->binop.right : p->binop.left;
		err = type_sync(from, to);
		if (err)
			return err;

		to = p;
		break;
	case FS_NOT:
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

static int type_infer_post(struct fs_node *n, void *_null)
{
	/* struct fs_node *k; */
	/* size_t ksize; */
	/* int err = 0; */

	if (n->dyn->size)
		return type_bubble(n);

	return 0;

	/* if (err || n->type != FS_MAP) */
	/* 	return err; */

	/* fs_foreach(k, n->map.vargs) { */
	/* 	if (!k->dyn->size) */
	/* 		return 0; */

	/* 	ksize += k->dyn->size; */
	/* } */

	/* if (!n->dyn->ksize) { */
	/* 	n->dyn->ksize = ksize; */
	/* 	return 0; */
	/* } else if (ksize == n->dyn->ksize) { */
	/* 	return 0; */
	/* } */

	/* _e("map key size mismatch: %zx != %zx", ksize, n->dyn->ksize); */
	/* return -EINVAL; */
}

static struct fs_dyn *dyn_get(struct fs_node *n)
{
	struct fs_dyn *dyn;
	struct fs_node *s, *k;

	for (s = n; s && s->type != FS_SCRIPT; s = s->parent);
	assert(s);

	if (n->type != FS_VAR && n->type != FS_MAP)
		goto new;
		
	for (dyn = s->script.dyns; dyn; dyn = dyn->next)
		if (dyn->string && !strcmp(n->string, dyn->string))
			return dyn;

new:
	dyn = calloc(1, sizeof(*dyn));
	if (!s->script.dyns)
		s->script.dyns = dyn;
	else
		insque_tail(dyn, s->script.dyns);

	if (!(n->type == FS_VAR || n->type == FS_MAP))
		return dyn;

	dyn->string = strdup(n->string);
	if (n->type == FS_VAR) {
		dyn->ksize = 8;
		dyn->varkey = ++s->script.globals;
		return dyn;
	} else if (n->type == FS_MAP) {	
		fs_foreach(k, n->map.vargs) {
			if (!k->dyn->size) {
				dyn->ksize = 0;
				break;
			}
			dyn->ksize += k->dyn->size;
		}
	}
	return dyn;
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

static int static_pre(struct fs_node *n, void *_prov)
{
	struct fs_node *c;

	switch (n->type) {
	case FS_SCRIPT:
		fs_foreach(c, n->script.probes)
			c->parent = n;
		break;
	case FS_PROBE:
		if (n->probe.pred)
			n->probe.pred->parent = n;

		fs_foreach(c, n->probe.stmts)
			c->parent = n;
		break;
	case FS_PRED:
		n->pred.left->parent  = n;
		n->pred.right->parent = n;
		break;
	case FS_CALL:		
		fs_foreach(c, n->call.vargs)
			c->parent = n;
		break;
	case FS_ASSIGN:
		n->assign.lval->parent = n;
		n->assign.expr->parent = n;
		break;
	case FS_AGG:
		n->agg.map->parent  = n;
		n->agg.func->parent = n;
		break;
	case FS_RETURN:
		n->ret->parent = n;
		break;
	case FS_BINOP:
		n->binop.left->parent  = n;
		n->binop.right->parent = n;
		break;
	case FS_NOT:
		n->not->parent = n;
		break;
	case FS_MAP:
		fs_foreach(c, n->map.vargs)
			c->parent = n;
		break;
	default:
		break;
	}

	return 0;
}

static int static_post(struct fs_node *n, void *_prov)
{
	struct provider *prov = _prov;
	char *escaped;
	int err;

	n->dyn = dyn_get(n);

	switch (n->type) {
	case FS_INT:
		n->dyn->type = FS_INT;
		n->dyn->size = 8;
		break;
	case FS_STR:
		escaped = str_escape(n->string);

		n->dyn->type = FS_STR;
		n->dyn->ssize = _ALIGNED(strlen(escaped) + 1);

		n->string = calloc(1, n->dyn->ssize);
		memcpy(n->string, escaped, n->dyn->ssize);
		free(escaped);
		break;
	case FS_RETURN:
		n->dyn->type = FS_INT;
		n->dyn->size = 8;
		break;
	case FS_CALL:
		err = prov->annotate(prov, NULL, n);
		if (err)
			return err;
		break;
	default:
		break;
	}
	
	return 0;
}

int fs_annotate(struct fs_node *script, struct provider *prov)
{
	struct fs_dyn *dyn;
	ssize_t stack = 0;
	int err;

	/* insert all statically known types */
	err = fs_walk(script, static_pre, static_post, prov);
	if (err) {
		_e("static annotation failed (%d)", err);
		return err;
	}

	/* infer the rest */
	err = fs_walk(script, NULL, type_infer_post, NULL);
	if (err) {
		_e("type inference failed (%d)", err);
		return err;
	}

	err = fs_walk(script, NULL, type_infer_post, NULL);
	if (err) {
		_e("type inference failed (%d)", err);
		return err;
	}

	/* allocate stack locations for symbols */
	for (dyn = script->script.dyns; dyn; dyn = dyn->next) {
		if (dyn->ssize)
			stack -= dyn->ssize;
		else if (dyn->string)
			stack -= dyn->size + dyn->ksize;
		else
			continue;

		dyn->loc.addr = stack;
	}
	return 0;
}
