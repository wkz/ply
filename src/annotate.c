#include <errno.h>
#include <inttypes.h>
#include <string.h>

#include "ply.h"
#include "lang/ast.h"
#include "pvdr/pvdr.h"

#define b_xor(_a, _b) ((!!(_a)) ^ (!!(_b)))

static int loc_assign_pre(node_t *n, void *_probe)
{
	node_t *c, *probe = _probe;
	ssize_t addr;

	switch (n->type) {
	case TYPE_NONE:
	case TYPE_SCRIPT:
		return 0;

	case TYPE_PROBE:
		c = n->probe.pred;
		if (c) {
			c->dyn.loc = LOC_REG;
			c->dyn.reg = BPF_REG_0;
			c->dyn.free_regs =
				(1 << BPF_REG_6) |
				(1 << BPF_REG_7) |
				(1 << BPF_REG_8);
		}

		node_foreach(c, n->probe.stmts) {
			c->dyn.free_regs =
				(1 << BPF_REG_6) |
				(1 << BPF_REG_7) |
				(1 << BPF_REG_8);
		}
		return 0;

	case TYPE_CALL:
		if (n->parent->type == TYPE_PROBE) {
			n->dyn.loc = LOC_REG;
			n->dyn.reg = BPF_REG_0;
		}

		return probe->probe.pvdr->loc_assign(n);

	case TYPE_ASSIGN:
		n->dyn.loc = LOC_REG;
		n->dyn.reg = BPF_REG_0;

		c = n->assign.lval;
		c->dyn.loc  = LOC_STACK;
		c->dyn.addr = node_probe_stack_get(probe, c->dyn.size);

		if (n->assign.op == ALU_OP_MOV) {
			n->assign.expr->dyn.loc  = LOC_STACK;
			n->assign.expr->dyn.addr = c->dyn.addr;
		} else {
			n->assign.expr->dyn.loc = LOC_REG;
			n->assign.expr->dyn.reg = BPF_REG_1;
		}
		return 0;
	case TYPE_METHOD:
		c = n->method.map;
		c->dyn.loc  = LOC_STACK;
		c->dyn.addr = node_probe_stack_get(probe, c->dyn.size);
		return 0;

	case TYPE_RETURN:
		c = n->ret;
		c->dyn.loc = LOC_REG;
		c->dyn.reg = BPF_REG_0;
		return 0;

	case TYPE_BINOP:
		/* TODO */
		return 0;

	case TYPE_NOT:
		c = n->not;
		c->dyn.loc  = n->dyn.loc;
		c->dyn.reg  = n->dyn.reg;
		c->dyn.addr = n->dyn.addr;
		return 0;

	case TYPE_MAP:
		c = n->map.rec;
		c->dyn.loc  = LOC_STACK;
		c->dyn.addr = node_probe_stack_get(probe, c->dyn.size);
		return 0;

	case TYPE_REC:
		addr = n->dyn.addr;
		node_foreach(c, n->rec.vargs) {
			c->dyn.loc  = LOC_STACK;
			c->dyn.addr = addr;
			addr += c->dyn.size;
		}
		return 0;

	case TYPE_STR:
	case TYPE_INT:
		return 0;
	}

	return -ENOSYS;
}

static int loc_assign(node_t *script)
{
	node_t *probe;
	int err;
	
	node_foreach(probe, script->script.probes) {
		err = node_walk(probe, loc_assign_pre, NULL, probe);
		if (err)
			return err;
	}

	return 0;
}

static int type_sync(node_t *a, node_t *b)
{
	node_t *ac, *bc;
	char *map_name = NULL;
	int i;

	/* if only one side is known, transfer it to the other
	 * side. if both sides are known, they must be equal. */

	if (b_xor(a->dyn.type, b->dyn.type)) {
		if (a->dyn.type)
			b->dyn.type = a->dyn.type;
		else
			a->dyn.type = b->dyn.type;
	} else if (a->dyn.type != b->dyn.type) {
		_e("%s: type mismatch: %s != %s", a->string,
		   type_str(a->dyn.type), type_str(b->dyn.type));
		return -EINVAL;
	}

	if (b_xor(a->dyn.size, b->dyn.size)) {
		if (a->dyn.size)
			b->dyn.size = a->dyn.size;
		else
			a->dyn.size = b->dyn.size;
	} else if (a->dyn.size != b->dyn.size) {
		_e("%s: size mismatch: %zx != %zx", a->string,
		   a->dyn.size, b->dyn.size);
		return -EINVAL;		
	}

	/* for types other than literal records, just compare the size */
	if (!(a->type == TYPE_REC && b->type == TYPE_REC))
		return 0;

	if (a->parent->type == TYPE_MAP)
		map_name = a->parent->string;

	/* when syncing record literals, also verify each of their
	 * respective components */
	for (i = 1, ac = a->rec.vargs, bc = b->rec.vargs;
	     ac && bc; i++, ac = ac->next, bc = bc->next) {
		if (ac->dyn.type != bc->dyn.type ||
		    ac->dyn.size != bc->dyn.size) {			
			_e("%s%srecord mismatch, argument %d: "
			   "%s/%#zx != %s/%#zx",
			   map_name ? : "", map_name ? ": key " : "", i,
			   type_str(ac->dyn.type), ac->dyn.size,
			   type_str(bc->dyn.type), bc->dyn.size);
			return -EINVAL;
		}
	}

	if (ac || bc) {
		_e("%s%srecord mismatch, expected %i argument(s)",
		   map_name ? : "", map_name ? ": key " : "", i);
		return -EINVAL;
	}

	return 0;
}

static int type_sync_map(node_t *a, node_t *b)
{
	node_t *a_rec = a->map.rec, *b_rec = b->map.rec;
	int err;

	err = type_sync(a, b);
	if (err)
		return err;

	if (!(a_rec->dyn.size && b_rec->dyn.size))
		return 0;


	return type_sync(a_rec, b_rec);
}

static int type_infer_map(node_t *script, node_t *n)
{
	mdyn_t *mdyn;

	for (mdyn = script->script.mdyns; mdyn; mdyn = mdyn->next) {
		if (!strcmp(mdyn->map->string, n->string))
			return type_sync_map(n, mdyn->map);
	}

	mdyn = calloc(1, sizeof(*mdyn));
	assert(mdyn);

	mdyn->map = n;

	if (!script->script.mdyns)
		script->script.mdyns = mdyn;
	else
		insque_tail(mdyn, script->script.mdyns);

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
	case TYPE_METHOD:
		to = (from == p->method.map) ? p->method.call : p->method.map;
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

static int type_infer_post(node_t *n, void *_script)
{
	node_t *script = _script;
	node_t *c;
	size_t sz = 0;
	int err;

	switch (n->type) {
	case TYPE_REC:
		/* when the sizes of all arguments are known, the size
		 * of the record is their sum. */
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
		break;
	case TYPE_MAP:
		err = type_infer_map(script, n);
		if (err)
			return err;
		break;
	default:
		break;
	}
	
	err = type_bubble(n);
	if (err)
		return err;

	return 0;
}

static int static_post(node_t *n, void *_null)
{
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
		err = node_get_pvdr(n)->annotate(n);
		if (err)
			return err;
		break;
	default:
		break;
	}
	
	return 0;
}

int annotate_script(node_t *script)
{
	int err;

	/* insert all statically known types */
	err = node_walk(script, NULL, static_post, NULL);
	_d("static inference done: %d", err);

	/* infer the rest. ...yes do three passes, this catches cases
	 * where maps are used as rvalues before being used as
	 * lvalues. TODO: this should be possible with two passes */
	err = err? : node_walk(script, NULL, type_infer_post, script);
	err = err? : node_walk(script, NULL, type_infer_post, script);
	err = err? : node_walk(script, NULL, type_infer_post, script);
	_d("dynamic inference done: %d", err);

	/* calculate register or stack location of each node */
	err = err? : loc_assign(script);
	_d("location assigment done: %d", err);
	return err;
}
