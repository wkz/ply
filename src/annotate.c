/*
 * Copyright 2015-2016 Tobias Waldekranz <tobias@waldekranz.com>
 *
 * This file is part of ply.
 *
 * ply is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, under the terms of version 2 of the
 * License.
 *
 * ply is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ply.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>

#include <ply/ast.h>
#include <ply/ply.h>
#include <ply/pvdr.h>
#include <ply/symtable.h>

#define b_xor(_a, _b) ((!!(_a)) ^ (!!(_b)))

static int loc_assign_binop(node_t *n, node_t *probe)
{
	node_t *l, *r;

	l = n->binop.left;
	r = n->binop.right;

	if (l->dyn->loc == LOC_REG)
		goto ldone;

	l->dyn->loc = LOC_REG;
	if (n->dyn->loc == LOC_REG && ((1 << n->dyn->reg) & DYN_REGS))
		l->dyn->reg = n->dyn->reg;
	else
		l->dyn->reg = node_probe_reg_get(probe, 1);

	if (l->dyn->reg >= 0)
		goto ldone;

	l->dyn->loc  = LOC_STACK;
	if (n->dyn->loc == LOC_STACK)
		l->dyn->addr = n->dyn->addr;
	else
		l->dyn->addr = node_probe_stack_get(probe, l->dyn->size);

ldone:
	if (r->dyn->loc == LOC_REG)
		goto rdone;

	if (r->type == TYPE_INT &&
	    r->integer >= INT32_MIN &&
	    r->integer <= INT32_MAX)
		goto rdone;

	r->dyn->loc = LOC_REG;
	r->dyn->reg = node_probe_reg_get(probe, 1);
	if (r->dyn->reg < 0) {
		r->dyn->loc  = LOC_STACK;
		r->dyn->addr = node_probe_stack_get(probe, r->dyn->size);
	}

rdone:
	return 0;
}

static int loc_assign_map(node_t *n, node_t *probe)
{
	if (n->dyn->loc != LOC_NOWHERE)
		return 0;

	n->dyn->loc  = LOC_STACK;
	n->dyn->addr = node_probe_stack_get(probe, n->dyn->size);
}

static int loc_assign_var(node_t *n, node_t *probe)
{
	node_fdump(n, stderr);

	if (n->dyn->loc != LOC_NOWHERE)
		return 0;

	if (n->dyn->type == TYPE_INT) {
		n->dyn->loc = LOC_REG;
		n->dyn->reg = node_probe_reg_get(probe, 0);

		if (n->dyn->reg > 0)
			return 0;
	}

	n->dyn->loc = LOC_NOWHERE;
	return loc_assign_map(n, probe); 
}

static int loc_assign_assign(node_t *n, node_t *probe)
{
	node_t *c;
	int err = 0;

	c = n->assign.lval;
	switch (c->type) {
	case TYPE_VAR:
		err = loc_assign_var(c, probe);
		break;

	case TYPE_MAP:
		err = loc_assign_map(c, probe);
		break;

	default:
		err = -ENOSYS;
		break;
	}

	if (!err && n->assign.expr) {
		n->assign.expr->dyn->loc  = c->dyn->loc;
		n->assign.expr->dyn->reg  = c->dyn->reg;
		n->assign.expr->dyn->addr = c->dyn->addr;
	}

	return err;
}

static int loc_assign_pre(node_t *n, void *_probe)
{
	node_t *c, *probe = _probe;
	ssize_t addr;

	switch (n->type) {
	case TYPE_PROBE:
		c = n->probe.pred;
		if (c) {
			c->dyn->loc = LOC_REG;
			c->dyn->reg = BPF_REG_0;
		}

		return 0;

	case TYPE_CALL:
		if (n->parent->type == TYPE_PROBE ||
		    n->parent->type == TYPE_UNROLL) {
			n->dyn->loc = LOC_REG;
			n->dyn->reg = BPF_REG_0;
		}

		return n->dyn->call.func->loc_assign(n);

	case TYPE_ASSIGN:
		n->dyn->loc = LOC_REG;
		n->dyn->reg = BPF_REG_0;
		return loc_assign_assign(n, probe);

	case TYPE_METHOD:
		c = n->method.map;
		c->dyn->loc  = LOC_STACK;
		c->dyn->addr = node_probe_stack_get(probe, c->dyn->size);
		return 0;

	case TYPE_RETURN:
		c = n->ret;
		c->dyn->loc = LOC_REG;
		c->dyn->reg = BPF_REG_0;
		return 0;

	case TYPE_BINOP:
		return loc_assign_binop(n, probe);

	case TYPE_NOT:
		c = n->not;
		c->dyn->loc  = n->dyn->loc;
		c->dyn->reg  = n->dyn->reg;
		c->dyn->addr = n->dyn->addr;
		return 0;

	case TYPE_VAR:
		return loc_assign_var(n, probe);

	case TYPE_MAP:
		/* upper node wants result in a register, but we still
		 * need stack space to bounce the data in */
		if (n->dyn->loc == LOC_REG && !n->dyn->addr)
			n->dyn->addr = node_probe_stack_get(probe, n->dyn->size);

		c = n->map.rec;
		c->dyn->loc  = LOC_STACK;
		c->dyn->addr = node_probe_stack_get(probe, c->dyn->size);
		return 0;

	case TYPE_REC:
		addr = n->dyn->addr;
		node_foreach(c, n->rec.vargs) {
			if (c->type != TYPE_VAR) {
				c->dyn->loc  = LOC_STACK;
				c->dyn->addr = addr;
			}

			addr += c->dyn->size;
		}
		return 0;

	case TYPE_NONE:
	case TYPE_SCRIPT:
	case TYPE_UNROLL:
	case TYPE_STR:
	case TYPE_INT:
		return 0;
	}

	return -ENOSYS;
}

static int loc_assign_post(node_t *n, void *_probe)
{
	node_t *probe = _probe;
	node_t *script = node_get_script(probe);
	sym_t *s;

	switch (n->type) {
	case TYPE_UNROLL:		
	case TYPE_VAR:
		sym_foreach(s, script->dyn->script.st->syms) {
			if (s->type == TYPE_VAR &&
			    s->var.last == n &&
			    s->dyn.loc == LOC_REG) {
				/* this was the last reference to this var */
				probe->dyn->probe.stat_regs |= (1 << s->dyn.reg);
				break;
			}
		}
		break;
	default:
		break;
	}

	/* for now, reset the dynamic registers after each statement,
	 * we can do something more fine grained in the future. */
	if (n->parent->type == TYPE_UNROLL ||
	    n->parent->type == TYPE_PROBE) {
		probe->dyn->probe.dyn_regs = DYN_REGS;
	}

	return 0;
}

static int loc_assign(node_t *script)
{
	node_t *probe;
	int err;
	
	node_foreach(probe, script->script.probes) {
		probe->dyn->probe.dyn_regs = DYN_REGS;
		probe->dyn->probe.stat_regs = DYN_REGS;

		err = node_walk(probe, loc_assign_pre, loc_assign_post, probe);
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

	if (b_xor(a->dyn->type, b->dyn->type)) {
		if (a->dyn->type)
			b->dyn->type = a->dyn->type;
		else
			a->dyn->type = b->dyn->type;
	} else if (a->dyn->type != b->dyn->type) {
		_e("%s: type mismatch: %s != %s", a->string,
		   type_str(a->dyn->type), type_str(b->dyn->type));
		return -EINVAL;
	}

	if (b_xor(a->dyn->size, b->dyn->size)) {
		if (a->dyn->size)
			b->dyn->size = a->dyn->size;
		else
			a->dyn->size = b->dyn->size;
	} else if (a->dyn->size != b->dyn->size) {
		_e("%s: size mismatch: %zx != %zx", a->string,
		   a->dyn->size, b->dyn->size);
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
		if (ac->dyn->type != bc->dyn->type ||
		    ac->dyn->size != bc->dyn->size) {			
			_e("%s%srecord mismatch, argument %d: "
			   "%s/%#zx != %s/%#zx",
			   map_name ? : "", map_name ? ": key " : "", i,
			   type_str(ac->dyn->type), ac->dyn->size,
			   type_str(bc->dyn->type), bc->dyn->size);
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
			if (c->dyn->size) {
				sz += c->dyn->size;
			} else {
				sz = 0;
				break;
			}
		}

		if (sz)
			n->dyn->size = sz;
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
	int err = 0;

	switch (n->type) {
	case TYPE_INT:
	case TYPE_NOT:
	case TYPE_RETURN:
		n->dyn->type = TYPE_INT;
		n->dyn->size = 8;
		break;
	case TYPE_STR:
		escaped = str_escape(n->string);

		n->dyn->type = TYPE_STR;
		n->dyn->size = _ALIGNED(strlen(escaped) + 1);

		n->string = calloc(1, n->dyn->size);
		memcpy(n->string, escaped, n->dyn->size);
		free(escaped);
		break;
	case TYPE_REC:
		n->dyn->type = TYPE_REC;
		break;
	case TYPE_BINOP:
		n->dyn->type = TYPE_INT;
		n->dyn->size = 8;
		break;
	case TYPE_CALL:
		err = n->dyn->call.func->annotate(n);
		break;
	default:
		break;
	}
	
	if (err) {
		char nstr[0x80];

		node_sdump(n, nstr, sizeof(nstr));
		_e("node:%s : %s", nstr, strerror(-err));
	}
	return err;
}

int annotate_script(node_t *script)
{
	symtable_t *st;
	int err;

	st = calloc(1, sizeof(*st));
	assert(st);
	err = symtable_populate(st, script);
	if (err) {
		_e("failed to populate symbol table");
		return err;
	}

	script->dyn->script.st = st;

	if (G.dump)
		symtable_fdump(st, stderr);

	/* insert all statically known types */
	err = node_walk(script, NULL, static_post, NULL);
	if (err) {
		_e("static type inference failed");
		return err;
	}

	/* infer the rest. ...yes do three passes, this catches cases
	 * where maps are used as rvalues before being used as
	 * lvalues. TODO: this should be possible with two passes */
	err =        node_walk(script, NULL, type_infer_post, script);
	err = err? : node_walk(script, NULL, type_infer_post, script);
	err = err? : node_walk(script, NULL, type_infer_post, script);
	if (err) {
		_e("dynamic type inference failed: %s", strerror(-err));
		return err;
	}

	/* calculate register or stack location of each node */
	err = loc_assign(script);
	if (err) {
		_e("location assignment failed: %s", strerror(-err));
		return err;
	}

	_d("ok");
	return 0;
}
