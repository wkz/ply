#include <ply/ply.h>
#include <ply/symtable.h>

#include "config.h"

int sym_fdump(sym_t *s, FILE *fp)
{
	int w;

	switch (s->type) {
	case TYPE_VAR:
		fprintf(fp, "%s(%s)%n", s->name, s->var.probe->string, &w);
		if (w < 40)
			fprintf(fp, "%*s", 40 - w, "");
		break;
	case TYPE_MAP:
		fprintf(fp, "%-40s", s->name);
		break;
	default:
		_d("corrupt sym (%s)", type_str(s->type));
		return -EINVAL;
	}

	fprintf(fp, " (type:%s/%s size:0x%zx loc:%s",
		type_str(s->type), type_str(s->dyn.type),
		s->dyn.size, loc_str(s->dyn.loc));

	switch (s->dyn.loc) {
	case LOC_NOWHERE:
	case LOC_VIRTUAL:
		break;
	case LOC_REG:
		fprintf(fp, "/%d", s->dyn.reg);
		break;
	case LOC_STACK:
		fprintf(fp, "/-0x%zx", -s->dyn.addr);
		break;
	}

	fputs(")", fp);
	return 0;
}

int symtable_fdump(symtable_t *st, FILE *fp)
{
	sym_t *s;
	int err = 0;

	fputs("symtable:\n", fp);
	sym_foreach(s, st->syms) {
		err = sym_fdump(s, fp);
		fputc('\n', fp);
		if (err)
			return err;
	}

	return 0;
}

#ifdef LINUX_HAS_STACKMAP
sym_t *symtable_get_stack(symtable_t *st)
{
	sym_t *s;

	sym_foreach(s, st->syms) {
		if (s->type == TYPE_MAP && !strcmp(s->name, "stack"))
			return s;
	}

	return NULL;
}

int symtable_ref_stack(symtable_t *st)
{
	sym_t *s;

	s = symtable_get_stack(st);
	if (s)
		return 0;

	s = calloc(1, sizeof(*s));
	assert(s);

	s->type = TYPE_MAP;
	s->name = strdup("stack"); /* user maps start with @ => no conflict */
	s->dyn.map.type  = BPF_MAP_TYPE_STACK_TRACE;
	s->dyn.map.ksize = sizeof(uint32_t);
	s->dyn.map.vsize = sizeof(uint64_t) * 0x10; /* save 16 frames */
	s->dyn.map.nelem = G.map_nelem;

	if (st->syms)
		insque_tail(s, st->syms);
	else
		st->syms = s;

	return 0;
}
#else
sym_t *symtable_get_stack(symtable_t *st) { return NULL; }
int    symtable_ref_stack(symtable_t *st) { return -ENOSYS; }
#endif	/* LINUX_HAS_STACKMAP */

sym_t *symtable_get(symtable_t *st, node_t *n)
{
	sym_t *s;

	sym_foreach(s, st->syms) {
		if (s->type != n->type ||
		    strcmp(s->name, n->string))
			continue;

		if (s->type == TYPE_VAR &&
		    node_get_probe(n) != s->var.probe)
			continue;

		return s;
	}

	return NULL;
}

static int symtable_ref_map(symtable_t *st, node_t *map)
{
	sym_t *s;

	s = symtable_get(st, map);
	if (s)
		goto found;

	s = calloc(1, sizeof(*s));
	assert(s);

	s->type = map->type;
	s->name = strdup(map->string);
	s->map.map = map;
	s->dyn.map.type = BPF_MAP_TYPE_HASH;

	if (st->syms)
		insque_tail(s, st->syms);
	else
		st->syms = s;

found:
	map->dyn = &s->dyn;
	return 0;
}

static int symtable_ref_var(symtable_t *st, node_t *var)
{
	node_t *unroll;
	sym_t *s;

	s = symtable_get(st, var);
	if (s) {
		s->var.last = var;
		goto found;
	}

	s = calloc(1, sizeof(*s));
	assert(s);

	s->type = var->type;
	s->name = strdup(var->string);
	s->var.probe = node_get_probe(var);
	s->var.first = s->var.last = var;

	unroll = node_get_parent_of_type(TYPE_UNROLL, var);
	if (unroll)
		s->var.last = unroll;
		
	if (st->syms)
		insque_tail(s, st->syms);
	else
		st->syms = s;

found:
	var->dyn = &s->dyn;
	return 0;

}

static int _symtable_populate(node_t *n, void *_st)
{
	symtable_t *st = _st;

	switch (n->type) {
	case TYPE_MAP:
		return symtable_ref_map(st, n);
	case TYPE_VAR:
		return symtable_ref_var(st, n);

	default:
		break;
	}

	return 0;
}

int symtable_type_sync(symtable_t *st, node_t *to, node_t *from)
{
	sym_t *s;

	s = symtable_get(st, to);
	if (!s) {
		_e("unknown symbol '%s'", to->string);
		return -EINVAL;
	}

	
	return 0;
}

int symtable_populate(symtable_t *st, node_t *script)
{
	return node_walk(script, NULL, _symtable_populate, st);
}
