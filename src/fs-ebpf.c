#include <assert.h>
#include <byteswap.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <linux/bpf.h>

#include "fs-ast.h"
#include "fs-ebpf.h"
#include "provider.h"

#define RET_ON_ERR(_err, _fmt, ...)					\
	if (_err) {							\
		fprintf(stderr, "error(%s:%d): " _fmt, __func__, _err,	\
			##__VA_ARGS__);					\
	}

#define _ALIGN 4
#define _ALIGNED(_size) (((_size) + _ALIGN - 1) & ~(_ALIGN - 1))

struct sym {
	const char *name;
	/* ssize_t     addr; */
	/* ssize_t     key_addr; */
	
	struct fs_annot annot;
	struct fs_node *keys;
};

struct symtable {
	size_t cap, len;
	struct sym *table;
};

void symtable_dump(struct symtable *st)
{
	struct sym *sym;
	size_t i;

	fprintf(stderr, "syms:%lu\n", st->len);
	
	for (i = 0, sym = st->table; i < st->len; i++, sym++)
		fprintf(stderr, "  name:%s(%s/%lu) addr:%ld\n", sym->name,
			fs_typestr(sym->annot.type), sym->annot.size,
			sym->annot.addr);
}

/* ssize_t symtable_reserve_map(struct symtable *st, struct fs_node *map) */
/* { */
/* 	struct fs_node *c; */
/* 	ssize_t addr = 0; */

/* 	fs_foreach(c, map->map.vargs) */
/* 		addr = symtable_reserve(st, c->annot.size); */

/* 	return addr; */
/* } */

struct sym *symtable_get(struct symtable *st, const char *name)
{
	size_t i;

	for (i = 0; i < st->len; i++) {
		if (!strcmp(st->table[i].name, name))
			return &st->table[i];
	}

	return NULL;
}

static inline int symtable_transfer(struct symtable *st, struct fs_node *n)
{
	struct sym *sym;

	if (n->type != FS_VAR && n->type != FS_MAP)
		return 0;

	sym = symtable_get(st, n->string);
	if (!sym || sym->annot.type == FS_UNKNOWN)
		RET_ON_ERR(-ENOENT, "%s used before initialization\n", n->string);

	n->annot = sym->annot;
	return 0;
}

static inline int symtable_transfer_map(struct symtable *st, struct fs_node *map)
{
	struct fs_node *c;
	int err;

	fs_foreach(c, map->map.vargs) {
		err = symtable_transfer(st, c);
		if (err)
			return err;
	}

	return 0;
}

int symtable_restrict(struct symtable *st, struct fs_node *n, struct fs_node *expr)
{
	struct sym *sym = symtable_get(st, n->string);

	if (!sym)
		RET_ON_ERR(-ENOENT, "assignment to unknown symbol %s\n",
			   n->string);

	if (sym->annot.type == FS_UNKNOWN) {
		sym->annot = expr->annot;
		return 0;
	}

	if (fs_annot_compatible(&sym->annot, &expr->annot))
		return 0;

	symtable_dump(st);
	RET_ON_ERR(-EINVAL, "conflicting type for %s, known:%s/%lu new:%s/%lu\n",
		   sym->name,
		   fs_typestr(sym->annot.type), sym->annot.size,
		   fs_typestr(expr->annot.type), expr->annot.size);

	return 0;
}

static int symtable_restrict_map(struct symtable *st, struct sym *sym,
				 struct fs_node *map)
{
	struct fs_node *known, *new;
	int i = 1;

	known = sym->keys;
	new = map->map.vargs;
	for (; known && new; known = known->next, new = new->next, i++) {
		if (fs_annot_compatible(&new->annot, &known->annot))
			continue;

		RET_ON_ERR(-EINVAL, "conflicting types for %s keys, argument "
			   "%d, known:%s/%lu new:%s/%lu\n", sym->name, i,
			   fs_typestr(known->annot.type), known->annot.size,
			   fs_typestr(new->annot.type), new->annot.size);
	}

	if (!!known ^ !!new)
		RET_ON_ERR(-EINVAL, "conflicting number of arguments for %s\n",
			   sym->name);

	return 0;
}

int symtable_add(struct symtable *st, struct fs_node *n)
{
	struct sym *sym;
	int err;
	
	sym = symtable_get(st, n->string);
	if (sym) {
		if (n->type == FS_VAR)
			return 0;
		else {
			err = symtable_transfer_map(st, n);
			if (err)
				return err;
			
			return symtable_restrict_map(st, sym, n);
		}
	}
	
	if (st->len == st->cap) {
		st->cap += 16;
		st->table = realloc(st->table, sizeof(*st));
		memset(&st->table[st->len], 0, 16 * sizeof(*st));
	}

	sym = &st->table[st->len++];
	sym->name  = n->string;
	sym->annot = n->annot;
	
	if (n->type == FS_MAP) {		
		sym->keys = n->map.vargs;
		err = symtable_transfer_map(st, n);
		if (err)
			return err;

		/* sym->key_addr = symtable_reserve_map(st, n); */
	}
	return 0;
}

struct symtable *symtable_new(void)
{
	struct symtable *st = calloc(1, sizeof(*st));

	assert(st);
	return st;
}



ssize_t ebpf_reserve(struct ebpf *e, size_t size)
{
	e->stack -= _ALIGNED(size);
	return e->stack;
}

static int ebpf_push(struct ebpf *e, ssize_t at, void *data, size_t size)
{
	uint32_t *wdata = data;	/* TODO: ENSURE ALIGNMENT */
	size_t left = _ALIGNED(size) / sizeof(*wdata);

	for (; left; left--, wdata++, at += sizeof(*wdata))
		*(e->ip++) = STW(BPF_REG_10, at, *wdata);

	return 0;
}

/* static int ebpf_mov(struct ebpf *e, int dst, struct fs_node *n) */
/* { */
/* 	switch (n->type) { */
/* 	case FS_INT: */
/* 		*(e->ip)++ = MOV_IMM(dst, n->integer); */
/* 		break; */

/* 	default: */
/* 		assert(0); */
/* 	} */

/* 	return 0; */
/* } */

struct ebpf *ebpf_new(struct provider *provider)
{
	struct ebpf *e = calloc(1, sizeof(*e));

	assert(e);
	e->provider = provider;
	e->st       = symtable_new();
	e->ip       = e->prog;
	return e;
}

static int _fs_compile_pre(struct fs_node *n, void *_e)
{
	/* struct ebpf *e = _e; */

	return 0;
}

static int _fs_compile_post(struct fs_node *n, void *_e)
{
	struct ebpf *e = _e;

	switch (n->type) {
	case FS_STR:
		ebpf_push(e, n->annot.addr, n->string, n->annot.size);
		break;

	default:
		break;
	}
	
	return 0;
}

static int _fs_annotate_post(struct fs_node *n, void *_e)
{
	struct ebpf *e = _e;
	int err = 0;

	switch (n->type) {
	case FS_STR:
		n->annot.type = FS_STR;
		n->annot.size = strlen(n->string);
		n->annot.addr = ebpf_reserve(e, n->annot.size);
		break;
	case FS_INT:
		n->annot.type = FS_INT;
		n->annot.size = sizeof(n->integer);
		break;
	case FS_NOT:
		n->annot.type = n->not->annot.type;
		n->annot.size = n->not->annot.size;
		break;
	case FS_BINOP:
		err = symtable_transfer(e->st, n->binop.left);
		if (err)
			return err;

		err = symtable_transfer(e->st, n->binop.right);
		if (err)
			return err;

		if (n->binop.left->annot.type != FS_INT || 
		    n->binop.right->annot.type != FS_INT)
			RET_ON_ERR(-EINVAL, "binop: expected type int\n");

		n->annot.type = n->binop.left->annot.type;
		n->annot.size = n->binop.left->annot.size;
		break;
	case FS_RETURN:
		if (n->ret->annot.type != FS_INT)
			RET_ON_ERR(-EINVAL, "return: unexpected type %s\n",
				   fs_typestr(n->ret->annot.type));

		n->annot.type = n->ret->annot.type;
		n->annot.size = n->ret->annot.size;
		break;
	case FS_ASSIGN:
		err = symtable_transfer(e->st, n->assign.expr);
		if (err)
			return err;

		n->assign.lval->annot.type = n->assign.expr->annot.type;
		n->assign.lval->annot.size = n->assign.expr->annot.size;
		n->assign.lval->annot.addr = ebpf_reserve(e, n->assign.lval->annot.size);

		err = symtable_add(e->st, n->assign.lval);
		if (err)
			return err;

		err = symtable_restrict(e->st, n->assign.lval, n->assign.expr);
		if (err)
			return err;

		break;
	case FS_CALL:
		err = e->provider->annotate(e->provider, n);
		RET_ON_ERR(err, "fs_annotate: call(%s): unknown function or invalid parameters\n",
			   n->string);
		break;

	default:
		break;
	}

	return err;
}

static int fs_annotate(struct fs_node *probe, struct ebpf *e)
{
	fs_walk(probe, NULL, _fs_annotate_post, e);

	symtable_dump(e->st);
	return 0;
}

struct ebpf *fs_compile(struct fs_node *probe, struct provider *provider)
{
	struct ebpf *e = ebpf_new(provider);
	int err;
	
	err = fs_annotate(probe, e);
	if (err)
		goto err;

	err = fs_walk(probe, _fs_compile_pre, _fs_compile_post, e);
	if (err)
		goto err;

	return e;
err:
	free(e);
	return NULL;
}
