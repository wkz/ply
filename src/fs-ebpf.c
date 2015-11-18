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
	ssize_t     addr;
	size_t      size;

	int         in_reg;
	
	struct fs_annot annot;
	struct fs_node *keys;
	int mapfd;
};

struct reg {
	const int reg;

	enum {
		REG_EMPTY,
		REG_SYM,
		REG_NODE,
	} type;

	int age;
	
	union {
		void           *obj;
		struct sym     *sym;
		struct fs_node *n;
	};
};

struct symtable {
	size_t cap, len;
	struct sym *table;

	int         age;
	struct reg  reg[__MAX_BPF_REG];
	ssize_t     stack_top;
};

void symtable_dump(struct symtable *st)
{
	struct sym *sym;
	size_t i;

	fprintf(stderr, "syms:%lu stack_top:-%#lx\n", st->len, (size_t)-st->stack_top);
	
	for (i = 0, sym = st->table; i < st->len; i++, sym++)
		fprintf(stderr, "  name:%-10.10s type:%s/%#lx  addr:-%#lx+%#lx\n", sym->name,
			fs_typestr(sym->annot.type), sym->annot.size,
			(size_t)-sym->addr, sym->size);
}

ssize_t symtable_reserve(struct symtable *st, size_t size)
{
	st->stack_top -= size;
	return st->stack_top;
}

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
	sym->size  = _ALIGNED(n->annot.size);

	if (n->type == FS_MAP) {		
		struct fs_node *key;

		sym->keys = n->map.vargs;
		fs_foreach(key, sym->keys)
			sym->size += _ALIGNED(key->annot.size);
	}

	sym->addr = symtable_reserve(st, sym->size);
	return 0;
}

struct symtable *symtable_new(void)
{
	struct symtable *st = calloc(1, sizeof(*st));
	int i;

	assert(st);

	for (i = BPF_REG_0; i < __MAX_BPF_REG; i++)
		*(int *)(&st->reg[i].reg) = i;
	return st;
}






static inline void ebpf_emit(struct ebpf *e, struct bpf_insn insn)
{
	FILE *dasm = popen("ebpf-dasm >&2", "w");

	if (dasm) {
		fwrite(&insn, sizeof(insn), 1, dasm);
		pclose(dasm);
	} else {
		assert(0);
	}

	*(e->ip)++ = insn;
}

/* static int ebpf_push(struct ebpf *e, ssize_t at, void *data, size_t size) */
/* { */
/* 	uint32_t *wdata = data;	/\* TODO: ENSURE ALIGNMENT *\/ */
/* 	size_t left = _ALIGNED(size) / sizeof(*wdata); */

/* 	for (; left; left--, wdata++, at += sizeof(*wdata)) */
/* 		*(e->ip++) = STW(BPF_REG_10, at, *wdata); */

/* 	return 0; */
/* } */

static struct reg *ebpf_reg_find(struct ebpf *e, struct fs_node *n)
{
	struct reg *r;
	void *obj = n;
	int type = REG_NODE;

	if (n->type == FS_VAR || n->type == FS_MAP) {
		type = REG_SYM;
		obj  = symtable_get(e->st, n->string);
	}

	for (r = &e->st->reg[BPF_REG_0]; r <= &e->st->reg[BPF_REG_9]; r++) {
		if (r->type == type && r->obj == obj)
			return r;
	}

	return NULL;
}

/* static void ebpf_reg_clean(struct ebpf *e, struct fs_node *n) */
/* { */
/* 	struct reg *r; */

/* 	if (n->type != FS_VAR && n->type != FS_MAP) */
/* 		return; */

/* 	r = ebpf_reg_find(e, n); */
/* 	if (r) */
/* 		r->type = REG_EMPTY; */
/* } */

static int ebpf_mov(struct ebpf *e, int dst, struct fs_node *n)
{
	struct reg *r;

	if (n->type == FS_INT) {
		ebpf_emit(e, MOV_IMM(dst, n->integer));
		return 0;
	}

	r = ebpf_reg_find(e, n);
	if (!r)
		return -ENOENT;

	if (dst != r->reg)
		ebpf_emit(e, MOV(dst, r->reg));

	return 0;
}

static int ebpf_alu(struct ebpf *e, int dst, enum fs_op op, struct fs_node *expr)
{
	struct reg *r;

	if (expr->type == FS_INT) {
		ebpf_emit(e, ALU_IMM(op, dst, expr->integer));
		return 0;
	}

	r = ebpf_reg_find(e, expr);
	if (!r)
		return -ENOENT;

	ebpf_emit(e, ALU(op, dst, r->reg));
	return 0;
}

static struct reg *ebpf_reg_swap(struct ebpf *e, struct reg *r, struct fs_node *n)
{
	int err;

	if (r->type == REG_SYM) {
		ebpf_emit(e, STXDW(BPF_REG_10, r->sym->addr, r->reg));
		r->sym->in_reg = 0;
	}

	switch (n->type) {
	case FS_VAR:
	case FS_MAP:
		r->type = REG_SYM;
		r->sym = symtable_get(e->st, n->string);
		r->sym->in_reg = 1;
		break;
	default:
		r->type = REG_NODE;
		r->n = n;
		break;
	}

	r->age  = ++(e->st->age);

	err = ebpf_mov(e, r->reg, n);
	if (err)
		return NULL;

	return r;
}

static struct reg *ebpf_load(struct ebpf *e, struct fs_node *n)
{
	struct reg *r, *r_aged;

	r = ebpf_reg_find(e, n);
	if (r)
		return r;
	
	for (r = &e->st->reg[BPF_REG_9]; r >= &e->st->reg[BPF_REG_0]; r--) {
		if (r->type == REG_EMPTY)
			return ebpf_reg_swap(e, r, n);

		if (r->type == REG_SYM && (!r_aged || r->age < r_aged->age))
			r_aged = r;
	}

	if (!r_aged)
		return NULL;

	return ebpf_reg_swap(e, r_aged, n);
}

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
	struct reg  *dst;
	/* int dst; */
	/* struct sym *sym; */

	fprintf(stderr, ";; %s(%s)\n", n->string ? : "anon", fs_typestr(n->type));
	
	switch (n->type) {
	/* case FS_STR: */
	/* 	sym */
	/* 	ebpf_push(e, n->annot.addr, n->string, n->annot.size); */
	/* 	break; */

	case FS_BINOP:
		dst = ebpf_load(e, n->binop.left);
		if (!dst)
			return -ENOSPC;

		ebpf_alu(e, dst->reg, n->binop.op, n->binop.right);
		ebpf_reg_swap(e, dst, n);
		
		/* ebpf_reg_clean(e, n->binop.left); */
		/* ebpf_reg_clean(e, n->binop.right); */
		break;

	case FS_RETURN:
		ebpf_mov(e, BPF_REG_0, n->ret);
		ebpf_emit(e, EXIT);
		break;

	case FS_ASSIGN:
		dst = ebpf_load(e, n->assign.lval);
		if (!dst)
			return -ENOSPC;

		ebpf_alu(e, dst->reg, n->assign.op, n->assign.expr);
		/* ebpf_reg_clean(e, n->assign.expr); */
		break;

	case FS_PROBE:
		if ((e->ip - 1)->code != EXIT.code) {
			ebpf_emit(e, MOV_IMM(BPF_REG_0, 0));
			ebpf_emit(e, EXIT);
		}
		break;
		
	default:
		break;
	}
	
	return 0;
}

static int _fs_annotate_pre(struct fs_node *n, void *_e)
{
	struct ebpf *e = _e;

	n->parent = e->parent;

	switch (n->type) {
	case FS_MAP:
	case FS_RETURN:
	case FS_ASSIGN:
	case FS_CALL:
		e->parent = n;
	default:
		break;
	}
	return 0;
}

static int _fs_annotate_post(struct fs_node *n, void *_e)
{
	struct ebpf *e = _e;
	int err = 0;

	e->parent = n->parent;

	switch (n->type) {
	case FS_STR:
		n->annot.type = FS_STR;
		n->annot.size = strlen(n->string);
		fprintf(stderr, "%s: parent:%s\n", n->string, fs_typestr(n->parent->type));
		/* n->annot.addr = ebpf_reserve(e, n->annot.size); */
		break;
	case FS_INT:
		n->annot.type = FS_INT;
		n->annot.size = sizeof(n->integer);
		break;
	case FS_NOT:
		n->annot.type = n->not->annot.type;
		n->annot.size = n->not->annot.size;
		break;
	case FS_MAP:
		err = symtable_transfer_map(e->st, n);
		if (err)
			return err;
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
	fs_walk(probe, _fs_annotate_pre, _fs_annotate_post, e);

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
