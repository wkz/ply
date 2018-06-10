#define _GNU_SOURCE 		/* asprintf */
#include <assert.h>
#include <errno.h>

#include <ply/ply.h>
#include <ply/internal.h>

#include "built-in.h"

static int struct_deref_rewrite(const struct func *func, struct node *n,
				 struct ply_probe *pb)
{
	struct node *new, *sou, *member;

	sou = n->expr.args;
	member = sou->next;
	
	/* sou->member => (*sou).member */
	new = node_expr(&n->loc, ".",
			node_expr(&n->loc, "u*", node_expr_ident(&sou->loc, sou->expr.func), NULL),
			node_string(&member->loc, member->string.data),
			NULL);

	/* TODO: n leaked */
	node_replace(n, new);
	return 0;
}

static int struct_deref_type_infer(const struct func *func, struct node *n)
{
	struct node *sou, *member;
	struct type *t;
	struct tfield *f;

	if (n->sym->type)
		return 0;

	sou = n->expr.args;
	member = sou->next;
	if (!sou->sym->type)
		return 0;

	t = type_base(sou->sym->type);

	if (t->ttype != T_POINTER) {
		_ne(n, "%N is not a pointer (type '%T').\n",
		    sou, sou->sym->type);
	}

	t = type_base(t->ptr.type);

	/* TODO: add union */
	if (t->ttype != T_STRUCT) {
		_ne(n, "%N is neither struct nor union (type '%T').\n",
		    sou, sou->sym->type);
		return -EINVAL;
	}

	f = tfields_get(t->sou.fields, member->string.data);
	if (!f) {
		_ne(n, "type '%T' has no member named %N.\n", t, member);
		return -EINVAL;
	}

	/* given `sou->member` where sou is a pointer to struct/union,
	 * infer that the expression's type is equal to the
	 * dereferenced member's type. */
	n->sym->type = f->type;
	return 0;
}

__ply_built_in const struct func struct_deref_func = {
	.name = "->",
	.type = &t_binop_func,
	.type_infer = struct_deref_type_infer,
	.rewrite = struct_deref_rewrite,
};


static int struct_dot_ir_pre(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *sou = n->expr.args;

	if (node_is(sou, "u*")) {
		/* (*ptr).member, if *ptr is not already loaded let it
		 * know that we're only interested in one member */
		sou->sym->irs.hint.dot = 1;

		/* this also means we need to put ourselves on the
		 * stack since data will be loaded via probe_read */
		n->sym->irs.hint.stack = 1;
	}
	return 0;
}

static int struct_dot_ir_post(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *sou, *member;
	struct irstate *dst;
	ssize_t offset;

	sou = n->expr.args;
	member = sou->next;
	dst = &n->sym->irs;
	
	ir_init_sym(pb->ir, n->sym);

	offset = type_offsetof(type_base(sou->sym->type), member->string.data);
	assert(offset >= 0);

	if (!sou->sym->irs.loc) {
		/* sou is a u* which wasn't loaded by child, just
		 * read the member we're interested in. */
		struct node *ptr = sou->expr.args;

		ir_emit_sym_to_reg(pb->ir, BPF_REG_3, ptr->sym);
		ir_emit_insn(pb->ir, ALU_IMM(BPF_ADD, offset), BPF_REG_3, 0);
		goto probe_read;
	}

	offset += sou->sym->irs.stack;

	if (dst->loc == LOC_REG) {
		ir_emit_insn(pb->ir, LDX(bpf_width(dst->size), offset),
			     dst->reg, BPF_REG_BP);
		return 0;
	}

	ir_emit_insn(pb->ir, ALU_IMM(BPF_ADD, offset), BPF_REG_3, 0);
probe_read:
	ir_emit_insn(pb->ir, MOV_IMM((int32_t)dst->size), BPF_REG_2, 0);
	ir_emit_insn(pb->ir, MOV, BPF_REG_1, BPF_REG_BP);
	ir_emit_insn(pb->ir, ALU_IMM(BPF_ADD, dst->stack), BPF_REG_1, 0);
	ir_emit_insn(pb->ir, CALL(BPF_FUNC_probe_read), 0, 0);
	/* TODO if (r0) exit(r0); */
	return 0;
}

static int struct_dot_type_infer(const struct func *func, struct node *n)
{
	struct node *sou, *member;
	struct type *t;
	struct tfield *f;

	if (n->sym->type)
		return 0;

	sou = n->expr.args;
	member = sou->next;
	if (!sou->sym->type)
		return 0;

	t = type_base(sou->sym->type);

	/* TODO: add union */
	if (t->ttype != T_STRUCT) {
		_ne(n, "%N is neither struct nor union (type '%T').\n",
		    sou, sou->sym->type);
		return -EINVAL;
	}

	f = tfields_get(t->sou.fields, member->string.data);
	if (!f) {
		_ne(n, "type '%T' has no member named %N.\n", t, member);
		return -EINVAL;
	}

	/* given `sou.member` where sou is a struct/union, infer that
	 * the expression's type is equal to member's type. */
	n->sym->type = f->type;
	return 0;
}

__ply_built_in const struct func struct_dot_func = {
	.name = ".",
	.type = &t_binop_func,
	.type_infer = struct_dot_type_infer,

	.ir_pre  = struct_dot_ir_pre,
	.ir_post = struct_dot_ir_post,
};


static int deref_ir_post(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *ptr = n->expr.args;
	struct irstate *dst;
	size_t size;

	dst = &n->sym->irs;
	if (dst->hint.dot)
		/* (*ptr).member, ptr points to a struct and our
		 * parent is only interested in one member. don't load
		 * the struct, let the dot operaton steal the address
		 * from our argument */
		return 0;

	ir_init_sym(pb->ir, n->sym);

	if (dst->hint.lval)
		/* *ptr = val, whatever is in our storage now it will
                    be overwritten, so skip the load. */
		return 0;

	ir_emit_sym_to_reg(pb->ir, BPF_REG_0, ptr->sym);
	ir_emit_read_to_sym(pb->ir, n->sym, BPF_REG_0);
	return 0;
}


static int deref_type_infer(const struct func *func, struct node *n)
{
	struct node *ptr = n->expr.args;
	struct type *t;

	if (n->sym->type || !ptr->sym->type)
		return 0;

	t = type_base(ptr->sym->type);
	if (t->ttype != T_POINTER) {
		_ne(n, "can't dereference %N (type '%T').\n",
		    ptr, ptr->sym->type);
		return -EINVAL;
	}

	/* given `*p` where p is a pointer, infer that the
	 * expression's type is equal to p's concrete type. */
	n->sym->type = t->ptr.type;
	return 0;
}

__ply_built_in const struct func deref_func = {
	.name = "u*",
	.type = &t_unary_func,
	.type_infer = deref_type_infer,

	.ir_post = deref_ir_post,
};



static int map_ir_update(struct node *n, struct ply_probe *pb)
{
	struct node *map = n->expr.args;

	ir_emit_ldmap(pb->ir, BPF_REG_1, map->sym);
	ir_emit_insn(pb->ir, MOV, BPF_REG_2, BPF_REG_BP);
	ir_emit_insn(pb->ir, ALU_IMM(BPF_ADD, map->sym->irs.stack), BPF_REG_2, 0);
	ir_emit_insn(pb->ir, MOV, BPF_REG_3, BPF_REG_BP);
	ir_emit_insn(pb->ir, ALU_IMM(BPF_ADD, n->sym->irs.stack), BPF_REG_3, 0);
	ir_emit_insn(pb->ir, MOV_IMM(0), BPF_REG_4, 0);
	ir_emit_insn(pb->ir, CALL(BPF_FUNC_map_update_elem), 0, 0);
	/* TODO: if (r0) exit(r0); */
	return 0;
}

static int map_ir_pre_key(struct node *n, struct ply_probe *pb)
{
	struct node *map = n->expr.args, *arg;
	struct type *ktype = type_base(map->sym->type->map.ktype);
	ssize_t stack = map->sym->irs.stack;
	size_t offset = 0, size = 0, pad;
	struct tfield *f;

	arg = map->next;
	tfields_foreach(f, ktype->sou.fields) {
		offset = type_offsetof(ktype, f->name);
		size = type_sizeof(f->type);

		if (!arg->sym->irs.loc) {
			arg->sym->irs.hint.stack = 1;
			arg->sym->irs.stack = stack + offset;
		}

		if (arg->next) {
			pad = type_offsetof(ktype, f[1].name) - (offset + size);
			if (pad)
				ir_emit_bzero(pb->ir,
					      stack + offset + size, pad);
		}
		arg = arg->next;
	}

	pad = type_sizeof(ktype) - (offset + size);
	if (pad)
		ir_emit_bzero(pb->ir, stack + offset + size, pad);
	return 0;
}

static int map_ir_pre(const struct func *func, struct node *n,
		      struct ply_probe *pb)
{
	struct irstate *kirs;
	struct node *map = n->expr.args;
	struct type *ktype = type_base(map->sym->type->map.ktype);

	map->sym->irs.hint.stack = 1;
	ir_init_irs(pb->ir, &map->sym->irs, ktype);


	if (ktype->ttype == T_STRUCT)
		return map_ir_pre_key(n, pb);

	kirs = &map->next->sym->irs;
	if (!kirs->loc) {
		kirs->hint.stack = 1;
		kirs->stack = map->sym->irs.stack;
	}
	return 0;
}

static int map_ir_post(const struct func *func, struct node *n,
		       struct ply_probe *pb)
{
	struct node *map = n->expr.args, *arg;
	struct type *ktype = type_base(map->sym->type->map.ktype);
	ssize_t stack = map->sym->irs.stack;
	size_t offset;
	struct tfield *f;
	int16_t lmiss, lhit;

	arg = map->next;

	if (ktype->ttype == T_STRUCT) {
		tfields_foreach(f, ktype->sou.fields) {
			offset = type_offsetof(ktype, f->name);
			ir_emit_sym_to_stack(pb->ir, stack + offset, arg->sym);
			arg = arg->next;
		}
	} else {
		ir_emit_sym_to_stack(pb->ir, stack, arg->sym);
		assert(!arg->next);
	}

	n->sym->irs.hint.stack = 1;
	ir_init_sym(pb->ir, n->sym);

	if (n->sym->irs.hint.lval)
		/* map[key] = val, whatever is in our storage now it
                    will be overwritten, so skip the load. */
		return 0;

	ir_emit_ldmap(pb->ir, BPF_REG_1, map->sym);
	ir_emit_insn(pb->ir, MOV, BPF_REG_2, BPF_REG_BP);
	ir_emit_insn(pb->ir, ALU_IMM(BPF_ADD, stack), BPF_REG_2, 0);
	ir_emit_insn(pb->ir, CALL(BPF_FUNC_map_lookup_elem), 0, 0);

	lmiss = ir_alloc_label(pb->ir);
	lhit  = ir_alloc_label(pb->ir);

	ir_emit_insn(pb->ir, JMP_IMM(BPF_JEQ, 0, lmiss), BPF_REG_0, 0);
	ir_emit_read_to_sym(pb->ir, n->sym, BPF_REG_0);
	ir_emit_insn(pb->ir, JMP_IMM(BPF_JA, 0, lhit), 0, 0);

	ir_emit_label(pb->ir, lmiss);
	ir_emit_bzero(pb->ir, n->sym->irs.stack, n->sym->irs.size);
	
	ir_emit_label(pb->ir, lhit);
	return 0;
}

static struct type *map_key_type(struct node *n)
{
	struct node *map, *key;
	struct type *ktype;
	struct tfield *kfields, *f;
	int i, nargs = node_nargs(n);
	char *kname;

	map = n->expr.args;

	if (nargs == 2)
		return map->next->sym->type;

	ktype = calloc(1, sizeof(*ktype));
	assert(ktype);

	kfields = calloc(nargs, sizeof(*kfields));
	assert(kfields);

	for (key = map->next, f = kfields, i = 0; key; key = key->next, f++, i++) {
		asprintf(&f->name, "k%d", i);
		f->type = key->sym->type;
	}

	asprintf(&ktype->sou.name, ":%s_key", map->expr.func);
	ktype->ttype = T_STRUCT;
	ktype->sou.fields = kfields;

	type_add(ktype);
	return ktype;
}

static int map_type_validate(struct node *n)
{
	/* TODO */
	return 0;
}

static int map_type_infer(const struct func *func, struct node *n)
{
	struct node *map, *key;
	struct type *ktype;

	map = n->expr.args;
	if (!map->sym)
		return 0;

	if (map->sym->type) {
		if (!n->sym->type)
			/* given `m[key]` where m's type is known,
			 * infer that the expression's type is equal
			 * to m's value type. */
			n->sym->type = map->sym->type->map.vtype;

		return map_type_validate(n);
	}

	if (!n->sym->type)
		return 0;

	for (key = map->next; key; key = key->next) {
		if (type_sizeof(key->sym->type) < 0)
			return 0;
	}

	map->sym->type = type_map_of(map_key_type(n), n->sym->type);
	return 0;
}

static int map_static_validate(const struct func *func, struct node *n)
{
	if (n->expr.args->ntype != N_EXPR || !n->expr.args->expr.ident) {
		_ne(n, "can't lookup a key in %N, which is not a map.\n", n);
		return -EINVAL;
	}

	return 0;
}

__ply_built_in const struct func map_func = {
	.name = "[]",
	.type_infer = map_type_infer,
	.static_validate = map_static_validate,

	.ir_pre  = map_ir_pre,
	.ir_post = map_ir_post,
};


static int assign_ir_pre(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *lval, *rval;

	lval = n->expr.args;
	rval = lval->next;

	n->sym->irs.hint.stack = 1;
	ir_init_irs(pb->ir, &n->sym->irs, lval->sym->type);

	lval->sym->irs.hint.lval = 1;
	lval->sym->irs.hint.stack = 1;
	lval->sym->irs.stack = n->sym->irs.stack;

	rval->sym->irs.hint.stack = 1;
	rval->sym->irs.stack = n->sym->irs.stack;
	return 0;
}

static int assign_ir_post(const struct func *func, struct node *n,
				 struct ply_probe *pb)
{
	struct node *lval, *rval;

	lval = n->expr.args;
	rval = lval->next;

	ir_emit_sym_to_sym(pb->ir, lval->sym, rval->sym);
	if (!node_is(lval, "[]"))
		return 0;

	return map_ir_update(lval, pb);
}

static int assign_type_infer(const struct func *func, struct node *n)
{
	struct node *lval, *rval;
	int err;

	if (n->sym->type)
		return 0;

	lval = n->expr.args;
	rval = lval->next;

	if (!rval->sym->type)
		return 0;

	if (!lval->sym->type) {
		/* given `a = b` where b's type is known but not a's,
		 * infer that a's type must be equal to b's */
		lval->sym->type = rval->sym->type;

		/* TODO do we need assignment expressions? */
		n->sym->type = &t_void;
		
		if (!node_is(lval, "[]"))
			return 0;

		err = map_type_infer(lval->sym->func, lval);
		if (err)
			return err;
	}

	if (type_compatible(lval->sym->type, rval->sym->type))
		return 0;

	_ne(n, "can't assign %N (type '%T'), to %N (type '%T').\n",
	    rval, rval->sym->type, lval, lval->sym->type);

	return -EINVAL;
}

static int assign_static_validate(const struct func *func, struct node *n)
{
	struct node *lval;

	lval = n->expr.args;

	if (node_is(lval, "[]"))
		return 0;

	_ne(n, "can't assign a value to %N.\n", lval);
	return -EINVAL;
}

__ply_built_in const struct func assign_func = {
	.name = "=",
	.type = &t_binop_func,
	.type_infer = assign_type_infer,
	.static_validate = assign_static_validate,

	.ir_pre  = assign_ir_pre,
	.ir_post = assign_ir_post,
};


static int agg_ir_post(const struct func *func, struct node *n,
			      struct ply_probe *pb)
{
	return map_ir_update(n->expr.args, pb);
}

__ply_built_in const struct func agg_func = {
	.name = "@=",
	.type = &t_binop_func,
	.type_infer = assign_type_infer,
	.static_validate = assign_static_validate,

	.ir_post = agg_ir_post,
};
