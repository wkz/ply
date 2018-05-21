#define _GNU_SOURCE 		/* asprintf */
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ply/ply.h>
#include <ply/internal.h>

/* -> */

static int global_sderef_rewrite(const struct func *func, struct node *n,
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

static int global_sderef_type_infer(const struct func *func, struct node *n)
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

/* . */

static int global_dot_ir_pre(const struct func *func, struct node *n,
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

static int global_dot_ir_post(const struct func *func, struct node *n,
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

static int global_dot_type_infer(const struct func *func, struct node *n)
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


/* u* */

static int global_deref_ir_post(const struct func *func, struct node *n,
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


static int global_deref_type_infer(const struct func *func, struct node *n)
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


/* :map */

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
	size_t offset, size, pad;
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

/* @= */
/*  = */

static int global_assign_ir_pre(const struct func *func, struct node *n,
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

static int global_assign_ir_post(const struct func *func, struct node *n,
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

static int global_assign_type_infer(const struct func *func, struct node *n)
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

static int global_assign_static_validate(const struct func *func, struct node *n)
{
	struct node *lval;

	lval = n->expr.args;

	if (node_is(lval, "[]"))
		return 0;

	_ne(n, "can't assign a value to %N.\n", lval);
	return -EINVAL;
}


/* :unary */

static int global_unary_ir_post(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *expr = n->expr.args;
	int arg, dst;
	
	ir_init_irs(pb->ir, &n->sym->irs, n->sym->type);
	dst = (n->sym->irs.loc == LOC_REG) ? n->sym->irs.reg : BPF_REG_0;

	if (expr->sym->irs.loc == LOC_REG) {
		arg = expr->sym->irs.reg;
	} else {
		arg = BPF_REG_1;
	}

	if (!strcmp(func->name, "u-")) {
		ir_emit_sym_to_reg(pb->ir, dst, expr->sym);

		if (type_sizeof(expr->sym->type) == 8)
			ir_emit_insn(pb->ir, ALU64_IMM(BPF_NEG, 0), dst, 0);
		else
			ir_emit_insn(pb->ir, ALU_IMM(BPF_NEG, 0), dst, 0);
	} else if (!strcmp(func->name, "u~")) {
		ir_emit_sym_to_reg(pb->ir, dst, expr->sym);
		if (type_sizeof(expr->sym->type) == 8)
			ir_emit_insn(pb->ir, ALU64_IMM(BPF_XOR, -1), dst, 0);
		else
			ir_emit_insn(pb->ir, ALU_IMM(BPF_XOR, -1), dst, 0);		
	} else if (!strcmp(func->name, "u!")) {
		ir_emit_insn(pb->ir, MOV_IMM(0), dst, 0);
		if (arg == BPF_REG_1)
			ir_emit_sym_to_reg(pb->ir, arg, expr->sym);
		ir_emit_insn(pb->ir, JMP_IMM(BPF_JNE, 0, 1), arg, 0);
		ir_emit_insn(pb->ir, MOV_IMM(1), dst, 0);		
	} else {
		assert(0);
	}

	if (dst == BPF_REG_0)
		ir_emit_reg_to_sym(pb->ir, n->sym, BPF_REG_0);
	return 0;
}

static int global_unary_type_infer(const struct func *func, struct node *n)
{
	struct node *expr = n->expr.args;

	if (type_base(expr->sym->type)->ttype != T_SCALAR) {
		_ne(expr, "argument of '%N' must be a scalar value, "
		    "but '%N' is of type '%T'\n", n, expr, expr->sym->type);
		return -EINVAL;
	}

	if (!strcmp(func->name, "u!"))
		n->sym->type = &t_int;
	else
		n->sym->type = type_scalar_convert(expr->sym->type, &t_int);

	return 0;
}

/* :relop */

static int global_relop_ir_post(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *lval, *rval;
	struct bpf_insn jmp;
	struct type *t;
	int32_t *imm = NULL;
	int dst, lreg, rreg;
	int unsignd;

	/* basic operation:
	 * mov   r0, #0
	 * j<OP> rl, rr, +1
	 * mov   r0, #1
	 */
	
	ir_init_irs(pb->ir, &n->sym->irs, n->sym->type);
	dst = (n->sym->irs.loc == LOC_REG) ? n->sym->irs.reg : BPF_REG_0;
	ir_emit_insn(pb->ir, MOV_IMM(1), dst, 0);

	lval = n->expr.args;
	rval = lval->next;
	t = type_scalar_convert(lval->sym->type, rval->sym->type);
	unsignd = type_base(t)->scalar.unsignd;
	
	/* TODO: flip lval/rval for commutative operations if lval is
	 * an immediate and rval is not. */

	if (lval->sym->irs.loc == LOC_REG) {
		lreg = lval->sym->irs.reg;
	} else {
		lreg = BPF_REG_1;
		ir_emit_sym_to_reg(pb->ir, lreg, lval->sym);
	}

	switch (rval->sym->irs.loc) {
	case LOC_IMM:
		imm = &rval->sym->irs.imm;
		break;
	case LOC_REG:
		rreg = rval->sym->irs.reg;
		break;
	default:
		rreg = BPF_REG_2;
		ir_emit_sym_to_reg(pb->ir, rreg, rval->sym);
		break;
	}

	jmp = imm ? JMP_IMM(0, *imm, 1) : JMP(0, 1);

	if (!strcmp(func->name, "=="))
		jmp.code |= BPF_OP(BPF_JEQ);
	else if (!strcmp(func->name, "!="))
		jmp.code |= BPF_OP(BPF_JNE);
	else if (!strcmp(func->name, "<"))
		jmp.code |= BPF_OP(unsignd ? BPF_JLT : BPF_JSLT);
	else if (!strcmp(func->name, ">"))
		jmp.code |= BPF_OP(unsignd ? BPF_JGT : BPF_JSGT);
	else if (!strcmp(func->name, "<="))
		jmp.code |= BPF_OP(unsignd ? BPF_JLE : BPF_JSLE);
	else if (!strcmp(func->name, ">="))
		jmp.code |= BPF_OP(unsignd ? BPF_JGE : BPF_JSGE);
	else
		assert(0);

	ir_emit_insn(pb->ir, jmp, lreg, imm ? 0 : rreg);
	ir_emit_insn(pb->ir, MOV_IMM(0), dst, 0);

	if (dst == BPF_REG_0)
		ir_emit_reg_to_sym(pb->ir, n->sym, BPF_REG_0);
	return 0;
}

static int global_relop_type_infer(const struct func *func, struct node *n)
{
	struct node *lval, *rval;
	struct type *ltype, *rtype;

	if (n->sym->type)
		return 0;

	lval = n->expr.args;
	rval = lval->next;

	ltype = lval->sym->type;
	rtype = rval->sym->type;
	if (!ltype || !rtype)
		return 0;

	if (type_base(ltype)->ttype != T_SCALAR) {
		_ne(n, "left side of '%N' must be a scalar value, "
		    "but '%N' is of type '%T'\n", n, lval, ltype);
		return -EINVAL;
	}

	if (type_base(rtype)->ttype != T_SCALAR) {
		_ne(n, "right side of '%N' must be a scalar value, "
		    "but '%N' is of type '%T'\n", n, rval, rtype);
		return -EINVAL;
	}

	n->sym->type = &t_int;
	return 0;
}

/* :binop */

static int global_binop_ir_post(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *lval, *rval;
	struct bpf_insn op;
	int32_t *imm = NULL;
	int dst, src;

	ir_init_irs(pb->ir, &n->sym->irs, n->sym->type);
	dst = (n->sym->irs.loc == LOC_REG) ? n->sym->irs.reg : BPF_REG_0;
	
	lval = n->expr.args;
	rval = lval->next;

	/* TODO: flip lval/rval for commutative operations if lval is
	 * an immediate and rval is not. */

	switch (rval->sym->irs.loc) {
	case LOC_IMM:
		imm = &rval->sym->irs.imm;
		break;
	case LOC_REG:
		src = rval->sym->irs.reg;
		break;
	default:
		src = BPF_REG_1;
		break;
	}

	ir_emit_sym_to_reg(pb->ir, dst, lval->sym);

	if (!imm)
		ir_emit_sym_to_reg(pb->ir, src, rval->sym);

	if (type_sizeof(n->sym->type) == 8)
		op = imm ? ALU64_IMM(0, *imm) : ALU64(0);
	else
		op = imm ? ALU32_IMM(0, *imm) : ALU32(0);

	if (!strcmp(func->name, "|"))
		op.code |= BPF_OP(BPF_OR);
	else if (!strcmp(func->name, "^"))
		op.code |= BPF_OP(BPF_XOR);
	else if (!strcmp(func->name, "&"))
		op.code |= BPF_OP(BPF_AND);
	else if (!strcmp(func->name, "<<"))
		op.code |= BPF_OP(BPF_LSH);
	else if (!strcmp(func->name, ">>"))
		op.code |= BPF_OP(BPF_RSH);
	else if (!strcmp(func->name, "+"))
		op.code |= BPF_OP(BPF_ADD);
	else if (!strcmp(func->name, "-"))
		op.code |= BPF_OP(BPF_SUB);
	else if (!strcmp(func->name, "*"))
		op.code |= BPF_OP(BPF_MUL);
	else if (!strcmp(func->name, "/"))
		op.code |= BPF_OP(BPF_DIV);
	else if (!strcmp(func->name, "%"))
		op.code |= BPF_OP(BPF_MOD);
	else
		assert(0);

	ir_emit_insn(pb->ir, op, dst, imm ? 0 : src);

	if (dst == BPF_REG_0)
		ir_emit_reg_to_sym(pb->ir, n->sym, BPF_REG_0);
	return 0;
}

static int global_binop_type_infer(const struct func *func, struct node *n)
{
	struct node *lval, *rval;
	struct type *ltype, *rtype;

	if (n->sym->type)
		return 0;

	lval = n->expr.args;
	rval = lval->next;

	ltype = lval->sym->type;
	rtype = rval->sym->type;
	if (!ltype || !rtype)
		return 0;

	if (type_base(ltype)->ttype != T_SCALAR) {
		_ne(n, "left side of '%N' must be a scalar value, "
		    "but '%N' is of type '%T'\n", n, lval, ltype);
		return -EINVAL;
	}

	if (type_base(rtype)->ttype != T_SCALAR) {
		_ne(n, "right side of '%N' must be a scalar value, "
		    "but '%N' is of type '%T'\n", n, rval, rtype);
		return -EINVAL;
	}

	n->sym->type = type_scalar_convert(ltype, rtype);
	return 0;
}


/* :if */

struct if_priv {
	int16_t miss_label;
	int16_t end_label;
};

static int global_iftest_ir_post(const struct func *func, struct node *n,
				 struct ply_probe *pb)
{
	struct node *expr, *estmt, *ifn = n->up;
	struct if_priv *ifp = ifn->sym->priv;
	int reg;

	expr = n->prev;
	estmt = n->next->next->next;

	if (expr->sym->irs.loc == LOC_REG) {
		reg = expr->sym->irs.reg;
	} else {
		reg = BPF_REG_0;
		ir_emit_sym_to_reg(pb->ir, reg, expr->sym);
	}

	ifp->miss_label = ir_alloc_label(pb->ir);
	if (estmt)
		ifp->end_label = ir_alloc_label(pb->ir);

	ir_emit_insn(pb->ir, JMP_IMM(BPF_JEQ, 0, ifp->miss_label), reg, 0);
	return 0;
}

static int global_ifjump_ir_post(const struct func *func, struct node *n,
				 struct ply_probe *pb)
{
	struct node *ifn = n->up;
	struct if_priv *ifp = ifn->sym->priv;

	if (ifp->end_label)
		ir_emit_insn(pb->ir, JMP_IMM(BPF_JA, 0, ifp->end_label), 0, 0);

	ir_emit_label(pb->ir, ifp->miss_label);
	return 0;
}

static int global_if_ir_post(const struct func *func, struct node *n,
			     struct ply_probe *pb)
{
	struct if_priv *ifp = n->sym->priv;

	if (ifp->end_label)
		ir_emit_label(pb->ir, ifp->end_label);
	return 0;
}

static int global_if_rewrite(const struct func *func, struct node *n,
			     struct ply_probe *pb)
{
	struct node *expr, *stmt;

	expr = n->expr.args;
	stmt = expr->next;

	node_insert(expr, node_expr(&n->loc, ":iftest", NULL));	
	node_insert(stmt, node_expr(&n->loc, ":ifjump", NULL));
	return 0;
}

static int global_if_type_infer(const struct func *func, struct node *n)
{
	struct node *expr = n->expr.args;

	if (type_base(expr->sym->type)->ttype != T_SCALAR) {
		_ne(expr, "condition of '%N' must be a scalar value, "
		    "but '%N' is of type '%T'\n", n, expr, expr->sym->type);
		return -EINVAL;
	}

	/* TODO: leaked */
	n->sym->priv = calloc(1, sizeof(struct if_priv));
	assert(n->sym->priv);

	n->sym->type = &t_void;
	return 0;
}


/* count() */

static int count_ir_post(const struct func *func, struct node *n,
			 struct ply_probe *pb)
{
	struct node *mapop = n->up->expr.args;

	ir_emit_sym_to_reg(pb->ir, BPF_REG_0, mapop->sym);
	ir_emit_insn(pb->ir, ALU_IMM(BPF_ADD, 1), BPF_REG_0, 0);
	ir_emit_reg_to_sym(pb->ir, mapop->sym, BPF_REG_0);

	return map_ir_update(mapop, pb);
}

struct type t_count_func = {
	.ttype = T_FUNC,

	.func = { .type = &t_ulong },
};

/* quantize */

static uint64_t __quantize_total(struct type *t, const unsigned int *bucket)
{
	uint64_t total;
	int i, len = type_base(t)->array.len;

	for (i = 0, total = 0; i < len; i++)
		total += bucket[i];

	return total;
}

static void __quantize_fprint_hist_unicode(FILE *fp, unsigned int count,
					   uint64_t total)
{
	static const char bar_open[] = { 0xe2, 0x94, 0xa4 };
	static const char bar_close[] = { 0xe2, 0x94, 0x82 };

	int w = (((float)count / (float)total) * 256.0) + 0.5;
	int space = 32 - ((w +  7) >> 3);
	char block[] = { 0xe2, 0x96, 0x88 };

	fwrite(bar_open, sizeof(bar_open), 1, fp);

	for (; w > 8; w -= 8)
		fwrite(block, sizeof(block), 1, fp);

	if (w) {
		block[2] += 8 - w;
		fwrite(block, sizeof(block), 1, fp);
	}

	fprintf(fp, "%*s", space, "");
	fwrite(bar_close, sizeof(bar_close), 1, fp);
}

static void __quantize_fprint_hist_ascii(FILE *fp, unsigned int count,
					 uint64_t total)
{
	int w = (((float)count / (float)total) * 32.0) + 0.5;
	int i;

	fputc('|', fp);

	for (i = 0; i < 32; i++, w--)
		fputc((w > 0) ? '#' : ' ', fp);

	fputc('|', fp);
}

static int __quantize_fprint_value(FILE *fp, unsigned int count, uint64_t total)
{
	fprintf(fp, "\t%8u ", count);

	if (ply_config.unicode)
		__quantize_fprint_hist_unicode(fp, count, total);
	else
		__quantize_fprint_hist_ascii(fp, count, total);
	fputc('\n', fp);
	return 0;
}

static int __quantize_normalize(int log2, char const **suffix)
{
	static const char *s[] = { NULL, "k", "M", "G", "T", "P", "Z" };
	int i;

	for (i = 0; log2 >= 10; i++, log2 -= 10);

	*suffix = s[i];
	return (1 << log2);
}

static int __quantize_fprint_bucket(struct type *t, FILE *fp, int i)
{
	struct type *arg_type = t->tdef.priv;
	const char *ls, *hs;
	int lo, hi;

	if ((arg_type->ttype == T_TYPEDEF) && arg_type->tdef.fprint_log2)
		return arg_type->tdef.fprint_log2(arg_type, fp, i);

	lo = __quantize_normalize(i    , &ls);
	hi = __quantize_normalize(i + 1, &hs);

	/* closed interval for values < 1k, else open ended */
	if (!hs)
		fprintf(fp, "\t[%4d, %4d]", lo, hi - 1);
	else
		fprintf(fp, "\t[%*d%s, %*d%s)",
			ls ? 3 : 4, lo, ls ? : "",
			hs ? 3 : 4, hi, hs ? : "");

	return 0;
}

static int global_quantize_fprint(struct type *t, FILE *fp, const void *data)
{
	const unsigned int *bucket = data;
	struct type *arg_type = t->tdef.priv;
	uint64_t total = __quantize_total(t, bucket);
	int gap, i, len;

	fputc('\n', fp);

	len = type_base(t)->array.len;

	/* signed argument => last bucket holds count of negative
	 * values and should thus be listed first. */
	if (!type_base(arg_type)->scalar.unsignd) {
		len--;

		if (bucket[len]) {
			fputs("\t         < 0", fp);
			__quantize_fprint_value(fp, bucket[len], total);
			if (!bucket[0])
				fputs("\t...\n", fp);
		}
	}

	for (i = 0, gap = 0; i < len; i++) {
		if (bucket[i]) {
			if (gap) {
				if (gap != i)
					fputs("\t...\n", fp);
				gap = 0;
			}

			__quantize_fprint_bucket(t, fp, i);
			__quantize_fprint_value(fp, bucket[i], total);
		} else {
			gap++;
		}
	}

	return 0;
}

static int global_quantize_ir_post(const struct func *func, struct node *n,
				   struct ply_probe *pb)
{
	struct node *mapop = n->up->expr.args;
	struct node *arg = n->expr.args;
	struct type *atype = type_base(n->sym->type)->array.type;
	size_t bucketsz = type_sizeof(atype);
	int i;

	/* r0: bucket number
	   r1: arg
	   r2: arg copy, for 64-bit log2 operation
	 */
	ir_emit_insn(pb->ir, MOV_IMM(0), BPF_REG_0, 0);

	ir_emit_sym_to_reg(pb->ir, BPF_REG_1, arg->sym);
	if (type_sizeof(type_return(arg->sym->type)) > 4) {
		ir_emit_insn(pb->ir, MOV64, BPF_REG_2, BPF_REG_1);
		ir_emit_insn(pb->ir, ALU64_IMM(BPF_RSH, 32), BPF_REG_2, 0);
		ir_emit_insn(pb->ir, JMP_IMM(BPF_JEQ, 0, 2), BPF_REG_2, 0);
		ir_emit_insn(pb->ir, ALU_IMM(BPF_ADD, 32), BPF_REG_0, 0);
		ir_emit_insn(pb->ir, MOV64, BPF_REG_1, BPF_REG_2);
	}

	for (i = 16; i; i >>= 1) {
		ir_emit_insn(pb->ir, JMP_IMM(BPF_JLE, ((1 << i) - 1), 2), BPF_REG_1, 0);
		ir_emit_insn(pb->ir, ALU_IMM(BPF_ADD, i), BPF_REG_0, 0);
		ir_emit_insn(pb->ir, ALU64_IMM(BPF_RSH, i), BPF_REG_1, 0);
	}

	/* bucket in r0, convert it to an offset in the array */
	switch (bucketsz) {
	case 8:
		ir_emit_insn(pb->ir, ALU_IMM(BPF_LSH, 3), BPF_REG_0, 0);
		break;
	case 4:
		ir_emit_insn(pb->ir, ALU_IMM(BPF_LSH, 2), BPF_REG_0, 0);
		break;
	default:
		assert(0);
	}

	ir_emit_insn(pb->ir, MOV, BPF_REG_1, BPF_REG_BP);
	ir_emit_insn(pb->ir, ALU_IMM(BPF_ADD, mapop->sym->irs.stack), BPF_REG_1, 0);
	ir_emit_insn(pb->ir, ALU(BPF_ADD), BPF_REG_1, BPF_REG_0);

	ir_emit_insn(pb->ir, MOV_IMM(1), BPF_REG_0, 0);
	ir_emit_insn(pb->ir, ST_XADD(bpf_width(bucketsz), 0), BPF_REG_1, BPF_REG_0);
	return map_ir_update(mapop, pb);
}

static int global_quantize_type_infer(const struct func *func, struct node *n)
{
	struct node *arg;
	struct type *t, *array;
	char *type_name;

	arg = n->expr.args;

	if (n->sym->type || !arg->sym->type)
		return 0;

	t = type_base(arg->sym->type);
	if (t->ttype != T_SCALAR) {
		_ne(n, "can't quantize non-scalar value %N (type '%T').\n",
		    arg, arg->sym->type);
		return -EINVAL;	
	}

	array = type_array_of(&t_uint, type_sizeof(t) * 8);

	asprintf(&type_name, "quantize_%s_t", n->sym->name);
	n->sym->type = type_typedef(array, type_name);
	free(type_name);

	/* having access to the argument type lets us do (at least)
	 * two things: (1) know whether the argument was signed or not
	 * and thus, by extension, know how to interpret the top-most
	 * bucket. (2) allow range output to be customized,
	 * e.g. [256ms - 512ms] instead of [256G - 512G] and then
	 * having to figure out what a giga-nanosecond is. */
	n->sym->type->tdef.priv = arg->sym->type;
	n->sym->type->tdef.fprint = global_quantize_fprint;
	return 0;
}


/* pid/kpid */

static int global_pid_fprint(struct type *t, FILE *fp, const void *data)
{
	return fprintf(fp, "%5"PRIu32, *((uint32_t *)data)); 
}

static int global_pid_ir_post(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *ptr = n->expr.args;

	ir_init_sym(pb->ir, n->sym);

	ir_emit_insn(pb->ir, CALL(BPF_FUNC_get_current_pid_tgid), 0, 0);
	ir_emit_insn(pb->ir, ALU64_IMM(BPF_RSH, 32), BPF_REG_0, 0);
	ir_emit_reg_to_sym(pb->ir, n->sym, BPF_REG_0);
	return 0;
}

static int global_kpid_ir_post(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *ptr = n->expr.args;

	ir_init_sym(pb->ir, n->sym);

	ir_emit_insn(pb->ir, CALL(BPF_FUNC_get_current_pid_tgid), 0, 0);
	ir_emit_insn(pb->ir, ALU64_IMM(BPF_AND, 0xffffffff), BPF_REG_0, 0);
	ir_emit_reg_to_sym(pb->ir, n->sym, BPF_REG_0);
	return 0;
}

struct type t_pid = {
	.ttype = T_TYPEDEF,

	.tdef = {
		.name = ":pid",
		.type = &t_u32,
		.fprint = global_pid_fprint,
	},
};

struct type t_pid_func = {
	.ttype = T_FUNC,

	.func = { .type = &t_pid },
};

/* uid/gid */

static int global_uid_fprint(struct type *t, FILE *fp, const void *data)
{
	return fprintf(fp, "%4"PRIu32, *((uint32_t *)data)); 
}

static int global_uid_ir_post(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *ptr = n->expr.args;

	ir_init_sym(pb->ir, n->sym);

	ir_emit_insn(pb->ir, CALL(BPF_FUNC_get_current_uid_gid), 0, 0);
	ir_emit_insn(pb->ir, ALU64_IMM(BPF_AND, 0xffffffff), BPF_REG_0, 0);
	ir_emit_reg_to_sym(pb->ir, n->sym, BPF_REG_0);
	return 0;
}

static int global_gid_ir_post(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *ptr = n->expr.args;

	ir_init_sym(pb->ir, n->sym);

	ir_emit_insn(pb->ir, CALL(BPF_FUNC_get_current_uid_gid), 0, 0);
	ir_emit_insn(pb->ir, ALU64_IMM(BPF_RSH, 32), BPF_REG_0, 0);
	ir_emit_reg_to_sym(pb->ir, n->sym, BPF_REG_0);
	return 0;
}

struct type t_uid = {
	.ttype = T_TYPEDEF,

	.tdef = {
		.name = ":uid",
		.type = &t_u32,
		.fprint = global_uid_fprint,
	},
};

struct type t_uid_func = {
	.ttype = T_FUNC,

	.func = { .type = &t_uid },
};


/* cpu */

static int global_cpu_fprint(struct type *t, FILE *fp, const void *data)
{
	return fprintf(fp, "%2"PRIu32, *((uint32_t *)data)); 
}

static int global_cpu_ir_post(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *ptr = n->expr.args;

	ir_init_sym(pb->ir, n->sym);

	ir_emit_insn(pb->ir, CALL(BPF_FUNC_get_smp_processor_id), 0, 0);
	ir_emit_reg_to_sym(pb->ir, n->sym, BPF_REG_0);
	return 0;
}

struct type t_cpu = {
	.ttype = T_TYPEDEF,

	.tdef = {
		.name = ":cpu",
		.type = &t_u32,
		.fprint = global_cpu_fprint,
	},
};

struct type t_cpu_func = {
	.ttype = T_FUNC,

	.func = { .type = &t_cpu },
};


/* comm/execname */

static int global_comm_ir_post(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *ptr = n->expr.args;

	ir_init_sym(pb->ir, n->sym);

	ir_emit_bzero(pb->ir, n->sym->irs.stack, type_sizeof(n->sym->type));

	ir_emit_insn(pb->ir, MOV, BPF_REG_1, BPF_REG_BP);
	ir_emit_insn(pb->ir, ALU_IMM(BPF_ADD, n->sym->irs.stack), BPF_REG_1, 0);
	ir_emit_insn(pb->ir, MOV_IMM(type_sizeof(n->sym->type)), BPF_REG_2, 0);
	ir_emit_insn(pb->ir, CALL(BPF_FUNC_get_current_comm), 0, 0);
	return 0;
}

struct type t_comm = {
	.ttype = T_ARRAY,

	.array = {
		.type = &t_char,
		.len = 16,
	},
};

struct type t_comm_func = {
	.ttype = T_FUNC,

	.func = { .type = &t_comm },
};


/* time */

static int global_time_ir_post(const struct func *func, struct node *n,
			       struct ply_probe *pb)
{
	struct node *ptr = n->expr.args;

	ir_init_sym(pb->ir, n->sym);

	ir_emit_insn(pb->ir, CALL(BPF_FUNC_ktime_get_ns), 0, 0);
	ir_emit_reg_to_sym(pb->ir, n->sym, BPF_REG_0);
	return 0;
}

/* TODO: pretty time formats */
/* static int global_time_fprint(struct type *t, FILE *fp, const void *data) */
/* { */
/* 	return 0; */
/* } */

struct type t_time = {
	.ttype = T_TYPEDEF,

	.tdef = {
		.name = ":time",
		.type = &t_s64,

		/* .fprint = global_time_fprint, */
	},
};

struct type t_time_func = {
	.ttype = T_FUNC,

	.func = { .type = &t_time },
};


/*  */

struct type t_block_func = {
	.ttype = T_FUNC,

	.func = { .type = &t_void, .vargs = 1 },
};

struct type t_string_array = {
	.ttype = T_ARRAY,

	.array = { .type = &t_char, .len = 64 }, /* TODO: tunable */
};

struct type t_string = {
	.ttype = T_TYPEDEF,

	.tdef = { .name = ":string", .type = &t_string_array },
};

struct tfield f_2args[] = {
	{ .type = &t_void },
	{ .type = &t_void },

	{ .type = NULL }
};

struct type t_2args_func = {
	.ttype = T_FUNC,

	.func = { .type = &t_void, .args = f_2args },
};

struct tfield f_1arg[] = {
	{ .type = &t_void },

	{ .type = NULL }
};

struct type t_1arg_func = {
	.ttype = T_FUNC,

	.func = { .type = &t_void, .args = f_1arg },
};

#define UNARY(_name)						\
	{							\
		.name = _name,					\
		.type = &t_1arg_func,				\
		.type_infer = global_unary_type_infer,		\
		.ir_post = global_unary_ir_post,		\
	}

#define BINOP(_name)						\
	{							\
		.name = _name,					\
		.type = &t_2args_func,				\
		.type_infer = global_binop_type_infer,		\
		.ir_post = global_binop_ir_post,		\
	}

#define RELOP(_name)						\
	{							\
		.name = _name,					\
		.type = &t_2args_func,				\
		.type_infer = global_relop_type_infer,		\
		.ir_post = global_relop_ir_post,		\
	}

static const struct func global_funcs[] = {
	UNARY("u-"),
	UNARY("u~"),
	UNARY("u!"),

	BINOP( "|"),
	BINOP( "^"),
	BINOP( "&"),
	BINOP("<<"),
	BINOP(">>"),
	BINOP( "+"),
	BINOP( "-"),
	BINOP( "*"),
	BINOP( "/"),
	BINOP( "%"),

	RELOP("=="),
	RELOP("!="),
	RELOP( "<"),
	RELOP( ">"),
	RELOP("<="),
	RELOP(">="),
	
	{
		.name = "if",
		.type = &t_block_func,
		.static_ret = 1,
		.type_infer = global_if_type_infer,
		.rewrite = global_if_rewrite,

		.ir_post = global_if_ir_post,
	},
	{
		.name = ":iftest",
		.type = &t_void,
		.static_ret = 1,

		.ir_post = global_iftest_ir_post,
	},
	{
		.name = ":ifjump",
		.type = &t_void,
		.static_ret = 1,

		.ir_post = global_ifjump_ir_post,
	},

	{
		.name = "{}",
		.type = &t_block_func,
		.static_ret = 1,
	},

	{
		.name = "->",
		.type = &t_2args_func,
		.type_infer = global_sderef_type_infer,
		.rewrite = global_sderef_rewrite,
	},
	{
		.name = ".",
		.type = &t_2args_func,
		.type_infer = global_dot_type_infer,

		.ir_pre  = global_dot_ir_pre,
		.ir_post = global_dot_ir_post,
	},
	{
		.name = "u*",
		.type = &t_1arg_func,
		.type_infer = global_deref_type_infer,

		.ir_post = global_deref_ir_post,
	},
	
	{
		.name = "=",
		.type = &t_2args_func,
		.type_infer = global_assign_type_infer,
		.static_validate = global_assign_static_validate,

		.ir_pre  = global_assign_ir_pre,
		.ir_post = global_assign_ir_post,
	},
	{
		.name = "@=",
		.type = &t_2args_func,
		.type_infer = global_assign_type_infer,
		.static_validate = global_assign_static_validate,
	},
	{
		.name = "[]",
		.type_infer = map_type_infer,
		.static_validate = map_static_validate,

		.ir_pre  = map_ir_pre,
		.ir_post = map_ir_post,
	},

	{
		.name = "count",
		.type = &t_count_func,
		.static_ret = 1,

		.ir_post = count_ir_post,
	},
	{
		.name = "quantize",
		.type = &t_1arg_func,
		.type_infer = global_quantize_type_infer,

		.ir_post = global_quantize_ir_post,
	},

	{
		.name = "pid",
		.type = &t_pid_func,
		.static_ret = 1,

		.ir_post = global_pid_ir_post,
	},
	{
		.name = "kpid",
		.type = &t_pid_func,
		.static_ret = 1,

		.ir_post = global_kpid_ir_post,
	},
	{
		.name = "uid",
		.type = &t_uid_func,
		.static_ret = 1,

		.ir_post = global_uid_ir_post,
	},
	{
		.name = "gid",
		.type = &t_uid_func,
		.static_ret = 1,

		.ir_post = global_gid_ir_post,
	},
	{
		.name = "cpu",
		.type = &t_cpu_func,
		.static_ret = 1,

		.ir_post = global_cpu_ir_post,
	},
	{
		.name = "comm",
		.type = &t_comm_func,
		.static_ret = 1,

		.ir_post = global_comm_ir_post,
	},
	{
		/* alias to comm */
		.name = "execname",
		.type = &t_comm_func,
		.static_ret = 1,

		.ir_post = global_comm_ir_post,
	},
	{
		.name = "time",
		.type = &t_time_func,
		.static_ret = 1,

		.ir_post = global_time_ir_post,
	},
	
	{ .name = NULL }
};

static struct type *global_num_type(struct node *n)
{
	if (n->num.unsignd) {
		if (n->num.u64 <= INT_MAX)
			return &t_int;
		else if (n->num.u64 <= UINT_MAX)
			return &t_uint;
		else if (n->num.u64 <= LONG_MAX)
			return &t_long;
		else if (n->num.u64 <= ULONG_MAX)
			return &t_ulong;
		else if (n->num.u64 <= LLONG_MAX)
			return &t_llong;
		else if (n->num.u64 <= ULLONG_MAX)
			return &t_ullong;
	} else {
		if (n->num.s64 >= INT_MIN && n->num.s64 <= INT_MAX)
			return &t_int;
		else if (n->num.s64 >= LONG_MIN && n->num.s64 <= LONG_MAX)
			return &t_long;
		else if (n->num.s64 >= LLONG_MIN && n->num.s64 <= LLONG_MAX)
			return &t_llong;
	}

	assert(0);
	return NULL;
}

static int global_num_ir_post(const struct func *func, struct node *n,
			      struct ply_probe *pb)
{
	struct irstate *irs = &n->sym->irs;

	if ((n->num.unsignd && (n->num.u64 <= INT32_MAX)) ||
	    (n->num.s64 >= INT32_MIN && n->num.s64 <= INT32_MAX)) {
		irs->loc = LOC_IMM;
		irs->imm = n->num.s64;
		irs->size = 4;
		return 0;
	}

	/* we need to load the constant to a register, so ignore any
	 * advise about stack allocation. */
	irs->hint.stack = 0;

	ir_init_sym(pb->ir, n->sym);

	/* use special instruction pair to load 64-bit immediate to
	 * register. second instruction is a dummy except for the
	 * upper 32 bits of the immediate. */
	ir_emit_insn(pb->ir, LDDW_IMM((uint32_t)n->num.u64), irs->reg, 0);
	ir_emit_insn(pb->ir, INSN(0, 0, 0, 0, n->num.u64 >> 32), 0, 0);
	return 0;
}

static const struct func global_num_func = {
	.name = ":num",

	.ir_post = global_num_ir_post,	
};

static int global_string_ir_post(const struct func *func, struct node *n,
				 struct ply_probe *pb)
{
	struct irstate *irs = &n->sym->irs;

	if (node_is(n->up, "."))
		return 0;

	ir_init_sym(pb->ir, n->sym);

	ir_emit_data(pb->ir, irs->stack, n->string.data,
		     type_sizeof(n->sym->type));
	return 0;
}

static struct type *global_string_type(struct node *n)
{
	size_t len = ((strlen(n->string.data) ? : 1) + 7) & ~7;

	return type_array_of(&t_char, len);
}

static const struct func global_string_func = {
	.name = ":string",

	.ir_post = global_string_ir_post,	
};

static const struct func global_ident_func = {
	.name = ":ident",
};

static const struct func *global_func_get(struct node *n)
{
	const struct func *func;
	int err;

	for (func = global_funcs; func->name; func++) {
		if (strcmp(func->name, n->expr.func))
			continue;

		return func;
	}

	return NULL;
}

int global_sym_alloc(struct ply_probe *pb, struct node *n)
{
	const struct func *func;
	int err;

	switch (n->ntype) {
	case N_EXPR:
		func = global_func_get(n);
		if (func)
			break;

		if (!n->expr.args) {
			n->expr.ident = 1;
			func = &global_ident_func;
		}
		break;
	case N_NUM:
		func = &global_num_func;
		break;
	case N_STRING:
		func = &global_string_func;
		break;
	}

	if (!func)
		return -ENOENT;

	err = func_static_validate(func, n);
	if (err)
		return err;

	n->sym = sym_alloc(&pb->ply->globals, n, func);

	/* infer statically known types early */
	if (n->ntype == N_NUM)
		n->sym->type = global_num_type(n);
	else if (n->ntype == N_STRING)
		n->sym->type = global_string_type(n);
	else if (func->static_ret)
		n->sym->type = func_return_type(func);
	return 0;
}

int global_probe(struct ply_probe *pb)
{
	return 0;
}

struct provider global = {
	.name = "!",

	.sym_alloc = global_sym_alloc,
	.probe = global_probe,
};

__attribute__((constructor))
static void global_init(void)
{
	provider_register(&global);
}
