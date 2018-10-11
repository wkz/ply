/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <assert.h>
#include <errno.h>
#include <string.h>

#include <ply/ply.h>
#include <ply/internal.h>

#include "built-in.h"


static int unary_ir_post(const struct func *func, struct node *n,
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

static int unary_type_infer(const struct func *func, struct node *n)
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

#define UNARY(_fn, _name)				\
	__ply_built_in const struct func math_ ## _fn =	\
	{						\
		.name = _name,				\
		.type = &t_unary_func,			\
		.type_infer = unary_type_infer,		\
		.ir_post = unary_ir_post,		\
	}

UNARY(uminus, "u-");
UNARY(bwnot,  "u~");
UNARY(lognot, "u!");

static int logop_ir_post(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *lval, *rval;
	struct bpf_insn jmp;
	struct type *t;
	int16_t out;
	int dst = 0, lreg = 0, rreg = 0;
	int start;

	lval = n->expr.args;
	rval = lval->next;

	/* basic operation:
	 * mov      r0, #<0, 1>
	 * b<eq,ne> rl, #0, end
	 * b<eq,ne> rr, #0, end
	 * mov      r0, #<1, 0>
	 * end:
	 */
	out = ir_alloc_label(pb->ir);
	if (!strcmp(func->name, "&&")) {
		start = 0;
		jmp = JMP_IMM(BPF_JEQ, 0, out);
	} else if (!strcmp(func->name, "||")) {
		start = 1;
		jmp = JMP_IMM(BPF_JNE, 0, out);
	} else
		assert(0);

	ir_init_irs(pb->ir, &n->sym->irs, n->sym->type);
	dst = (n->sym->irs.loc == LOC_REG) ? n->sym->irs.reg : BPF_REG_0;

	ir_emit_insn(pb->ir, MOV_IMM(start), dst, 0);

	if (lval->sym->irs.loc == LOC_REG) {
		lreg = lval->sym->irs.reg;
	} else {
		lreg = BPF_REG_1;
		ir_emit_sym_to_reg(pb->ir, lreg, lval->sym);
	}

	ir_emit_insn(pb->ir, jmp, lreg, 0);

	if (rval->sym->irs.loc == LOC_REG) {
		rreg = rval->sym->irs.reg;
	} else {
		rreg = BPF_REG_2;
		ir_emit_sym_to_reg(pb->ir, rreg, rval->sym);
	}

	ir_emit_insn(pb->ir, jmp, rreg, 0);
	ir_emit_insn(pb->ir, MOV_IMM(!start), dst, 0);
	ir_emit_label(pb->ir, out);

	if (dst == BPF_REG_0)
		ir_emit_reg_to_sym(pb->ir, n->sym, BPF_REG_0);
	return 0;
}

static int logop_type_infer(const struct func *func, struct node *n)
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

#define LOGOP(_fn, _name)				\
	__ply_built_in const struct func math_ ## _fn =	\
	{						\
		.name = _name,				\
		.type = &t_binop_func,			\
		.type_infer = logop_type_infer,		\
		.ir_post = logop_ir_post,		\
	}

LOGOP(logand, "&&");
LOGOP(logor,  "||");

static int relop_ir_post(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *lval, *rval;
	struct bpf_insn jmp;
	struct type *t;
	int32_t *imm = NULL;
	int dst = 0, lreg = 0, rreg = 0;
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

static int relop_type_infer(const struct func *func, struct node *n)
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

#define RELOP(_fn, _name)				\
	__ply_built_in const struct func math_ ## _fn =	\
	{						\
		.name = _name,				\
		.type = &t_binop_func,			\
		.type_infer = relop_type_infer,		\
		.ir_post = relop_ir_post,		\
	}

RELOP(eq, "==");
RELOP(ne, "!=");
RELOP(lt,  "<");
RELOP(gt,  ">");
RELOP(le, "<=");
RELOP(ge, ">=");


static int binop_ir_post(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *lval, *rval;
	struct bpf_insn op;
	int32_t *imm = NULL;
	int dst = 0, src = 0;

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

static int binop_type_infer(const struct func *func, struct node *n)
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

#define BINOP(_fn, _name)				\
	__ply_built_in const struct func math_ ## _fn =	\
	{						\
		.name = _name,				\
		.type = &t_binop_func,			\
		.type_infer = binop_type_infer,		\
		.ir_post = binop_ir_post,		\
	}

BINOP(bitor,   "|");
BINOP(bitxor,  "^");
BINOP(bitand,  "&");
BINOP(shl,    "<<");
BINOP(shr,    ">>");
BINOP(add,     "+");
BINOP(sub,     "-");
BINOP(mul,     "*");
BINOP(div,     "/");
BINOP(mod,     "%");
