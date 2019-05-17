/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <assert.h>
#include <errno.h>

#include <ply/ply.h>
#include <ply/internal.h>

#include "built-in.h"


static int count_ir_post(const struct func *func, struct node *n,
			 struct ply_probe *pb)
{
	struct node *mapop = n->up->expr.args;

	ir_emit_sym_to_reg(pb->ir, BPF_REG_0, mapop->sym);
	ir_emit_insn(pb->ir, ALU_IMM(BPF_ADD, 1), BPF_REG_0, 0);
	ir_emit_reg_to_sym(pb->ir, mapop->sym, BPF_REG_0);
	return 0;
	/* return map_ir_update(mapop, pb); */
}

struct type t_count_func = {
	.ttype = T_FUNC,

	.func = { .type = &t_ulong },
};

__ply_built_in const struct func count_func = {
	.name = "count",
	.type = &t_count_func,
	.static_ret = 1,

	.ir_post = count_ir_post,
};


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

	if (!log2) {
		*suffix = s[0];
		return 0;
	}

	for (i = 0; log2 >= 10; i++, log2 -= 10);

	*suffix = s[i];
	return (1 << log2);
}

static int __quantize_fprint_bucket_ext(struct type *t, FILE *fp, int i)
{
	struct type *arg_type = t->priv;
	int64_t slo, shi;
	uint64_t ulo, uhi;

	slo = i ? (1LL  << i) : 0;
	ulo = i ? (1ULL << i) : 0;

	shi = (1LL  << (i + 1)) - 1;
	uhi = (1ULL << (i + 1)) - 1;

	fputs("\t[", fp);
	if (type_base(arg_type)->scalar.unsignd)
		type_fprint(arg_type, fp, &ulo);
	else
		type_fprint(arg_type, fp, &slo);

	fputs(", ", fp);
	if (type_base(arg_type)->scalar.unsignd)
		type_fprint(arg_type, fp, &uhi);
	else
		type_fprint(arg_type, fp, &shi);

	fputs("]", fp);
	return 0;
}

static int __quantize_fprint_bucket(struct type *t, FILE *fp, int i)
{
	struct type *arg_type = t->priv;
	const char *ls, *hs;
	int lo, hi;

	if (arg_type->fprint_log2)
		return __quantize_fprint_bucket_ext(t, fp, i);

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

static int quantize_fprint(struct type *t, FILE *fp, const void *data)
{
	const unsigned int *bucket = data;
	struct type *arg_type = t->priv;
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

static int quantize_ir_post(const struct func *func, struct node *n,
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

	ir_emit_ldbp(pb->ir, BPF_REG_1, mapop->sym->irs.stack);
	ir_emit_insn(pb->ir, ALU64(BPF_ADD), BPF_REG_1, BPF_REG_0);

	ir_emit_insn(pb->ir, MOV_IMM(1), BPF_REG_0, 0);
	ir_emit_insn(pb->ir, ST_XADD(bpf_width(bucketsz), 0), BPF_REG_1, BPF_REG_0);
	return 0;
	/* return map_ir_update(mapop, pb); */
}

static int quantize_type_infer(const struct func *func, struct node *n)
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
	n->sym->type->priv = arg->sym->type;
	n->sym->type->fprint = quantize_fprint;
	return 0;
}

__ply_built_in const struct func quantize_func = {
	.name = "quantize",
	.type = &t_unary_func,
	.type_infer = quantize_type_infer,

	.ir_post = quantize_ir_post,
};
