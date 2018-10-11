/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <assert.h>

#include <ply/internal.h>

#define arch_typedef(_a, _t) {					\
		.ttype = T_TYPEDEF,				\
		.tdef = { .name = #_a, .type = _t },		\
	}

struct type t_s8  = arch_typedef(s8,  &t_schar);
struct type t_u8  = arch_typedef(u8,  &t_uchar);
struct type t_s16 = arch_typedef(s16, &t_sshort);
struct type t_u16 = arch_typedef(u16, &t_ushort);
struct type t_s32 = arch_typedef(s32, &t_sint);
struct type t_u32 = arch_typedef(u32, &t_uint);
struct type t_s64 = arch_typedef(s64, &t_sllong);
struct type t_u64 = arch_typedef(u64, &t_ullong);

static int reg_fprint(struct type *t, FILE *fp, const void *data)
{
	return fprintf(fp, "%#lx", *((unsigned long *)data));
}

struct type t_reg_t = {
	.ttype = T_TYPEDEF,
	.tdef = {
		.name = "reg_t",
		.type = &t_ulong,
	},

	.fprint = reg_fprint,
};

struct tfield f_pt_regs_fields[] = {
	{ .name =  "gpr0",     .type = &t_reg_t },
	{ .name =  "gpr1",     .type = &t_reg_t },
	{ .name =  "gpr2",     .type = &t_reg_t },
	{ .name =  "gpr3",     .type = &t_reg_t },
	{ .name =  "gpr4",     .type = &t_reg_t },
	{ .name =  "gpr5",     .type = &t_reg_t },
	{ .name =  "gpr6",     .type = &t_reg_t },
	{ .name =  "gpr7",     .type = &t_reg_t },
	{ .name =  "gpr8",     .type = &t_reg_t },
	{ .name =  "gpr9",     .type = &t_reg_t },
	{ .name = "gpr10",     .type = &t_reg_t },
	{ .name = "gpr11",     .type = &t_reg_t },
	{ .name = "gpr12",     .type = &t_reg_t },
	{ .name = "gpr13",     .type = &t_reg_t },
	{ .name = "gpr14",     .type = &t_reg_t },
	{ .name = "gpr15",     .type = &t_reg_t },
	{ .name = "gpr16",     .type = &t_reg_t },
	{ .name = "gpr17",     .type = &t_reg_t },
	{ .name = "gpr18",     .type = &t_reg_t },
	{ .name = "gpr19",     .type = &t_reg_t },
	{ .name = "gpr20",     .type = &t_reg_t },
	{ .name = "gpr12",     .type = &t_reg_t },
	{ .name = "gpr22",     .type = &t_reg_t },
	{ .name = "gpr23",     .type = &t_reg_t },
	{ .name = "gpr24",     .type = &t_reg_t },
	{ .name = "gpr25",     .type = &t_reg_t },
	{ .name = "gpr26",     .type = &t_reg_t },
	{ .name = "gpr27",     .type = &t_reg_t },
	{ .name = "gpr28",     .type = &t_reg_t },
	{ .name = "gpr29",     .type = &t_reg_t },
	{ .name = "gpr30",     .type = &t_reg_t },
	{ .name = "gpr31",     .type = &t_reg_t },
	{ .name = "nip",       .type = &t_reg_t },
	{ .name = "msr",       .type = &t_reg_t },
	{ .name = "orig_gpr3", .type = &t_reg_t },
	{ .name = "ctr",       .type = &t_reg_t },
	{ .name = "link",      .type = &t_reg_t },
	{ .name = "xer",       .type = &t_reg_t },
	{ .name = "ccr",       .type = &t_reg_t },
	{ .name = "mq",        .type = &t_reg_t },
	{ .name = "trap",      .type = &t_reg_t },
	{ .name = "dar",       .type = &t_reg_t },
	{ .name = "dsisr",     .type = &t_reg_t },
	{ .name = "result",    .type = &t_reg_t },

	{ .type = NULL }
};

struct type t_pt_regs = {
	.ttype = T_STRUCT,

	.sou = {
		.name = "pt_regs",
		.fields = f_pt_regs_fields,
	},
};

struct type *arch_types[] = {
	&t_s8, &t_u8,
	&t_s16, &t_u16,
	&t_s32, &t_u32,
	&t_s64, &t_u64,
	&t_reg_t, &t_pt_regs,

	NULL
};

const char *arch_register_argument(int num)
{
	switch (num) {
	case 0: return "gpr3";
	case 1: return "gpr4";
	case 2: return "gpr5";
	case 3: return "gpr6";
	case 4: return "gpr7";
	case 5: return "gpr8";
	case 6: return "gpr9";
	}

	return NULL;
}

const char *arch_register_pc(void)
{
	return "nip";
}

const char *arch_register_return(void)
{
	return "gpr3";
}

__attribute__((constructor))
static void arch_init(void)
{
	type_add_list(arch_types);
}
