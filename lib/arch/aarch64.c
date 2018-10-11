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
struct type t_s64 = arch_typedef(s64, &t_slong);
struct type t_u64 = arch_typedef(u64, &t_ulong);

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
	{ .name =  "x0",      .type = &t_reg_t },
	{ .name =  "x1",      .type = &t_reg_t },
	{ .name =  "x2",      .type = &t_reg_t },
	{ .name =  "x3",      .type = &t_reg_t },
	{ .name =  "x4",      .type = &t_reg_t },
	{ .name =  "x5",      .type = &t_reg_t },
	{ .name =  "x6",      .type = &t_reg_t },
	{ .name =  "x7",      .type = &t_reg_t },
	{ .name =  "x8",      .type = &t_reg_t },
	{ .name =  "x9",      .type = &t_reg_t },
	{ .name = "x10",      .type = &t_reg_t },
	{ .name = "x11",      .type = &t_reg_t },
	{ .name = "x12",      .type = &t_reg_t },
	{ .name = "x13",      .type = &t_reg_t },
	{ .name = "x14",      .type = &t_reg_t },
	{ .name = "x15",      .type = &t_reg_t },
	{ .name = "x16",      .type = &t_reg_t },
	{ .name = "x17",      .type = &t_reg_t },
	{ .name = "x18",      .type = &t_reg_t },
	{ .name = "x19",      .type = &t_reg_t },
	{ .name = "x20",      .type = &t_reg_t },
	{ .name = "x12",      .type = &t_reg_t },
	{ .name = "x22",      .type = &t_reg_t },
	{ .name = "x23",      .type = &t_reg_t },
	{ .name = "x24",      .type = &t_reg_t },
	{ .name = "x25",      .type = &t_reg_t },
	{ .name = "x26",      .type = &t_reg_t },
	{ .name = "x27",      .type = &t_reg_t },
	{ .name = "x28",      .type = &t_reg_t },
	{ .name = "x29",      .type = &t_reg_t },
	{ .name = "x30",      .type = &t_reg_t },
	{ .name = "sp",       .type = &t_reg_t },
	{ .name = "pc",       .type = &t_reg_t },
	{ .name = "pstate",   .type = &t_reg_t },

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
	case 0: return "x0";
	case 1: return "x1";
	case 2: return "x2";
	case 3: return "x3";
	case 4: return "x4";
	case 5: return "x5";
	case 6: return "x6";
	case 7: return "x7";
	}

	return NULL;
}

const char *arch_register_pc(void)
{
	return "pc";
}

const char *arch_register_return(void)
{
	return "x0";
}

__attribute__((constructor))
static void arch_init(void)
{
	type_add_list(arch_types);
}
