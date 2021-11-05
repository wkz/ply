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
	{ .name = "r15",      .type = &t_reg_t },
	{ .name = "r14",      .type = &t_reg_t },
	{ .name = "r13",      .type = &t_reg_t },
	{ .name = "r12",      .type = &t_reg_t },
	{ .name = "rbp",      .type = &t_reg_t },
	{ .name = "rbx",      .type = &t_reg_t },
	{ .name = "r11",      .type = &t_reg_t },
	{ .name = "r10",      .type = &t_reg_t },
	{ .name = "r9",       .type = &t_reg_t },
	{ .name = "r8",       .type = &t_reg_t },
	{ .name = "rax",      .type = &t_reg_t },
	{ .name = "rcx",      .type = &t_reg_t },
	{ .name = "rdx",      .type = &t_reg_t },
	{ .name = "rsi",      .type = &t_reg_t },
	{ .name = "rdi",      .type = &t_reg_t },
	{ .name = "orig_rax", .type = &t_reg_t },
	{ .name = "rip",      .type = &t_reg_t },
	{ .name = "cs",       .type = &t_reg_t },
	{ .name = "eflags",   .type = &t_reg_t },
	{ .name = "rsp",      .type = &t_reg_t },
	{ .name = "ss",       .type = &t_reg_t },

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
	case 0: return "rdi";
	case 1: return "rsi";
	case 2: return "rdx";
	case 3: return "r10";
	case 4: return "r8";
	case 5: return "r9";
	}

	return NULL;
}

const char *arch_register_pc(void) 
{
	return "rip";
}

const char *arch_register_return(void)
{
	return "rax";
}

__attribute__((constructor))
static void arch_init(void)
{
	type_struct_layout(&t_pt_regs);
	type_add_list(arch_types);
}
