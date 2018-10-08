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
	{ .name =  "r0",     .type = &t_reg_t },
	{ .name =  "r1",     .type = &t_reg_t },
	{ .name =  "r2",     .type = &t_reg_t },
	{ .name =  "r3",     .type = &t_reg_t },
	{ .name =  "r4",     .type = &t_reg_t },
	{ .name =  "r5",     .type = &t_reg_t },
	{ .name =  "r6",     .type = &t_reg_t },
	{ .name =  "r7",     .type = &t_reg_t },
	{ .name =  "r8",     .type = &t_reg_t },
	{ .name =  "r9",     .type = &t_reg_t },
	{ .name = "r10",     .type = &t_reg_t },
	{ .name = "fp",      .type = &t_reg_t },
	{ .name = "ip",      .type = &t_reg_t },
	{ .name = "sp",      .type = &t_reg_t },
	{ .name = "lr",      .type = &t_reg_t },
	{ .name = "pc",      .type = &t_reg_t },
	{ .name = "cpsr",    .type = &t_reg_t },
	{ .name = "orig_r0", .type = &t_reg_t },

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
	case 0: return "r0";
	case 1: return "r1";
	case 2: return "r2";
	case 3: return "r3";
	case 4: return "r4";
	case 5: return "r5";
	case 6: return "r6";
	}

	return NULL;
}

const char *arch_register_pc(void)
{
	return "pc";
}

const char *arch_register_return(void)
{
	return "r0";
}

__attribute__((constructor))
static void arch_init(void)
{
	type_add_list(arch_types);
}
