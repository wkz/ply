/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <time.h>

#include <ply/ply.h>
#include <ply/internal.h>

#include "built-in.h"

struct stack_priv {
	struct ksyms *ks;
	struct sym *sym;

	uint64_t bt[0];
};

static int stack_fprint(struct type *t, FILE *fp, const void *data)
{
	struct stack_priv *sp = t->priv;
	uint32_t stackid = *(uint32_t *)data;
	size_t i;

	if (bpf_map_lookup(sp->sym->mapfd, &stackid, sp->bt))
		return fprintf(fp, "<STACKID%u>", stackid);

	fputc('\n', fp);
	for (i = 0; i < ply_config.stack_depth; i++) {
		if (!sp->bt[i])
			break;

		fputc('\t', fp);
		ksym_fprint(sp->ks, fp, (uintptr_t)sp->bt[i]);
		fputc('\n', fp);
	}

	return 0;
}


struct type t_stackid_t = {
	.ttype = T_TYPEDEF,

	.tdef = {
		.type = &t_u32,
		.name = ":stackid",
	},

	.fprint = stack_fprint,
};

__ply_built_in const struct func stackmap_func = {
	.name = ":stackmap",
};

static int stack_ir_post(const struct func *func, struct node *n,
			 struct ply_probe *pb)
{
	struct node *ctx, *map;

	ctx = n->expr.args;
	map  = ctx->next;

	ir_init_sym(pb->ir, n->sym);

	ir_emit_sym_to_reg(pb->ir, BPF_REG_1, ctx->sym);
	ir_emit_ldmap(pb->ir, BPF_REG_2, map->sym);
	ir_emit_insn(pb->ir, MOV_IMM(0), BPF_REG_3, 0);
	ir_emit_insn(pb->ir, CALL(BPF_FUNC_get_stackid), 0, 0);
	ir_emit_reg_to_sym(pb->ir, n->sym, BPF_REG_0);
	return 0;
}

static int stack_rewrite(const struct func *func, struct node *n,
			 struct ply_probe *pb)
{
	struct node *nmap;
	struct type *tarray, *tmap;
	struct stack_priv *sp;
	size_t depth;

	if (n->sym->type->priv)
		return 0;

	nmap = node_expr_ident(&n->loc, ":stackmap");
	nmap->sym = sym_alloc(&pb->ply->globals, nmap, &stackmap_func);

	tarray = type_array_of(&t_u64, ply_config.stack_depth);
	tmap = type_map_of(&t_u32, tarray, BPF_MAP_TYPE_STACK_TRACE, 0);
	nmap->sym->type = tmap;

	sp = xcalloc(1, sizeof(*sp) + type_sizeof(tarray));
	sp->ks = pb->ply->ksyms;
	sp->sym = nmap->sym;

	node_expr_append(&n->loc, n, node_expr_ident(&n->loc, "ctx"));
	node_expr_append(&n->loc, n, nmap);

	n->sym->type->priv = sp;
	return 1;
}

__ply_built_in const struct func kprobe_stack_func = {
	.name = "stack",
	.type = &t_stackid_t,
	.static_ret = 1,

	.rewrite = stack_rewrite,
	.ir_post = stack_ir_post,
};


static int pid_fprint(struct type *t, FILE *fp, const void *data)
{
	return fprintf(fp, "%5"PRIu32, *((uint32_t *)data)); 
}

struct type t_pid = {
	.ttype = T_TYPEDEF,

	.tdef = {
		.name = ":pid",
		.type = &t_u32,
	},

	.fprint = pid_fprint,
};

struct type t_pid_func = {
	.ttype = T_FUNC,

	.func = { .type = &t_pid },
};

static int pid_ir_post(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *ptr = n->expr.args;

	ir_init_sym(pb->ir, n->sym);

	ir_emit_insn(pb->ir, CALL(BPF_FUNC_get_current_pid_tgid), 0, 0);
	ir_emit_insn(pb->ir, ALU64_IMM(BPF_RSH, 32), BPF_REG_0, 0);
	ir_emit_reg_to_sym(pb->ir, n->sym, BPF_REG_0);
	return 0;
}

__ply_built_in const struct func pid_func = {
	.name = "pid",
	.type = &t_pid_func,
	.static_ret = 1,

	.ir_post = pid_ir_post,
};


static int kpid_ir_post(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *ptr = n->expr.args;

	ir_init_sym(pb->ir, n->sym);

	ir_emit_insn(pb->ir, CALL(BPF_FUNC_get_current_pid_tgid), 0, 0);
	ir_emit_insn(pb->ir, ALU64_IMM(BPF_AND, 0xffffffff), BPF_REG_0, 0);
	ir_emit_reg_to_sym(pb->ir, n->sym, BPF_REG_0);
	return 0;
}

__ply_built_in const struct func kpid_func = {
	.name = "kpid",
	.type = &t_pid_func,
	.static_ret = 1,

	.ir_post = kpid_ir_post,
};


/* uid/gid */

static int uid_fprint(struct type *t, FILE *fp, const void *data)
{
	return fprintf(fp, "%4"PRIu32, *((uint32_t *)data)); 
}

struct type t_uid = {
	.ttype = T_TYPEDEF,

	.tdef = {
		.name = ":uid",
		.type = &t_u32,
	},

	.fprint = uid_fprint,
};

struct type t_uid_func = {
	.ttype = T_FUNC,

	.func = { .type = &t_uid },
};

static int uid_ir_post(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *ptr = n->expr.args;

	ir_init_sym(pb->ir, n->sym);

	ir_emit_insn(pb->ir, CALL(BPF_FUNC_get_current_uid_gid), 0, 0);
	ir_emit_insn(pb->ir, ALU64_IMM(BPF_AND, 0xffffffff), BPF_REG_0, 0);
	ir_emit_reg_to_sym(pb->ir, n->sym, BPF_REG_0);
	return 0;
}


__ply_built_in const struct func uid_func = {
	.name = "uid",
	.type = &t_uid_func,
	.static_ret = 1,

	.ir_post = uid_ir_post,
};



static int gid_ir_post(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *ptr = n->expr.args;

	ir_init_sym(pb->ir, n->sym);

	ir_emit_insn(pb->ir, CALL(BPF_FUNC_get_current_uid_gid), 0, 0);
	ir_emit_insn(pb->ir, ALU64_IMM(BPF_RSH, 32), BPF_REG_0, 0);
	ir_emit_reg_to_sym(pb->ir, n->sym, BPF_REG_0);
	return 0;
}

__ply_built_in const struct func gid_func = {
	.name = "gid",
	.type = &t_uid_func,
	.static_ret = 1,

	.ir_post = gid_ir_post,
};


static int cpu_fprint(struct type *t, FILE *fp, const void *data)
{
	return fprintf(fp, "%2"PRIu32, *((uint32_t *)data)); 
}

struct type t_cpu = {
	.ttype = T_TYPEDEF,

	.tdef = {
		.name = ":cpu",
		.type = &t_u32,
	},

	.fprint = cpu_fprint,
};

struct type t_cpu_func = {
	.ttype = T_FUNC,

	.func = { .type = &t_cpu },
};

static int cpu_ir_post(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *ptr = n->expr.args;

	ir_init_sym(pb->ir, n->sym);

	ir_emit_insn(pb->ir, CALL(BPF_FUNC_get_smp_processor_id), 0, 0);
	ir_emit_reg_to_sym(pb->ir, n->sym, BPF_REG_0);
	return 0;
}

__ply_built_in const struct func cpu_func = {
	.name = "cpu",
	.type = &t_cpu_func,
	.static_ret = 1,

	.ir_post = cpu_ir_post,
};


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

static int comm_ir_post(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *ptr = n->expr.args;

	ir_init_sym(pb->ir, n->sym);

	ir_emit_bzero(pb->ir, n->sym->irs.stack, type_sizeof(n->sym->type));

	ir_emit_ldbp(pb->ir, BPF_REG_1, n->sym->irs.stack);
	ir_emit_insn(pb->ir, MOV_IMM(type_sizeof(n->sym->type)), BPF_REG_2, 0);
	ir_emit_insn(pb->ir, CALL(BPF_FUNC_get_current_comm), 0, 0);
	return 0;
}

__ply_built_in const struct func comm_func = {
	.name = "comm",
	.type = &t_comm_func,
	.static_ret = 1,

	.ir_post = comm_ir_post,
};

__ply_built_in const struct func execname_func = {
	/* alias to comm */
	.name = "execname",
	.type = &t_comm_func,
	.static_ret = 1,

	.ir_post = comm_ir_post,
};

#define SECOND 1000000000LL

static int64_t to_walltime = 0;

__attribute__((constructor))
static void walltime_init(void)
{
	struct timespec mono, wall;

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &mono) ||
	    clock_gettime(CLOCK_REALTIME, &wall))
		return;

	wall.tv_nsec -= mono.tv_nsec;
	if (wall.tv_nsec < 0) {
		wall.tv_sec--;
		wall.tv_nsec += SECOND;
	}

	wall.tv_sec -= mono.tv_sec;

	to_walltime = wall.tv_sec * SECOND + wall.tv_nsec;
}

static int walltime_fprint(struct type *t, FILE *fp, const void *data)
{
	int64_t ns = *(int64_t *)data;
	char tstr[0x20] = { '\0' };
	struct tm tm;
	time_t s;

	ns += to_walltime;

	s   = ns / SECOND;
	ns %= SECOND;

	localtime_r(&s, &tm);
	strftime(tstr, sizeof(tstr), "%T", &tm);
	fputs(tstr, fp);
	fprintf(fp, ".%09"PRId64, ns);
	return 0;
}

struct type t_walltime = {
	.ttype = T_TYPEDEF,

	.tdef = {
		.name = ":walltime",
		.type = &t_s64,
	},

	.fprint = walltime_fprint,
};

struct type t_walltime_func = {
	.ttype = T_FUNC,

	.func = { .type = &t_walltime },
};

static int time_fprint_long(FILE *fp, int64_t ns)
{
	char tstr[0x10] = { '\0' };
	struct tm *tm;
	time_t s;

	s = ns / SECOND;

	tm = gmtime(&s);
	strftime(tstr, sizeof(tstr), "%T", tm);
	fputs(tstr, fp);
	return 0;
}

struct timefmt {
	int cutoff;
	int next;

	const char *fmt;
	int radix;
};

static int time_fprint(struct type *t, FILE *fp, const void *data)
{
	static const struct timefmt fmts[] = {
		{  999,  10, "%4dns", 1 },
		{  999,  10, "%1d.%02dus", 100 },
		{  999,  10, "%2d.%01dus", 10 },
		{  999,  10, "%4dus", 1 },
		{  999,  10, "%1d.%02dms", 100 },
		{  999,  10, "%2d.%01dms", 10 },
		{  999,  10, "%4dms", 1 },
		{  999,  10, "%1d.%02d s", 100 },
		{  999,  10, "%2d.%01d s", 10 },
		{  999,  60, "%4d s", 1 },
		{  999,  60, "%4d M", 1 },
		{  999,  24, "%4d H", 1 },
		{  999, 365, "%4d D", 1 },
		{  999,   1, "%4d Y", 1 },

		{ 0, 0, NULL, 0 }
	};

	int64_t ns = *(int64_t *)data;
	const struct timefmt *fmt;

	for (fmt = fmts; fmt->fmt; fmt++) {
		if (ns <= fmt->cutoff)
			break;

		ns /= fmt->next;
	}

	assert(fmt && fmt->fmt);

	if (fmt->radix == 1)
		return fprintf(fp, fmt->fmt, (int)ns);
	else
		return fprintf(fp, fmt->fmt,
			       (int)ns/fmt->radix, (int)ns%fmt->radix);
}

struct type t_time = {
	.ttype = T_TYPEDEF,

	.tdef = {
		.name = ":time",
		.type = &t_s64,
	},

	.fprint = time_fprint,
	.fprint_log2 = 1,
};

struct type t_time_func = {
	.ttype = T_FUNC,

	.func = { .type = &t_time },
};

static int time_ir_post(const struct func *func, struct node *n,
			       struct ply_probe *pb)
{
	struct node *ptr = n->expr.args;

	ir_init_sym(pb->ir, n->sym);

	ir_emit_insn(pb->ir, CALL(BPF_FUNC_ktime_get_ns), 0, 0);
	ir_emit_reg_to_sym(pb->ir, n->sym, BPF_REG_0);
	return 0;
}

__ply_built_in const struct func time_func = {
	.name = "time",
	.type = &t_time_func,
	.static_ret = 1,

	.ir_post = time_ir_post,
};

__ply_built_in const struct func walltime_func = {
	.name = "walltime",
	.type = &t_walltime_func,
	.static_ret = 1,

	.ir_post = time_ir_post,
};
