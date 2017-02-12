/*
 * Copyright 2015-2016 Tobias Waldekranz <tobias@waldekranz.com>
 *
 * This file is part of ply.
 *
 * ply is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, under the terms of version 2 of the
 * License.
 *
 * ply is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ply.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <assert.h>
#include <errno.h>
#include <search.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/bpf.h>

#define _ALIGN sizeof(int64_t)
#define _ALIGNED(_size) (((_size) + _ALIGN - 1) & ~(_ALIGN - 1))

#define DYN_REGS ((1 << BPF_REG_6) | (1 << BPF_REG_7) | (1 << BPF_REG_8))

static inline void insque_tail(void *elem, void *prev)
{
	struct { void *next, *prev; } *le = elem, *pe = prev;

	for (; pe && pe->next; pe = pe->next);
	insque(le, pe);
}

/* The bpf opcode-field is 8 bits, so we know this won't collide with
 * any BPF_* defines */
#define OP_JMP 0x100

#define OP_TABLE				\
	OP(OP_OR,  BPF_OR,            "|" )	\
	OP(OP_XOR, BPF_XOR,           "^" )	\
	OP(OP_AND, BPF_AND,           "&" )	\
	OP(OP_EQ,  BPF_JEQ  | OP_JMP, "==")	\
	OP(OP_NE,  BPF_JNE  | OP_JMP, "!=")	\
	OP(OP_GE,  BPF_JSGE | OP_JMP, ">=")	\
	OP(OP_GT,  BPF_JSGT | OP_JMP, ">" )	\
	OP(OP_LSH, BPF_LSH,           "<<")	\
	OP(OP_RSH, BPF_RSH,           ">>")	\
	OP(OP_ADD, BPF_ADD,           "+" )	\
	OP(OP_SUB, BPF_SUB,           "-" )	\
	OP(OP_MUL, BPF_MUL,           "*" )	\
	OP(OP_DIV, BPF_DIV,           "/" )	\
	OP(OP_MOD, BPF_MOD,           "%" )

#define OP(_type, _bpf_type, _typestr) _type = _bpf_type,
typedef enum op {
	OP_TABLE
} op_t;
#undef OP

typedef struct node node_t;
typedef struct dyn  dyn_t;

typedef struct pvdr pvdr_t;

typedef struct func func_t;

typedef struct rec {
	int     n_vargs;
	node_t *vargs;
} rec_t;

typedef struct map {
	int max_len;
	node_t *rec;
} map_t;

typedef struct binop {
	op_t    op;
	node_t *left, *right;
} binop_t;

typedef struct assign {
	node_t *lval, *expr;
} assign_t;

typedef struct method {
	node_t *map, *call;
} method_t;

typedef struct iff {
	node_t *cond;
	node_t *then, *then_last;
	node_t *els;
} if_t;

typedef struct unroll {
	int64_t count;
	node_t *stmts;
} unroll_t;

typedef struct call {
	char   *module;
	int     n_vargs;
	node_t *vargs;
} call_t;

typedef struct probe {
	node_t *pred;
	node_t *stmts;
} probe_t;

typedef struct script {
	node_t *probes;
} script_t;

#define NODE_TYPE_TABLE					\
	TYPE(TYPE_NONE,     "none")			\
	TYPE(TYPE_SCRIPT,   "script")			\
	TYPE(TYPE_PROBE,    "probe")			\
	TYPE(TYPE_IF,       "if")			\
	TYPE(TYPE_UNROLL,   "unroll")			\
	TYPE(TYPE_BREAK,    "break")			\
	TYPE(TYPE_CONTINUE, "continue")			\
	TYPE(TYPE_CALL,     "call")			\
	TYPE(TYPE_ASSIGN,   "assign")			\
	TYPE(TYPE_METHOD,   "method")			\
	TYPE(TYPE_RETURN,   "return")			\
	TYPE(TYPE_BINOP,    "binop")			\
	TYPE(TYPE_NOT,      "not")			\
	TYPE(TYPE_VAR,      "var")			\
	TYPE(TYPE_MAP,      "map")			\
	TYPE(TYPE_REC,      "rec")			\
	TYPE(TYPE_STACK,    "stack")			\
	TYPE(TYPE_INT,      "int")			\
	TYPE(TYPE_STR,      "str")

#define TYPE(_type, _typestr) _type,
typedef enum type {
	NODE_TYPE_TABLE
} type_t;
#undef TYPE

const char *type_str(type_t type);

typedef void  (*dumper_t)(FILE *fp, node_t *n, void *data);
typedef void (*mdumper_t)(FILE *fp, node_t *n, void *data, int len);
typedef int    (*cmper_t)(node_t *n, const void *a, const void *b);

typedef enum loc {
	LOC_NOWHERE,
	LOC_VIRTUAL,
	LOC_REG,
	LOC_STACK,
} loc_t;

const char *loc_str(loc_t loc);

typedef struct symtable symtable_t;
typedef struct evpipe evpipe_t;

struct dyn {
	type_t type;
	size_t size;

	loc_t   loc;
	int     reg;
	ssize_t addr;

	union {
		struct {
			enum bpf_map_type type;
			int fd;

			mdumper_t dump;
			cmper_t cmp;
		} map;

		struct {
			const func_t *func;
		} call;

		struct {
			struct bpf_insn *jmp;
		} iff;

		struct {
			struct bpf_insn *start;
		} unroll;

		struct {
			pvdr_t *pvdr;
			void   *pvdr_priv;

			ssize_t sp;
			int     dyn_regs;
			int     stat_regs;
		} probe;

		struct {
			symtable_t *st;
			evpipe_t   *evp;

			int     fmt_id;
			node_t *printf[64];
		} script;
	};
};

struct node {
	node_t *next, *prev;

	type_t  type;
	dyn_t  *dyn;

	char   *string;
	node_t *parent;

	dumper_t dump;
	cmper_t  cmp;

	union {
		script_t script;
		probe_t  probe;
		if_t     iff;
		unroll_t unroll;
		call_t   call;
		assign_t assign;
		method_t method;
		binop_t  binop;
		map_t    map;
		rec_t    rec;
		node_t  *not;
		int64_t  integer;
	};
};

static inline const char *node_str(const node_t *node)
{
	static char buf[8];

	if (node->string)
		return node->string;

	snprintf(buf, sizeof(buf), "<%s>", type_str(node->type));
	return buf;
}

#define node_foreach(_n, _in) for((_n) = (_in); (_n); (_n) = (_n)->next)

int node_fdump(node_t *n, FILE *fp);
int node_sdump(node_t *n, char *buf, size_t sz);

void node_ast_dump(node_t *n);

node_t *node_get_parent_of_type(type_t type, node_t *n);

node_t *node_get_stmt  (node_t *n);
pvdr_t *node_get_pvdr  (node_t *n);
node_t *node_get_probe (node_t *n);
node_t *node_get_script(node_t *n);

/* int     node_stmt_reg_get   (node_t *stmt); */
int     node_probe_reg_get  (node_t *probe, int dynamic);
ssize_t node_probe_stack_get(node_t *probe, size_t size);

node_t *node_new         (type_t type);
node_t *node_str_new     (char *val);
node_t *node_int_new     (int64_t val);
node_t *node_rec_new     (node_t *vargs);
node_t *node_map_new     (char *name, node_t *rec);
node_t *node_var_new     (char *name);
node_t *node_not_new     (node_t *expr);
node_t *node_binop_new   (node_t *left, op_t op, node_t *right);
node_t *node_assign_new  (node_t *lval, node_t *expr);
node_t *node_method_new  (node_t *map, node_t *call);
node_t *node_if_new      (node_t *cond, node_t *then, node_t *els);
node_t *node_unroll_new  (int64_t count, node_t *stmts);
node_t *node_call_new    (char *module, char *func, node_t *vargs);
node_t *node_probe_new   (char *pspec, node_t *pred, node_t *stmts);
node_t *node_script_new  (node_t *probes);
node_t *node_script_parse(FILE *fp);

void node_free(node_t *n);
int  node_walk(node_t *n,
	       int  (*pre)(node_t *n, void *ctx),
	       int (*post)(node_t *n, void *ctx), void *ctx);
