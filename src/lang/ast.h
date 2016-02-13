#pragma once

#include <assert.h>
#include <errno.h>
#include <search.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <linux/bpf.h>

#define _ALIGN sizeof(int64_t)
#define _ALIGNED(_size) (((_size) + _ALIGN - 1) & ~(_ALIGN - 1))

static inline void insque_tail(void *elem, void *prev)
{
	struct { void *next, *prev; } *le = elem, *pe = prev;

	for (; pe && pe->next; pe = pe->next);
	insque(le, pe);
}

typedef enum jmp {
	JMP_JEQ  = BPF_JEQ,
	JMP_JGT  = BPF_JGT,
	JMP_JGE  = BPF_JGE,
	JMP_JNE  = BPF_JNE,
	JMP_JSGT = BPF_JSGT,
	JMP_JSGE = BPF_JSGE,
	JMP_JA   = BPF_JA,
} jmp_t;

typedef enum alu_op {
	ALU_OP_ADD = BPF_ADD,
	ALU_OP_SUB = BPF_SUB,
	ALU_OP_MUL = BPF_MUL,
	ALU_OP_DIV = BPF_DIV,
	ALU_OP_OR  = BPF_OR,
	ALU_OP_AND = BPF_AND,
	ALU_OP_LSH = BPF_LSH,
	ALU_OP_RSH = BPF_RSH,
	ALU_OP_NEG = BPF_NEG,
	ALU_OP_MOD = BPF_MOD,
	ALU_OP_XOR = BPF_XOR,
	ALU_OP_MOV = BPF_MOV,
} alu_op_t;

typedef struct node node_t;
typedef struct dyn  dyn_t;
typedef struct mdyn mdyn_t;

/* forward from pvdr/pvdr.h */
typedef struct pvdr pvdr_t;

typedef struct rec {
	node_t *vargs;
} rec_t;

typedef struct map {
	node_t *rec;
} map_t;

typedef struct binop {
	alu_op_t op;
	node_t *left, *right;
} binop_t;

typedef struct assign {
	alu_op_t op;
	node_t *lval, *expr;
} assign_t;

typedef struct method {
	node_t *map, *call;
} method_t;

typedef struct call {
	node_t *vargs;
	void   *priv;
} call_t;

typedef struct probe {
	node_t *pred;
	node_t *stmts;

	pvdr_t *pvdr;

	ssize_t sp;
} probe_t;

struct mdyn {
	mdyn_t *next, *prev;

	node_t *map;
	int     mapfd;
};

typedef struct script {
	node_t *probes;
	mdyn_t *mdyns;

	int     fmt_id;
	node_t *printf[64];
} script_t;

#define NODE_TYPE_TABLE \
	TYPE(TYPE_NONE, "none")			\
	TYPE(TYPE_SCRIPT, "script")		\
	TYPE(TYPE_PROBE, "probe")		\
	TYPE(TYPE_CALL, "call")			\
	TYPE(TYPE_ASSIGN, "assign")		\
	TYPE(TYPE_METHOD, "method")		\
	TYPE(TYPE_RETURN, "return")		\
	TYPE(TYPE_BINOP, "binop")		\
	TYPE(TYPE_NOT, "not")			\
	TYPE(TYPE_MAP, "map")			\
	TYPE(TYPE_REC, "rec")			\
	TYPE(TYPE_INT, "int")			\
	TYPE(TYPE_STR, "str")

#define TYPE(_type, _typestr) _type,
typedef enum type {
	NODE_TYPE_TABLE
} type_t;
#undef TYPE

const char *type_str(type_t type);

typedef enum loc {
	LOC_NOWHERE,
	LOC_VIRTUAL,
	LOC_REG,
	LOC_STACK,
} loc_t;

struct dyn {
	type_t type;
	size_t size;

	loc_t   loc;
	int     reg;
	ssize_t addr;

	int     free_regs;

	union {
		struct {
			void *pvdr_priv;
		} probe;
	};
};

struct node {
	node_t *next, *prev;
	
	type_t  type;
	dyn_t   dyn;

	char   *string;
	node_t *parent;

	union {
		script_t script;
		probe_t  probe;
		call_t   call;
		assign_t assign;
		method_t method;
		binop_t  binop;
		map_t    map;
		rec_t    rec;
		node_t  *not;
		node_t  *ret;
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

void node_ast_dump(node_t *n);

node_t *node_get_stmt  (node_t *n);
pvdr_t *node_get_pvdr  (node_t *n);
node_t *node_get_probe (node_t *n);
node_t *node_get_script(node_t *n);

int     node_map_get_fd     (node_t *map);
int     node_stmt_reg_get   (node_t *stmt);
ssize_t node_probe_stack_get(node_t *probe, size_t size);

node_t *node_str_new     (char *val);
node_t *node_int_new     (int64_t val);
node_t *node_rec_new     (node_t *vargs);
node_t *node_map_new     (char *name, node_t *rec);
node_t *node_not_new     (node_t *expr);
node_t *node_return_new  (node_t *expr);
node_t *node_binop_new   (node_t *left, char *opstr, node_t *right);
node_t *node_assign_new  (node_t *lval, char *opstr, node_t *expr);
node_t *node_method_new  (node_t *map, node_t *call);
node_t *node_call_new    (char *func, node_t *vargs);
node_t *node_probe_new   (char *pspec, node_t *pred, node_t *stmts);
node_t *node_script_new  (node_t *probes);
node_t *node_script_parse(FILE *fp);

void node_free(node_t *n);
int  node_walk(node_t *n,
	     int  (*pre)(node_t *n, void *ctx),
	     int (*post)(node_t *n, void *ctx), void *ctx);
