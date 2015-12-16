#ifndef __FS_AST_H
#define __FS_AST_H

#include <assert.h>
#include <search.h>
#include <stdint.h>
#include <stdlib.h>

#include <linux/bpf.h>

#define _ALIGN 4
#define _ALIGNED(_size) (((_size) + _ALIGN - 1) & ~(_ALIGN - 1))

static inline void insque_tail(void *elem, void *prev)
{
	struct { void *next, *prev; } *le = elem, *pe = prev;

	for (; pe && pe->next; pe = pe->next);
	insque(le, pe);
}

enum fs_jmp {
	FS_JEQ = BPF_JEQ,
	FS_JGT = BPF_JGT,
	FS_JGE = BPF_JGE,
	FS_JNE = BPF_JNE,
	FS_JSGT = BPF_JSGT,
	FS_JSGE = BPF_JSGE,
};

enum fs_op {
	FS_ADD = BPF_ADD,
	FS_SUB = BPF_SUB,
	FS_MUL = BPF_MUL,
	FS_DIV = BPF_DIV,
	FS_OR  = BPF_OR,
	FS_AND = BPF_AND,
	FS_LSH = BPF_LSH,
	FS_RSH = BPF_RSH,
	FS_NEG = BPF_NEG,
	FS_MOD = BPF_MOD,
	FS_XOR = BPF_XOR,
	FS_MOV = BPF_MOV,
};

struct fs_map {
	struct fs_node *vargs;
};

struct fs_binop {
	enum fs_op op;
	struct fs_node *left, *right;
};

struct fs_assign {
	enum fs_op op;
	struct fs_node *lval, *expr;
};

struct fs_agg {
	struct fs_node *map, *func;
};

struct fs_pred {
	enum fs_jmp jmp;
	struct fs_node *left, *right;
};

struct fs_call {
	struct fs_node *vargs;
};

struct fs_probe {
	struct fs_node *pred;
	struct fs_node *stmts;
};

struct fs_script {
	struct fs_node *probes;
	struct fs_dyn  *dyns;
};

#define FS_TYPE_TABLE \
	TYPE(FS_NONE, "none")			\
	TYPE(FS_SCRIPT, "script")		\
	TYPE(FS_PROBE, "probe")			\
	TYPE(FS_PRED, "pred")			\
	TYPE(FS_CALL, "call")			\
	TYPE(FS_ASSIGN, "assign")		\
	TYPE(FS_AGG, "agg")			\
	TYPE(FS_RETURN, "return")		\
	TYPE(FS_BINOP, "binop")			\
	TYPE(FS_NOT, "not")			\
	TYPE(FS_MAP, "map")			\
	TYPE(FS_VAR, "var")			\
	TYPE(FS_INT, "int")			\
	TYPE(FS_STR, "str")

#define TYPE(_type, _typestr) _type,
enum fs_type {
	FS_TYPE_TABLE
};
#undef TYPE

const char *fs_typestr(enum fs_type type);

enum fs_loc_type {
	FS_LOC_NOWHERE,
	FS_LOC_REG,
	FS_LOC_STACK,
};

struct fs_loc {
	enum fs_loc_type type;

	int reg;
	ssize_t addr;
};

struct fs_dyn {
	struct fs_dyn *next, *prev;

	char           *string;

	enum fs_type    type;
	size_t          size;
	size_t          ksize;

	struct fs_loc   loc;
};

struct fs_node {
	struct fs_node *next, *prev;
	
	enum fs_type type;
	char        *string;

	struct fs_node *parent;
	struct fs_dyn  *dyn;

	union {
		struct fs_script script;
		struct fs_probe  probe;
		struct fs_pred   pred;
		struct fs_call   call;
		struct fs_assign assign;
		struct fs_agg    agg;
		struct fs_binop  binop;
		struct fs_map    map;
		struct fs_node  *not;
		struct fs_node  *ret;
		
		int64_t          integer;
	};
};


#define fs_foreach(_n, _in) for((_n) = (_in); (_n); (_n) = (_n)->next)

static inline int fs_node_is_sym(struct fs_node *n)
{
	return n->type == FS_VAR || n->type == FS_MAP;
}

static inline struct fs_node *fs_node_new(enum fs_type type) {
	struct fs_node *n = calloc(1, sizeof(*n));

	assert(n);
	n->type = type;
	return n;
}

void fs_ast_dump(struct fs_node *n);

struct fs_node *fs_str_new   (char *val);
struct fs_node *fs_int_new   (int64_t val);
struct fs_node *fs_var_new   (char *name);
struct fs_node *fs_map_new   (char *name, struct fs_node *vargs);
struct fs_node *fs_not_new   (struct fs_node *expr);
struct fs_node *fs_return_new(struct fs_node *expr);
struct fs_node *fs_binop_new (struct fs_node *left, char *opstr, struct fs_node *right);
struct fs_node *fs_agg_new   (struct fs_node *map, struct fs_node *func);
struct fs_node *fs_assign_new(struct fs_node *lval, char *opstr, struct fs_node *expr);
struct fs_node *fs_call_new  (char *func, struct fs_node *vargs);
struct fs_node *fs_pred_new  (struct fs_node *left, char *opstr, struct fs_node *right);
struct fs_node *fs_probe_new (char *pspec, struct fs_node *pred, struct fs_node *stmts);
struct fs_node *fs_script_new(struct fs_node *probes);

void fs_free(struct fs_node *n);
int  fs_walk(struct fs_node *n,
	     int  (*pre)(struct fs_node *n, void *ctx),
	     int (*post)(struct fs_node *n, void *ctx), void *ctx);

struct provider;
int fs_annotate(struct fs_node *script, struct provider *prov);

#endif	/* __FS_AST_H */
