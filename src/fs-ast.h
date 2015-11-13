#ifndef __FS_AST_H
#define __FS_AST_H

#include <assert.h>
#include <search.h>
#include <stdint.h>
#include <stdlib.h>

static inline void insque_tail(void *elem, void *prev)
{
	struct { void *next, *prev; } *le = elem, *pe = prev;

	for (; pe && pe->next; pe = pe->next);
	insque(le, pe);
}

struct fs_var {
	char *name;
	struct fs_node *vargs;
};

struct fs_binop {
	struct fs_node *left, *right;
	char *op;
};

struct fs_assign {
	struct fs_node *lval, *expr;
	char *op;
};

struct fs_cond {
	struct fs_node *cond;
	struct fs_node *yes, *no;
};

struct fs_call {
	char *func;
	struct fs_node *vargs;
};

struct fs_probespec {
	void *next, *prev;
	char *spec;
};

struct fs_probe {
	struct fs_probespec *spec;
	struct fs_node *stmts;
};

struct fs_script {
	struct fs_node *probes;
};

enum fs_type {
	FS_UNKNOWN,
	FS_NOP,
	FS_SCRIPT,
	FS_PROBE,
	FS_CALL,
	FS_COND,
	FS_ASSIGN,
	FS_RETURN,
	FS_BINOP,
	FS_NOT,
	FS_VAR,
	FS_INT,
	FS_STR,
};

struct fs_node {
	void *next, *prev;

	enum fs_type type;

	union {
		struct fs_script script;
		struct fs_probe  probe;
		struct fs_call   call;
		struct fs_cond   cond;
		struct fs_assign assign;
		struct fs_binop  binop;
		struct fs_var    var;
		struct fs_node  *not;
		struct fs_node  *ret;
		
		int64_t          integer;
		char            *string;
	};
};
	
void fs_ast_dump(struct fs_node *n);

static inline struct fs_node *fs_node_new(enum fs_type type) {
	struct fs_node *n = calloc(1, sizeof(*n));

	assert(n);
	n->type = type;
	return n;
}

struct fs_node *fs_str_new(char *val);
struct fs_node *fs_int_new(int64_t val);
struct fs_node *fs_var_new(char *name, struct fs_node *vargs);
struct fs_node *fs_not_new(struct fs_node *expr);
struct fs_node *fs_return_new(struct fs_node *expr);
struct fs_node *fs_binop_new(struct fs_node *left, char *op, struct fs_node *right);
struct fs_node *fs_assign_new(struct fs_node *lval, char *op, struct fs_node *expr);
struct fs_node *fs_cond_new(struct fs_node *cond,
			    struct fs_node *yes, struct fs_node *no);
struct fs_node *fs_call_new(char *func, struct fs_node *vargs);
struct fs_probespec *fs_probespec_add(struct fs_probespec *prev, char *spec);
struct fs_node *fs_probe_new(struct fs_probespec *spec, struct fs_node *stmts);

#endif	/* __FS_AST_H */
