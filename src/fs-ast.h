#ifndef __FS_AST_H
#define __FS_AST_H


struct fs_script {
	struct fs_node *probes;
};

struct fs_probespec {
	void *next, *prev;
	char *spec;
};

struct fs_probe {
	struct fs_probespec *spec;
	struct fs_node *stmts;
};

enum fs_type {
	FS_SCRIPT,
	FS_PROBE,
	FS_STMT,
	FS_EXPR,
	FS_ASSIGN,
};

struct fs_node {
	void *next, *prev;

	enum fs_type type;

	union {
		struct fs_script script;
		struct fs_probe  probe;
		/* fs_stmt_t   stmt; */
		/* fs_expr_t   expr; */
		/* fs_assign_t assign; */
	};
};
	
void fs_ast_dump(struct fs_node *n);

#endif	/* __FS_AST_H */
