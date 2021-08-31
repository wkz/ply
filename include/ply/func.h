/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef _FUNC_H
#define _FUNC_H

#include <sys/queue.h>

struct node;
struct ply_probe;
struct type;

struct func {
	const char *name;
	struct type *type;

	int static_ret:1; 	/* return type is statically known */

	SLIST_ENTRY(func) entry;

	int (*static_validate)(const struct func *, struct node *);
	int (*type_infer)     (const struct func *, struct node *);
	int (*rewrite)        (const struct func *, struct node *, struct ply_probe *);

	int (*ir_pre) (const struct func *, struct node *, struct ply_probe *);
	int (*ir_post)(const struct func *, struct node *, struct ply_probe *);
};

int func_pass_ir_post(const struct func *func, struct node *n,
		      struct ply_probe *pb);

int func_static_validate(const struct func *func, struct node *n);
struct type *func_return_type(const struct func *func);

#endif	/* _FUNC_H */
