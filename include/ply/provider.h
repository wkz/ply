/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef _PROVIDER_H
#define _PROVIDER_H

#include <linux/bpf.h>

struct ply;
struct ply_probe;
struct node;

struct provider {
	const char *name;
	enum bpf_prog_type prog_type;

	int (*probe)    (struct ply_probe *);
	int (*sym_alloc)(struct ply_probe *, struct node *);
	int (*ir_pre)   (struct ply_probe *);
	int (*ir_post)  (struct ply_probe *);
	int (*attach)   (struct ply_probe *);
	int (*detach)   (struct ply_probe *);
};

struct provider *provider_get(const char *name);

#define __ply_provider __attribute__((		\
     section("providers"),			\
     aligned(__alignof__(struct provider))	\
))

extern struct provider __start_providers;
extern struct provider __stop_providers;

#endif	/* _PROVIDER_H */
