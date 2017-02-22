/*
 * Copyright 2015-2017 Tobias Waldekranz <tobias@waldekranz.com>
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

#ifndef _MODULE_H
#define _MODULE_H

#include <ply/ast.h>
#include <ply/compile.h>

typedef struct func func_t;

struct func {
	const char   *name;
	const func_t *alias;

	int (*annotate)  (node_t *call);
	int (*loc_assign)(node_t *call);
	int (*compile)   (node_t *call,  prog_t *prog);

	void *priv;
};

#define MODULE_FUNC_ALIAS(_mod, _name, _real)			\
	static func_t _mod ## _ ## _name ## _func = {		\
		.name  = #_name,				\
		.alias = &_mod ## _ ## _real ## _func,		\
	}

#define MODULE_FUNC(_mod, _name)				\
	static func_t _mod ## _ ## _name ## _func = {		\
		.name = #_name,					\
		.annotate   = _mod ## _ ## _name ## _annotate,	\
		.loc_assign = default_loc_assign,		\
		.compile    = _mod ## _ ## _name ## _compile,	\
	}

#define MODULE_FUNC_LOC(_mod, _name)					\
	static func_t _mod ## _ ## _name ## _func = {			\
		.name = #_name,						\
		.annotate   = _mod ## _ ## _name ## _annotate,		\
		.loc_assign = _mod ## _ ## _name ## _loc_assign,	\
		.compile    = _mod ## _ ## _name ## _compile,		\
	}

typedef struct module module_t;

struct module {
	const char *name;

	int (*get_func)(const module_t *m, node_t *call, const func_t **f);
};

int default_loc_assign(node_t *call);
int generic_get_func(const func_t **fs, node_t *call, const func_t **f);

int module_get_func(const module_t *m, node_t *call, const func_t **f);
int modules_get_func(const module_t **ms, node_t *call, const func_t **f);

extern module_t method_module;
extern module_t common_module;

extern module_t kprobe_module;
extern module_t kretprobe_module;
extern module_t trace_module;

#endif	/* _MODULE_H */
