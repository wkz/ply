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

#include <errno.h>
#include <stdio.h>

#include "lang/ast.h"

#define MAP_LEN 512

#define PRINTF_BUF_LEN MAP_LEN
#define PRINTF_META_OF (1 << 30)

#define _d(_fmt, ...)							\
	if (G.debug) {							\
		fprintf(stderr, "dbg %-20s: " _fmt "\n", __func__,	\
			##__VA_ARGS__);					\
	}

#define _D(_fmt, ...)							\
	if (G.dump) {							\
		fprintf(stderr, "dmp %-20s: " _fmt "\n", __func__,	\
			##__VA_ARGS__);					\
	}

#define _e(_fmt, ...) \
	fprintf(stderr, "ERR %-20s: " _fmt "\n", __func__, ##__VA_ARGS__)
#define _eno(_fmt, ...) \
	fprintf(stderr, "ERR %-20s: " _fmt " : %m\n", __func__, ##__VA_ARGS__)
#define _w(_fmt, ...) \
	fprintf(stderr, "WRN %-20s: " _fmt "\n", __func__, ##__VA_ARGS__)
#define _i(_fmt, ...) \
	fprintf(stderr, "nfo %-20s: " _fmt "\n", __func__, ##__VA_ARGS__)

struct globals {
	int ascii:1;
	int debug:1;
	int dump:1;
	int timeout;
};
extern struct globals G;

char *str_escape(char *str);

int annotate_script(node_t *script);
