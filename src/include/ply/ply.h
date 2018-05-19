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

#ifndef _PLY_H
#define _PLY_H

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>

#include <ply/kallsyms.h>
#include <ply/ast.h>

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
	pid_t self;

	size_t map_nelem;

	ksyms_t *ksyms;
};
extern struct globals G;

char *str_escape(char *str);

int annotate_script(node_t *script);


static inline FILE *fopenf(const char *mode, const char *fmt, ...)
{
	char path[0x100];
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vsnprintf(path, sizeof(path), fmt, ap);
	va_end(ap);

	if (ret < 0 || ret >= sizeof(path))
		return NULL;

	return fopen(path, mode);
}

#endif	/* _PLY_H */
