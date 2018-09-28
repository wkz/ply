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

#ifndef _PLY_UTILS_H
#define _PLY_UTILS_H

#include <assert.h>

int isstring(const char *data, size_t len);

FILE *fopenf(const char *mode, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));

void ast_fprint(FILE *fp, struct node *root);

#include "printxf.h"

#ifdef DEBUG
#define _l(_prefix, _fmt, ...)					\
	fprintxf(NULL, stderr, "\e[2m%s:%d\e[0m " _prefix _fmt,		\
		 __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define _l(_prefix, _fmt, ...)					\
	fprintxf(NULL, stderr, _prefix _fmt, ##__VA_ARGS__)
#endif

#ifdef DEBUG
#define _d(fmt, ...) _l("debug: ", fmt, ##__VA_ARGS__)
#else
#define _d(fmt, ...)
#endif

#define _i(fmt, ...) _l("info: ",    fmt, ##__VA_ARGS__)
#define _w(fmt, ...) _l("warning: ", fmt, ##__VA_ARGS__)
#define _e(fmt, ...) _l("error: ",   fmt, ##__VA_ARGS__)

#define _ne(_n, fmt, ...) _l("%#N: \e[31merror:\e[0m ", fmt, _n, ##__VA_ARGS__)


#define container_of(ptr, type, member) ({			     \
                const typeof( ((type *)0)->member ) *__mptr = (ptr); \
                (type *)( (char *)__mptr - offsetof(type,member) );})

static inline void *xcalloc(size_t nmemb, size_t size)
{
	void *mem = calloc(nmemb, size);

	assert(mem);
	return mem;
}

#endif	/* _PLY_UTILS_H */
