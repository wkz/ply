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

#define _d(_fmt, ...) if (debug) { fprintf(stderr, "DEBUG %s: " _fmt "\n", __func__, ##__VA_ARGS__); }
#define _e(_fmt, ...) fprintf(stderr, "ERROR %s: " _fmt "\n", __func__, ##__VA_ARGS__)
#define _i(_fmt, ...) fprintf(stderr, "INFO %s: " _fmt "\n", __func__, ##__VA_ARGS__)
#define _pe(_fmt, ...) _e("errno:%d " _fmt "\n", errno, ##__VA_ARGS__)

extern int debug;
extern int dump;

char *str_escape(char *str);

int annotate_script(node_t *script);
