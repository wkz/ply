/*
 * Copyright  Namhyung Kim <namhyung@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <errno.h>

#include <ply/ply.h>
#include <ply/internal.h>

static int special_sym_alloc(struct ply_probe *pb, struct node *n)
{
	return -ENOENT;
}

static int special_probe(struct ply_probe *pb)
{
	pb->special = 1;
	return 0;
}

struct provider begin_provider = {
	.name = "BEGIN",
	.prog_type = BPF_PROG_TYPE_RAW_TRACEPOINT,

	.probe     = special_probe,
	.sym_alloc = special_sym_alloc,
};

struct provider end_provider = {
	.name = "END",
	.prog_type = BPF_PROG_TYPE_RAW_TRACEPOINT,

	.probe     = special_probe,
	.sym_alloc = special_sym_alloc,
};
