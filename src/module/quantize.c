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

#include <inttypes.h>
#include <stdio.h>

#include <ply/ast.h>
#include <ply/map.h>
#include <ply/module.h>
#include <ply/ply.h>
#include <ply/pvdr.h>

int quantize_compile(node_t *call, prog_t *prog)
{
	node_t *map = call->parent->method.map;

	emit(prog, LDXDW(BPF_REG_0, map->dyn->addr, BPF_REG_10));
	emit(prog, ALU_IMM(BPF_ADD, BPF_REG_0, 1));
	emit(prog, STXDW(BPF_REG_10, map->dyn->addr, BPF_REG_0));
	return 0;
}

static int quantize_normalize(int log2, char const **suffix)
{
	static const char *s[] = { NULL, "k", "M", "G", "T", "P", "Z" };
	int i;

	for (i = 0; log2 >= 10; i++, log2 -= 10);

	*suffix = s[i];
	return (1 << log2);
}

static void quantize_dump_bar(FILE *fp, int64_t count, int64_t max)
{
	static const char bar_open[] = { 0xe2, 0x94, 0xa4 };
	static const char bar_close[] = { 0xe2, 0x94, 0x82 };

	int w = (((float)count / (float)max) * 256.0) + 0.5;
	int space = 32 - ((w +  7) >> 3);
	char block[] = { 0xe2, 0x96, 0x88 };

	fwrite(bar_open, sizeof(bar_open), 1, fp);

	for (; w > 8; w -= 8)
		fwrite(block, sizeof(block), 1, fp);

	if (w) {
		block[2] += 8 - w;
		fwrite(block, sizeof(block), 1, fp);
	}

	fprintf(fp, "%*s", space, "");
	fwrite(bar_close, sizeof(bar_close), 1, fp);
}

static void quantize_dump_bar_ascii(FILE *fp, int64_t count, int64_t max)
{
	int w = (((float)count / (float)max) * 32.0) + 0.5;
	int i;

	fputc('|', fp);

	for (i = 0; i < 32; i++, w--)
		fputc((w > 0) ? '#' : ' ', fp);

	fputc('|', fp);
}

static void quantize_dump_one(FILE *fp, int log2, int64_t count, int64_t max)
{
	int lo, hi;
	const char *ls, *hs;

	switch (log2) {
	case -1:
		fputs("\t         < 0", fp);
		break;
	case 0:
		fputs("\t           0", fp);
		break;
	case 1:
		fputs("\t           1", fp);
		break;
	default:
		lo = quantize_normalize(log2 - 1, &ls);
		hi = quantize_normalize(log2    , &hs);

		/* closed interval for values < 1k, else open ended */
		if (!hs)
			fprintf(fp, "\t[%4d, %4d]", lo, hi - 1);
		else
			fprintf(fp, "\t[%*d%s, %*d%s)",
				ls ? 3 : 4, lo, ls ? : "",
				hs ? 3 : 4, hi, hs ? : "");
	}

	fprintf(fp, "\t%8" PRId64" ", count);
	if (G.ascii)
		quantize_dump_bar_ascii(fp, count, max);
	else
		quantize_dump_bar(fp, count, max);
	fputc('\n', fp);
}

static void quantize_dump_seg(FILE *fp, node_t *map,
			      void *data, int len, int64_t max)
{
	node_t *rec = map->map.rec;
	size_t entry_size = rec->dyn->size + map->dyn->size;
	size_t rec_size = rec->dyn->size - sizeof(int64_t);
	char *key = data;
	int64_t *log2 = data + rec_size, *count = data + rec->dyn->size;

	dump_rec(fp, rec, data, rec->rec.n_vargs - 1);
	fputc('\n', fp);

	for (; len > 1; len--) {
		int last_log2 = *log2 + 1;

		quantize_dump_one(fp, *log2, *count, max);

		key += entry_size;
		log2 = (void *)log2 + entry_size;
		count = (void *)count + entry_size;

		for (; last_log2 < *log2; last_log2++)
			quantize_dump_one(fp, last_log2, 0, max);
	}

	quantize_dump_one(fp, *log2, *count, max);
}

static void quantize_dump(FILE *fp, node_t *map, void *data, int len)
{
	node_t *rec = map->map.rec;
	size_t entry_size = rec->dyn->size + map->dyn->size;
	size_t rec_size = rec->dyn->size - sizeof(int64_t);
	char *key = data, *seg_start = data;
	int64_t *count = data + rec->dyn->size;
	int64_t seg_max = *count;
	int seg_len = 1;

	for (; len > 1; len--) {
		key += entry_size;
		count = (void *)count + entry_size;

		if (!memcmp(key, seg_start, rec_size)) {
			seg_max = (*count > seg_max) ? *count : seg_max;
			seg_len++;
		} else {
			quantize_dump_seg(fp, map, seg_start, seg_len, seg_max);
			seg_max = *count;
			seg_len = 1;
			seg_start = key;
		}
	}

	quantize_dump_seg(fp, map, seg_start, seg_len, seg_max);
}

int quantize_loc_assign(node_t *call)
{
	node_t *map = call->parent->method.map;

	map->dyn->map.dump = quantize_dump;
	return default_loc_assign(call);
}

int quantize_annotate(node_t *call)
{
	pvdr_t *pvdr = node_get_probe(call)->dyn->probe.pvdr;
	node_t *map = call->parent->method.map;
	node_t *c;
	int err;

	if (!call->call.vargs ||
	    (call->call.vargs->dyn->type != TYPE_NONE &&
	     call->call.vargs->dyn->type != TYPE_INT) ||
	    call->call.vargs->next ||
	    call->parent->type != TYPE_METHOD)
		return -EINVAL;

	for (c = map->map.rec->rec.vargs; c->next; c = c->next);

	/* rewrite @map[c1, c2].quantize(some_int)
	 * into    @map[c1, c2, common.log2(some_int)].quantize()
	 *
	 * This means we only have to retrieve one bucket (8 bytes) to
	 * do an update. Storing all buckets in the value would
	 * require loading 65*8=520 bytes per update.
	 */
	c->next = node_call_new(strdup("common"), strdup("log2"),
				call->call.vargs);
	c->next->parent = map->map.rec;

	c = c->next;

	err = pvdr->resolve(c, &c->dyn->call.func);
	if (err)
		return err;

	err = c->dyn->call.func->annotate(c);
	if (err)
		return err;

	map->map.rec->rec.n_vargs++;
	call->call.vargs = NULL;

	call->dyn->type = TYPE_INT;
	call->dyn->size = sizeof(int64_t);
	return 0;
}

const func_t quantize_func = {
	.name = "quantize",

	.compile = quantize_compile,
	.loc_assign = quantize_loc_assign,
	.annotate = quantize_annotate,
};
