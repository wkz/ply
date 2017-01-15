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

#include <inttypes.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <ply/ast.h>
#include <ply/bpf-syscall.h>
#include <ply/compile.h>
#include <ply/module.h>
#include <ply/ply.h>

static void printf_spec(const char *spec, const char *term, void *data)
{
	int64_t *num = data;
	char strfmt[16];
	size_t fmt_len;
	/* TODO: flags/length/precision is only handled on strings for
	 * now */
	switch (*term) {
	case 's':
		fmt_len = term - spec + 1;
		if (fmt_len >= sizeof(strfmt)) {
			printf("%s", (char *)data);
			break;
		}
		strncpy(strfmt, spec, fmt_len);
		strfmt[fmt_len] = '\0';
#pragma GCC diagnostic ignored "-Wformat-security"
		printf(strfmt, (char *)data);
#pragma GCC diagnostic pop
		break;
	case 'c':
		printf("%c", (char)*num);
		break;
	case 'i':
	case 'd':
		printf("%" PRId64, *num);
		break;
	case 'o':
		printf("%" PRIo64, *num);
		break;
	case 'p':
		printf("<%" PRIx64 ">", *num);
		break;
	case 'u':
		printf("%" PRIu64, *num);
		break;
	case 'x':
		printf("%" PRIx64, *num);
		break;
	case 'X':
		printf("%" PRIX64, *num);
		break;
	}
}

static void printf_output(node_t *script, void *rec)
{
	node_t *call, *arg;
	int64_t *meta;
	size_t offs;
	char *fmt, *spec;

	meta = rec;
	if (*meta & PRINTF_META_OF) {
		_e("buffer overrun");
	}

	*meta &= 0xffff;
	call = script->dyn.script.printf[*meta];
	if (!call)
		return;

	arg  = call->call.vargs->next->rec.vargs->next;
	offs = sizeof(*meta);
	for (fmt = call->call.vargs->string; *fmt; fmt++) {
		if (*fmt == '%' && arg) {
			spec = fmt;
			fmt = strpbrk(spec, "cdiopsuxX");
			if (!fmt)
				break;

			printf_spec(spec, fmt, rec + offs);
			offs += arg->dyn.size;
			arg = arg->next;
		} else {
			fputc(*fmt, stdout);
		}
	}
}

void printf_drain(node_t *script)
{
	node_t *call, *rec;
	mdyn_t *mdyn;
	int64_t key;
	char *val;
	int err;

	for (mdyn = script->dyn.script.mdyns; mdyn; mdyn = mdyn->next)
		if (!strcmp(mdyn->map->string, "printf"))
			break;

	if (!mdyn) {
		poll(NULL, 0, -1);
		return;
	}

	call = mdyn->map;
	rec  = call->call.vargs->next;
	val  = malloc(rec->dyn.size);

	for (key = 0;;) {
		err = bpf_map_lookup(mdyn->mapfd, &key, val);
		if (err) {
			err = usleep(200000);
			if (err)
				break;
		} else {
			printf_output(script, val);
			bpf_map_delete(mdyn->mapfd, &key);
			key++;
			if (key >= (PRINTF_BUF_LEN - 1))
				key = 0;
		}
	}
}


int printf_compile(node_t *call, prog_t *prog)
{
	node_t *rec = call->call.vargs->next;
	int map_fd = node_map_get_fd(call);

	if (call->dyn.size > sizeof(int64_t)) {
		size_t diff = call->dyn.size - sizeof(int64_t);
		ssize_t addr = rec->dyn.addr + rec->dyn.size;

		emit(prog, MOV_IMM(BPF_REG_0, 0));
		for (; diff; addr += sizeof(int64_t), diff -= sizeof(int64_t))
			emit(prog, STXDW(BPF_REG_10, addr, BPF_REG_0));
	}
		
	/* lookup index into print buffer, stored out-of-band after
	 * the last entry */
	emit(prog, MOV_IMM(BPF_REG_0, PRINTF_BUF_LEN - 1));
	emit(prog, STXDW(BPF_REG_10, call->dyn.addr, BPF_REG_0));
	emit_map_lookup_raw(prog, map_fd, call->dyn.addr);

	/* if we get a null pointer, index is 0 */
	emit(prog, JMP_IMM(JMP_JNE, BPF_REG_0, 0, 2));
	emit(prog, STXDW(BPF_REG_10, call->dyn.addr, BPF_REG_0));
	emit(prog, JMP_IMM(JMP_JA, 0, 0, 5));

	/* otherwise, get it from the out-of-band value */
	emit_read_raw(prog, call->dyn.addr, BPF_REG_0, sizeof(int64_t));

	/* at this point call->dyn.addr is loaded with the index of
	 * the buffer */
	emit_map_lookup_raw(prog, map_fd, call->dyn.addr);

	/* lookup SHOULD return NULL, otherwise user-space has not
	 * been able to empty the buffer in time. */
	emit(prog, JMP_IMM(JMP_JEQ, BPF_REG_0, 0, 3));

	/* mark record with the overflow bit so that user-space at
	 * least knows when data has been lost */
	emit(prog, LDXDW(BPF_REG_0, rec->rec.vargs->dyn.addr, BPF_REG_10));
	emit(prog, ALU_IMM(ALU_OP_OR, BPF_REG_0, PRINTF_META_OF));
	emit(prog, STXDW(BPF_REG_10, rec->rec.vargs->dyn.addr, BPF_REG_0));

	/* store record */
	emit_map_update_raw(prog, map_fd, call->dyn.addr, rec->dyn.addr);

	/* calculate next index and store that in the record */
	emit(prog, LDXDW(BPF_REG_0, call->dyn.addr, BPF_REG_10));
	emit(prog, ALU_IMM(ALU_OP_ADD, BPF_REG_0, 1));
	emit(prog, JMP_IMM(JMP_JNE, BPF_REG_0, PRINTF_BUF_LEN - 1, 1));
	emit(prog, MOV_IMM(BPF_REG_0, 0));
	emit(prog, STXDW(BPF_REG_10, rec->rec.vargs->dyn.addr, BPF_REG_0));

	/* store next index */
	emit(prog, MOV_IMM(BPF_REG_0, PRINTF_BUF_LEN - 1));
	emit(prog, STXDW(BPF_REG_10, call->dyn.addr, BPF_REG_0));
	emit_map_update_raw(prog, map_fd, call->dyn.addr, rec->dyn.addr);
	return 0;
}

static int printf_walk(node_t *n, void *_mdyn)
{
	mdyn_t *mdyn = _mdyn;
	size_t largest, new;

	if (n->type != TYPE_CALL || strcmp(n->string, "printf"))
		return 0;

	if (!mdyn->map)
		mdyn->map = n;
	else {
		/* printf records can be of different sizes, store
		 * pointer to the printf call with the largest record
		 * so that all will fit. */
		largest = mdyn->map->call.vargs->next->dyn.size;
		new = n->call.vargs->next->dyn.size;

		if (new > largest)
			mdyn->map = n;
	}

	return 0;
}

static mdyn_t *printf_store_mdyn(node_t *script)
{
	mdyn_t *mdyn;

	mdyn = calloc(1, sizeof(*mdyn));
	assert(mdyn);

	mdyn->type = BPF_MAP_TYPE_HASH;
	node_walk(script, NULL, printf_walk, mdyn);

	node_script_mdyn_add(script, mdyn);
	return mdyn;
}

static size_t printf_rec_size(node_t *script)
{
	mdyn_t *mdyn;

	mdyn = node_map_get_mdyn(script->dyn.script.printf[0]);
	if (!mdyn)
		mdyn = printf_store_mdyn(script);

	return mdyn->map->call.vargs->next->dyn.size;
}

int printf_loc_assign(node_t *call)
{
	node_t *probe = node_get_probe(call);
	node_t *varg = call->call.vargs;
	node_t *rec  = varg->next;
	/* ssize_t addr; */
	size_t rec_max_size;

	/* no need to store any format strings in the kernel, we can
	 * fetch them from the AST, just store a format id instead. */
	varg->dyn.loc = LOC_VIRTUAL;

	rec_max_size  = printf_rec_size(probe->parent);
	rec->dyn.loc  = LOC_STACK;
	rec->dyn.addr = node_probe_stack_get(probe, rec_max_size);

	/* allocate storage for printf's map key */
	call->dyn.size = rec_max_size + sizeof(int64_t) - rec->dyn.size;
	call->dyn.addr = node_probe_stack_get(probe, call->dyn.size);
	return 0;
}

int printf_annotate(node_t *call)
{
	node_t *script = node_get_script(call);
	node_t *varg = call->call.vargs;
	node_t *meta, *rec;

	if (!varg) {
		_e("format string missing from %s", node_str(call));
		return -EINVAL;
	}

	if (varg->type != TYPE_STR) {
		_e("first arguement to %s must be literal string", node_str(call));
		return -EINVAL;
	}

	/* rewrite printf("a:%d b:%d", a(), b())
         *    into printf("a:%d b:%d", [meta, a(), b()])
	 */
	meta = node_int_new(script->dyn.script.fmt_id++);
	meta->dyn.type = TYPE_INT;
	meta->dyn.size = 8;
	meta->next = varg->next;
	rec = node_rec_new(meta);
	varg->next = rec;

	rec->parent = call;
	node_foreach(varg, rec->rec.vargs) {
		varg->parent = rec;
	}

	script->dyn.script.printf[meta->integer] = call;
	return 0;
}

const func_t printf_func = {
	.name = "printf",

	.compile = printf_compile,
	.loc_assign = printf_loc_assign,
	.annotate = printf_annotate,
};
