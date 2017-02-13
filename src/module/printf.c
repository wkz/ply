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
#include <ply/evpipe.h>
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

static int printf_event(event_t *ev, void *_call)
{
	node_t *arg, *call = _call;
	char *fmt, *spec;
	void *data = ev->data;

	arg  = call->call.vargs->next->rec.vargs->next;
	for (fmt = call->call.vargs->string; *fmt; fmt++) {
		if (*fmt == '%' && arg) {
			spec = fmt;
			fmt = strpbrk(spec, "cdiopsuxX");
			if (!fmt)
				break;

			printf_spec(spec, fmt, data);
			data += arg->dyn->size;
			arg = arg->next;
		} else {
			fputc(*fmt, stdout);
		}
	}

	return 0;
}

int printf_compile(node_t *call, prog_t *prog)
{
	node_t *script = node_get_script(call);
	node_t *rec = call->call.vargs->next;

	emit(prog, CALL(BPF_FUNC_get_smp_processor_id));
	emit(prog, MOV(BPF_REG_3, BPF_REG_0));

	emit(prog, MOV(BPF_REG_1, BPF_REG_9));
	emit_ld_mapfd(prog, BPF_REG_2, script->dyn->script.evp->mapfd);

	emit(prog, MOV(BPF_REG_4, BPF_REG_10));
	emit(prog, ALU_IMM(BPF_ADD, BPF_REG_4, rec->dyn->addr));

	emit(prog, MOV_IMM(BPF_REG_5, rec->dyn->size));
	emit(prog, CALL(BPF_FUNC_perf_event_output));
	return 0;
}

int printf_loc_assign(node_t *call)
{
	node_t *probe = node_get_probe(call);
	node_t *varg = call->call.vargs;
	node_t *rec  = varg->next;

	/* no need to store any format strings in the kernel, we can
	 * fetch them from the AST, just store a format id instead. */
	varg->dyn->loc = LOC_VIRTUAL;

	/* rec_max_size  = printf_rec_size(probe->parent); */
	rec->dyn->loc  = LOC_STACK;
	rec->dyn->addr = node_probe_stack_get(probe, rec->dyn->size);//_max_size);
	return 0;
}

int printf_annotate(node_t *call)
{
	evhandler_t *evh;
	node_t *meta, *rec, *varg;

	varg = call->call.vargs;
	if (!varg) {
		_e("format string missing from %s", node_str(call));
		return -EINVAL;
	}

	if (varg->type != TYPE_STR) {
		_e("first arguement to %s must be string literal", node_str(call));
		return -EINVAL;
	}

	evh = calloc(1, sizeof(*evh));
	assert(evh);

	evh->priv = call;
	evh->handle = printf_event;
	evhandler_register(evh);

	/* rewrite printf("a:%d b:%d", a(), b())
         *    into printf("a:%d b:%d", [event_type, a(), b()])
	 */
	meta = node_int_new(evh->type);
	meta->dyn->type = TYPE_INT;
	meta->dyn->size = 8;
	meta->next = varg->next;
	rec = node_rec_new(meta);
	varg->next = rec;

	rec->parent = call;
	node_foreach(varg, rec->rec.vargs) {
		varg->parent = rec;
	}
	return 0;
}

const func_t printf_func = {
	.name = "printf",

	.compile = printf_compile,
	.loc_assign = printf_loc_assign,
	.annotate = printf_annotate,
};
