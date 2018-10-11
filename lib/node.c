/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <search.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ply/internal.h>
#include "grammar.h"
#include "lexer.h"

void node_print(struct node *n, FILE *fp)
{
	switch (n->ntype) {
	case N_EXPR:
		fprintf(fp, "\e[34m%s\e[0m", n->expr.func);
		break;
	case N_NUM:
		if (n->num.unsignd)
			fprintf(fp, "%"PRIu64, n->num.u64);
		else
			fprintf(fp, "%"PRId64, n->num.s64);
		break;
	case N_STRING:
		fprintf(fp, "\"%s\"", n->string.data);
		break;

	default:
		fputs("<INVALID>", fp);
	}
}

static int node_nloc_valid(struct nloc *nloc)
{
	return nloc->first_line | nloc->first_column |
		nloc->last_line | nloc->last_column;
}

static void node_nloc_print(struct node *n, FILE *fp)
{
	fputs("\e[1m", fp);

	/* TODO: get real filename */
	fprintf(fp, "<input>:");

	if (n->loc.first_line != n->loc.last_line)
		fprintf(fp, "%d-%d:", n->loc.first_line, n->loc.last_line);
	else
		fprintf(fp, "%d:", n->loc.first_line);

	if (n->loc.first_column != n->loc.last_column)
		fprintf(fp, "%d-%d", n->loc.first_column, n->loc.last_column);
	else
		fprintf(fp, "%d", n->loc.first_column);

	fputs("\e[0m", fp);
}

int node_vfprintxf(struct printxf *pxf, FILE *fp, const char *spec, va_list ap)
{
	struct node *n;

	n = va_arg(ap, struct node *);

	if (strchr(spec, '#') && node_nloc_valid(&n->loc)) {
		node_nloc_print(n, fp);
		return 0;
	}

	node_print(n, fp);
	return 0;
}

int node_walk(struct node *n,
	      int (*pre)(struct node *, void *),
	      int (*post)(struct node *, void *),
	      void *ctx)
{
	int err = 0;
	
	if (pre && (err = pre(n, ctx)))
		return err;

	if (n->ntype == N_EXPR) {
		struct node *arg;

		node_expr_foreach(n, arg) {
			err = node_walk(arg, pre, post, ctx);
			if (err)
				return err;
		}
	}

	if (post && (err = post(n, ctx)))
		return err;

	return 0;
}

int node_replace(struct node *n, struct node *new)
{
	new->up = n->up;

	if (n->prev) {
		new->prev = n->prev;
		n->prev->next = new;
	}

	if (n->next) {
		new->next = n->next;
		n->next->prev = new;
	}

	if (new->up
	    && (new->up->ntype == N_EXPR)
	    && (new->up->expr.args == n))
		new->up->expr.args = new;

	/* TODO: don't leak memory */
	return 0;
}

/* helpers */

int node_is(struct node *n, const char *func)
{
	if (!n || (n->ntype != N_EXPR))
		return 0;

	return !strcmp(n->expr.func, func);

}


/* constructors */

static struct node *node_new(enum ntype ntype, const struct nloc *loc)
{
	struct node *n;

	n = xcalloc(1, sizeof(*n));
	n->ntype = ntype;

	if (loc)
		n->loc = *loc;
	return n;
}

void __string_escape(char *dst, const char *src)
{
	while (*src) {
		if (*src == '\\' && *(src + 1)) {
			src++;

			switch (*src) {
			case '\\': *dst++ = '\\'; break;
			case 'n': *dst++ = '\n'; break;
			case 'r': *dst++ = '\r'; break;
			case 't': *dst++ = '\t'; break;
			default: assert(!"TODO"); break;
			}

			src++;
		} else {
			*dst++ = *src++;
		}
	}
}

struct node *node_string(const struct nloc *loc, char *data)
{
	struct node *n = node_new(N_STRING, loc);
	size_t len;

	/* remove quotes */
	if (data[0] == '"') {
		char *unquoted;

		len = strlen(data) - 2;

		unquoted = xcalloc(1, len);
		strncpy(unquoted, data + 1, len);
		free(data);
		data = unquoted;
	}

	len = ((strlen(data) ? : 1) + 7) & ~7;
	n->string.data = xcalloc(1, len);
	__string_escape(n->string.data, data);
	free(data);
	return n;
}

struct node *__node_num(const struct nloc *loc, size_t size,
			int64_t *s64, uint64_t *u64)
{
	struct node *n = node_new(N_NUM, loc);

	if (s64) {
		n->num.s64 = *s64;
	} else {
		n->num.u64 = *u64;
		n->num.unsignd = 1;
	}

	n->num.size = size;
	return n;
}

struct node *node_num(const struct nloc *loc, const char *numstr)
{
	uint64_t u64;
	int64_t s64;

	errno = 0;
	if (numstr[0] == '-') {
		s64 = strtoll(numstr, NULL, 0);
		if (!errno)
			return __node_num(loc, 0, &s64, NULL);
	} else {
		u64 = strtoull(numstr, NULL, 0);
		if (!errno)
			return __node_num(loc, 0, NULL, &u64);
	}

	assert(0);
	return NULL;
}

void node_insert(struct node *prev, struct node *n)
{
	n->up = prev->up;

	n->prev = prev;
	n->next = prev->next;
	prev->next = n;
}

struct node *node_append(struct node *head, struct node *tail)
{
	struct node *last;

	for (last = head; last->next; last = last->next);

	last->next = tail;
	tail->prev = last;
	return head;
	
}

struct node *node_expr_append(const struct nloc *loc,
			      struct node *n, struct node *arg)
{
	struct node *last;
	assert(n->ntype == N_EXPR);

	if (loc)
		n->loc = *loc;

	arg->up = n;

	if (!n->expr.args) {
		n->expr.args = arg;
		return n;
	}

	node_append(n->expr.args, arg);
	return n;
}

struct node *node_expr(const struct nloc *loc, char *func, ...)
{
        va_list ap;
	struct node *n, *arg;

	n = node_new(N_EXPR, loc);

	n->expr.func = func;

        va_start(ap, func);

        while ((arg = va_arg(ap, struct node *)))
		node_expr_append(NULL, n, arg);

        va_end(ap);

	return n;
	
}

struct node *node_expr_ident(const struct nloc *loc, char *func)
{
	struct node *n = node_expr(loc, func, NULL);

	n->expr.ident = 1;
	return n;
}

__attribute__((constructor))
static void node_init(void)
{
	printxf_default.vfprintxf['N'] = node_vfprintxf;
}
