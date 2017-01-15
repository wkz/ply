#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <ply/ast.h>
#include <ply/map.h>
#include <ply/module.h>
#include <ply/ply.h>

struct trace_field {
	type_t type;
	size_t nmemb;
	size_t offset;
	size_t size;

	/* we only use one bit here, but it simplifies the parser if
	 * we use the same datatype. */
	size_t sign;
};

static int trace_field_compile(node_t *call, prog_t *prog)
{
	struct trace_field *tf = call->dyn.call.func->priv;
	size_t offset = tf->offset;
	size_t membsz = (tf->size / tf->nmemb);

	if (call->call.vargs)
		offset += membsz * call->call.vargs->integer;

	emit_stack_zero(prog, call);

	emit(prog, MOV(BPF_REG_1, BPF_REG_10));
	emit(prog, ALU_IMM(ALU_OP_ADD, BPF_REG_1, call->dyn.addr));
	emit(prog, MOV_IMM(BPF_REG_2, membsz));
	emit(prog, MOV(BPF_REG_3, BPF_REG_9));
	emit(prog, ALU_IMM(ALU_OP_ADD, BPF_REG_3, offset));
	emit(prog, CALL(BPF_FUNC_probe_read));

	if (call->dyn.loc == LOC_REG) {
		dyn_t src;

		src = call->dyn;
		src.loc = LOC_STACK;
		return emit_xfer_dyns(prog, &call->dyn, &src);
	}

	return 0;
}

static int trace_field_annotate(node_t *call)
{
	struct trace_field *tf = call->dyn.call.func->priv;
	node_t *arg = call->call.vargs;
	intptr_t reg;

	/* accept no argument for non-arrays and exactly one integer
	 * index for arrays */
	if ((tf->nmemb == 1 && arg) ||
	    (tf->nmemb != 1 && (!arg || arg->next || arg->type != TYPE_INT)))
	    return -EINVAL;

	call->dyn.type = tf->type;

	if (tf->type == TYPE_STR)
		call->dyn.size = tf->size;
	else
		call->dyn.size = 8;

	return 0;
}

static int trace_field_parse_tok(const char *expect, size_t *val)
{
	char *tok = strtok(NULL, ";");

	while (*tok && (*tok == ' ' || *tok == '\t'))
		tok++;
	
	_d("%s", tok);
	if (strncmp(tok, expect, strlen(expect)))
		return -EINVAL;

	*val = strtoul(tok + strlen(expect), NULL, 0);
	if (*val == ULONG_MAX)
		return -EINVAL;

	return 0;
}

static int trace_field_parse(char *line, const char *name,
			     struct trace_field *tf)
{
	char *p, *tok;
	int err;

	tok = strtok(&line[1], ";");
	if (!tok)
		return -EINVAL;

	while (*tok && (*tok == ' ' || *tok == '\t'))
		tok++;

	if (strncmp(tok, "field:", 6))
		return -EINVAL;

	tok+=6;

	tf->type  = TYPE_INT;
	tf->nmemb = 1;

	p = strchr(tok, '[');
	if (p) {
		*(p++) = '\0';

		if (!strncmp(tok, "char ", 5)) {
			tf->type = TYPE_STR;
			tf->nmemb = 1;
		} else {
			tf->nmemb = strtoul(p, NULL, 0);
			if (tf->nmemb == ULONG_MAX)
				return -EINVAL;
		}
	}

	tok = rindex(tok, ' ');
	if (!tok)
		return -EINVAL;

	tok++;
	if (strcmp(tok, name))
		return -ENOENT;

	err =         trace_field_parse_tok("offset:", &tf->offset);
	err = err ? : trace_field_parse_tok("size:", &tf->size);
	err = err ? : trace_field_parse_tok("signed:", &tf->sign);

	_d("%d", err);
	return err;
}

static struct trace_field *trace_field_get(node_t *call)
{
	node_t *probe = node_get_probe(call);
	struct trace_field *tf;
	const char *path;
	char line[0x80];
	FILE *fp;
	int err;

	path = strchr(probe->string, ':') + 1;
	fp = fopenf("r", "/sys/kernel/debug/tracing/events/%s/format", path);
	if (!fp)
		return NULL;

	tf = calloc(1, sizeof(*tf));
	if (!tf)
		goto out;

	while (fgets(line, sizeof(line), fp)) {
		err = trace_field_parse(line, call->string, tf);
		if (!err) {
			fclose(fp);
			return tf;
		}
	}

out:
	fclose(fp);
	return NULL;
}

int trace_get_func(const module_t *m, node_t *call, const func_t **out)
{
	struct trace_field *tf;
	func_t *f;

	tf = trace_field_get(call);
	if (!tf)
		return -ENOENT;

	/* TODO this func_t and associated trace_field is leaked */
	f = calloc(1, sizeof(*f));
	f->name       = call->string;
	f->priv       = tf;
	f->annotate   = trace_field_annotate;
	f->loc_assign = default_loc_assign;
	f->compile    = trace_field_compile;
	*out = f;
	return 0;
}

module_t trace_module = {
	.name = "trace",
	.get_func = trace_get_func,
};
