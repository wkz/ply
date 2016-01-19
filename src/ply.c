#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>

#include <asm/ptrace.h>

#include "ply.h"
#include "bpf-syscall.h"
#include "compile.h"
#include "lang/ast.h"
#include "lang/parse.h"
#include "lang/lex.h"
#include "pvdr/pvdr.h"


struct pt_regs regs;

FILE *scriptfp;
int dump = 0;

node_t *script_parse(FILE *fp)
{
	node_t *script = NULL;
	yyscan_t scanner;
	
	if (yylex_init(&scanner))
		return NULL;

	yyset_in(fp, scanner);
	yyparse(&script, scanner);
 
	yylex_destroy(scanner); 
	return script;
}

static const char *sopts = "Df:";
static struct option lopts[] = {
	{ "debug", no_argument,       0, 'D' },
	{ "file",  required_argument, 0, 'f' },

	{ NULL }
};

int parse_opts(int argc, char **argv)
{
	int opt;

	while ((opt = getopt_long(argc, argv, sopts, lopts, NULL)) > 0) {
		switch (opt) {
		case 'D':
			dump++;
			break;
		case 'f':
			scriptfp = fopen(optarg, "r");
			if (!scriptfp) {
				_e("unable to open '%s'", optarg);
				return -EIO;
			}
			break;
		default:
			_e("unknown option '%c'", opt);
			return -EINVAL;
		}
	}

	return 0;
}

int map_setup(node_t *script)
{
	mdyn_t *mdyn;
	int dumpfd = 0xfd00;

	for (mdyn = script->script.mdyns; mdyn; mdyn = mdyn->next) {
		if (dump)
			mdyn->mapfd = dumpfd++;
		else
			mdyn->mapfd = bpf_map_create(BPF_MAP_TYPE_HASH,
						     mdyn->map->map.rec->dyn.size,
						     mdyn->map->dyn.size, 1024);

		_d("created map with fd %#x(%d)\n", mdyn->mapfd, errno);
		if (mdyn->mapfd <= 0)
			return mdyn->mapfd;
	}

	return 0;
}

void map_dump(mdyn_t *mdyn)
{
	node_t *map = mdyn->map, *rec = map->map.rec, *varg = rec->rec.vargs;
	char *key = calloc(1, rec->dyn.size), *val = malloc(map->dyn.size);
	int err;

	printf("\n%s:\n", map->string);
	
	for (err = bpf_map_next(mdyn->mapfd, key, key); !err;
	     err = bpf_map_next(mdyn->mapfd, key, key)) {
		err = bpf_map_lookup(mdyn->mapfd, key, val);
		if (err)
			return;

		switch (varg->dyn.type) {
		case TYPE_INT:
			printf("  %-20" PRId64, *((int64_t *)key));
			break;
		case TYPE_STR:
			printf("  %-*.*s", (int)varg->dyn.size, (int)varg->dyn.size, key);
			break;
		default:
			err = -EINVAL;
			continue;
		}

		switch (map->dyn.type) {
		case TYPE_INT:
			printf("  %-20" PRId64 "\n", *((int64_t *)val));
			break;
		case TYPE_STR:
			printf("  %-*.*s\n", (int)map->dyn.size, (int)map->dyn.size, val);
			break;
		default:
			err = -EINVAL;
			continue;
		}
	}
}

int map_teardown(node_t *script)
{
	mdyn_t *mdyn;

	if (dump)
		return 0;

	for (mdyn = script->script.mdyns; mdyn; mdyn = mdyn->next) {
		if (mdyn->mapfd) {
			map_dump(mdyn);
			close(mdyn->mapfd);
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	node_t *script;
	prog_t *prog;
	int err = 0;

	scriptfp = stdin;
	err = parse_opts(argc, argv);
	if (err)
		goto err;

	script = script_parse(scriptfp);
	if (!script) {
		err = -EINVAL;
		goto err;
	}

	err = pvdr_resolve(script);
	if (err)
		goto err_free_script;

	err = annotate_script(script);
	if (err)
		goto err_free_script;

	err = map_setup(script);
	if (err)
		goto err_free_script;
		
	if (dump)
		node_ast_dump(script);

	prog = compile_probe(script->script.probes);
	if (!prog) {
		err = -EINVAL;
		goto err_free_script;
	}

	_d("compilation ok");
	if (dump)
		goto done;

	err = node_get_pvdr(script->script.probes)->setup(script->script.probes, prog);
	if (err)
		goto err_free_prog;

	system("echo 1 >/sys/kernel/debug/tracing/events/kprobes/enable");
	system("echo 1 >/sys/kernel/debug/tracing/tracing_on");
	system("cat /sys/kernel/debug/tracing/trace_pipe");
	system("echo 0 >/sys/kernel/debug/tracing/tracing_on");
	system("echo 0 >/sys/kernel/debug/tracing/events/kprobes/enable");

	/* err = node_get_pvdr(script->script.probes)->teardown(script->script.probes, prog); */
	/* if (err) */
	/* 	goto err_free_ebpf; */

	map_teardown(script);

done:
err_free_prog:
	free(prog);
err_free_script:
	node_free(script);
err:
	return err;
}
