#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>

#include "dtl.h"
#include "lang/ast.h"
#include "lang/parse.h"
#include "lang/lex.h"
#include "fs-ebpf.h"

#include "libbpf.h"
#include "provider/provider.h"

FILE *scriptfp;
int dump = 0;

node_t *fs_load(FILE *fp)
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
	dyn_t *dyn;
	int dumpfd = 0xfd00;

	for (dyn = script->script.dyns; dyn; dyn = dyn->next) {
		if (!dyn->ksize)
			continue;

		if (dump)
			dyn->mapfd = dumpfd++;
		else
			dyn->mapfd = bpf_map_create(BPF_MAP_TYPE_HASH,
						    dyn->ksize, dyn->size, 1024);

		_d("created map with fd %d(%d)\n", dyn->mapfd, errno);
		if (dyn->mapfd <= 0)
			return dyn->mapfd;

	}

	return 0;
}

void map_dump(dyn_t *dyn)
{
	node_t *k = dyn->node->map.vargs;
	char *key = calloc(1, dyn->ksize), *val = malloc(dyn->size);
	int err;

	printf("%s:\n", dyn->node->string);
	
	for (err = bpf_map_next(dyn->mapfd, key, key); !err;
	     err = bpf_map_next(dyn->mapfd, key, key)) {
		err = bpf_map_lookup(dyn->mapfd, key, val);
		if (err)
			return;

		switch (k->dyn->type) {
		case TYPE_INT:
			printf("  %-20" PRId64, *((int64_t *)key));
			break;
		case TYPE_STR:
			printf("  %-*.*s", (int)k->dyn->size, (int)k->dyn->size, key);
			break;
		default:
			err = -EINVAL;
			continue;
		}

		switch (dyn->type) {
		case TYPE_INT:
			printf("  %-20" PRId64 "\n", *((int64_t *)val));
			break;
		case TYPE_STR:
			printf("  %-*.*s\n", (int)dyn->size, (int)dyn->size, val);
			break;
		default:
			err = -EINVAL;
			continue;
		}		
	}
}

int map_teardown(node_t *script)
{
	dyn_t *dyn;

	if (dump)
		return 0;

	for (dyn = script->script.dyns; dyn; dyn = dyn->next) {
		if (dyn->mapfd) {
			map_dump(dyn);
			close(dyn->mapfd);
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	node_t *script, *p;
	struct provider *provider;
	struct ebpf *e;
	int err = 0;

	scriptfp = stdin;
	err = parse_opts(argc, argv);
	if (err)
		goto err;

	script = fs_load(scriptfp);
	if (!script) {
		err = -EINVAL;
		goto err;
	}

	p = script->script.probes;

	provider = provider_find(p->string);
	if (!provider) {
		_e("no provider for \"%s\"", p->string);
		err = -ENOENT;
		goto err_free_script;
	}

	err = script_annotate(script, provider);
	if (err) {
		_e("annotation error");
		err = -EINVAL;
		goto err_free_script;
	}

	err = map_setup(script);
	if (err) {
		_e("unable to allocate maps");
		goto err_free_script;
	}
		
	if (dump)
		node_ast_dump(script);

	e = node_compile(p, provider);
	if (!e) {
		_e("compilation error");
		err = -EINVAL;
		goto err_free_script;
	}

	_d("compilation ok");

	if (dump) {
		FILE *fp = fopen("/tmp/dtl.bin", "w");
		fwrite(e->prog, sizeof(e->prog[0]), e->ip - &e->prog[0], fp);
		fclose(fp);
		goto done;
	}

	err = provider->setup(provider, e, p);
	if (err)
		goto err_free_ebpf;

	system("echo 1 >/sys/kernel/debug/tracing/events/kprobes/enable");
	system("echo 1 >/sys/kernel/debug/tracing/tracing_on");
	system("cat /sys/kernel/debug/tracing/trace_pipe");
	system("echo 0 >/sys/kernel/debug/tracing/tracing_on");
	system("echo 0 >/sys/kernel/debug/tracing/events/kprobes/enable");

	/* err = provider->teardown(provider, p, e); */
	/* if (err) */
	/* 	goto err_free_ebpf; */

	map_teardown(script);

done:
err_free_ebpf:
	free(e);
err_free_script:
	node_free(script);
err:
	return err;
}
