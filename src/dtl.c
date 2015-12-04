#include <getopt.h>
#include <stdio.h>
#include <unistd.h>

#include "fs-ast.h"
#include "fs-ebpf.h"
#include "fs-parse.h"
#include "fs-lex.h"

#include "provider.h"

FILE *scriptfp;
int dump = 0;

struct fs_node *fs_load(FILE *fp)
{
	struct fs_node *script = NULL;
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
				fprintf(stderr, "unable to open '%s'\n", optarg);
				return -EIO;
			}
			break;
		default:
			fprintf(stderr, "unknown option '%c'\n", opt);
			return -EINVAL;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct fs_node *script, *p;
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

	if (dump)
		fs_ast_dump(script);

	p = script->script.probes;

	provider = provider_find(p->probe.pspecs->string);
	if (!provider) {
		fprintf(stderr, "error: no provider for \"%s\"\n",
			p->probe.pspecs->string);
		err = -ENOENT;
		goto err_free_script;
	}

	e = fs_compile(p, provider);
	if (!e) {
		fprintf(stderr, "error: compilation error\n");
		err = -EINVAL;
		goto err_free_script;
	}

	if (dump)
		goto done;

	err = provider->setup(provider, e, p);
	if (err)
		goto err_free_ebpf;

	system("echo 1 >/sys/kernel/debug/tracing/events/kprobes/enable");
	system("echo 1 >/sys/kernel/debug/tracing/tracing_on");
	system("cat /sys/kernel/debug/tracing/trace_pipe");

	/* err = provider->teardown(provider, p, e); */
	/* if (err) */
	/* 	goto err_free_ebpf; */

done:
err_free_ebpf:
	free(e);
err_free_script:
	fs_free(script);
err:
	return err;
}
