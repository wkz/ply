#include <stdio.h>
#include <unistd.h>

#include "fs-ast.h"
#include "fs-ebpf.h"
#include "fs-parse.h"
#include "fs-lex.h"

#include "provider.h"

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

int main(int argc, char **argv)
{
	struct fs_node *script, *p;
	struct provider *provider;
	struct ebpf *e;
	int err = 0;

	script = fs_load(stdin);
	if (!script) {
		err = -EINVAL;
		goto err;
	}

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

	err = provider->setup(provider, e, p);
	if (err)
		goto err_free_ebpf;

	system("echo 1 >/sys/kernel/debug/tracing/events/kprobes/enable");
	system("echo 1 >/sys/kernel/debug/tracing/tracing_on");
	system("cat /sys/kernel/debug/tracing/trace_pipe");

	/* err = provider->teardown(provider, p, e); */
	/* if (err) */
	/* 	goto err_free_ebpf; */
	
err_free_ebpf:
	free(e);
err_free_script:
	if (err)
		fs_ast_dump(script);

	fs_free(script);
err:
	return err;
}
