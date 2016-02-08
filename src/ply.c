#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include "ply.h"
#include "map.h"
#include "lang/ast.h"
#include "pvdr/pvdr.h"

FILE *scriptfp;
int debug = 0;
int timeout = 0;

static const char *sopts = "cdt:";
static struct option lopts[] = {
	{ "command", no_argument,       0, 'c' },
	{ "debug",   no_argument,       0, 'd' },
	{ "timeout", required_argument, 0, 't' },

	{ NULL }
};

int parse_opts(int argc, char **argv, FILE **sfp)
{
	int cmd = 0;
	int opt;

	while ((opt = getopt_long(argc, argv, sopts, lopts, NULL)) > 0) {
		switch (opt) {
		case 'c':
			cmd = 1;
			break;
		case 'd':
			debug++;
			break;
		case 't':
			timeout = strtol(optarg, NULL, 0);
			if (timeout <= 0) {
				_e("timeout option must be a positive integer");
				return -EINVAL;
			}
			break;
		default:
			_e("unknown option '%c'", opt);
			return -EINVAL;
		}
	}

	if (optind >= argc)
		return -EINVAL;

	if (cmd)
		*sfp = fmemopen(argv[optind], strlen(argv[optind]), "r");
	else
		*sfp = fopen(argv[optind], "r");

	if (!*sfp) {
		_pe("unable to read script");
		return -EIO;
	}

	return 0;
}

void sigint(int sigint)
{
	return;
}

int main(int argc, char **argv)
{
	FILE *sfp;
	node_t *script;
	prog_t *prog;
	int err = 0;

	scriptfp = stdin;
	err = parse_opts(argc, argv, &sfp);
	if (err)
		goto err;

	script = node_script_parse(sfp);
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
		
	if (debug)
		node_ast_dump(script);

	prog = compile_probe(script->script.probes);
	if (!prog) {
		err = -EINVAL;
		goto err_free_script;
	}

	_d("compilation ok");
	if (debug)
		goto done;

	err = node_get_pvdr(script->script.probes)->setup(script->script.probes, prog);
	if (err)
		goto err_free_prog;

	if (timeout) {
		siginterrupt(SIGALRM, 1);
		signal(SIGALRM, sigint);
		alarm(timeout);
	}

	siginterrupt(SIGINT, 1);
	signal(SIGINT, sigint);

	system("echo 1 >/sys/kernel/debug/tracing/events/kprobes/enable");
	printf_drain(script);
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
