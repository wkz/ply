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
int dump = 0;
char *license = "proprietary";
int timeout = 0;

static const char *sopts = "cdDGt:";
static struct option lopts[] = {
	{ "command", no_argument,       0, 'c' },
	{ "debug",   no_argument,       0, 'd' },
	{ "dump",    no_argument,       0, 'D' },
	{ "gpl",     required_argument, 0, 'G' },
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
		case 'D':
			dump++;
			break;
		case 'G':
			license = "GPL";
			break;
		case 't':
			timeout = strtol(optarg, NULL, 0);
			if (timeout <= 0) {
				_e("timeout must be a positive integer");
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
	node_t *probe, *script;
	prog_t *prog;
	pvdr_t *pvdr;
	int err = 0, num;

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
		goto err;

	err = annotate_script(script);
	if (err)
		goto err;

	err = map_setup(script);
	if (err)
		goto err;
		
	if (dump)
		node_ast_dump(script);

	node_foreach(probe, script->script.probes) {
		err = -EINVAL;
		prog = compile_probe(probe);
		if (!prog)
			break;

		if (dump)
			continue;

		pvdr = node_get_pvdr(probe);
		num = pvdr->setup(probe, prog);
		if (num < 0)
			break;
	}

	_d("compilation ok");
	if (dump)
		goto done;
	
	if (num < 0) {
		err = num;
		goto err;
	}

	if (timeout) {
		siginterrupt(SIGALRM, 1);
		signal(SIGALRM, sigint);
		alarm(timeout);
	}

	siginterrupt(SIGINT, 1);
	signal(SIGINT, sigint);

	_d("enabling %d probe(s)", num);
	system("echo 1 >/sys/kernel/debug/tracing/events/kprobes/enable");

	_i("%d probe%s active", num, (num == 1) ? "" : "s");
	printf_drain(script);

	_i("de-activating probes");
	system("echo 0 >/sys/kernel/debug/tracing/events/kprobes/enable");

	map_teardown(script);

done:
err:
	if (prog)
		free(prog);
	if (script)
		node_free(script);

	return err;
}
