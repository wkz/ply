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
	FILE *sfp, *enable;
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
	
	enable = fopen("/sys/kernel/debug/tracing/events/kprobes/enable", "w");
	if (!enable) {
		perror("unable to enable probes");
		err = -errno;
		goto err;
	}

	fputs("1\n", enable);
	fflush(enable);
	rewind(enable);

	fprintf(stderr, "%d probe%s active\n", num, (num == 1) ? "" : "s");
	printf_drain(script);

	fprintf(stderr, "de-activating probes");
	fputs("0\n", enable);
	fflush(enable);
	fclose(enable);

	node_foreach(probe, script->script.probes) {
		pvdr = node_get_pvdr(probe);
		err = pvdr->teardown(probe);
		if (err)
			break;
	}

	fclose(fopen("/sys/kernel/debug/tracing/kprobe_events", "w"));
	
	map_teardown(script);

done:
err:
	if (prog)
		free(prog);
	if (script)
		node_free(script);

	return err;
}
