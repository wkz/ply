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

#include <getopt.h>
#include <linux/version.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>

#include "config.h"
#include "ply.h"
#include "map.h"
#include "lang/ast.h"
#include "pvdr/pvdr.h"

FILE *scriptfp;

struct globals G;

static const char *sopts = "AcdDht:v";
static struct option lopts[] = {
	{ "ascii",   no_argument,       0, 'A' },
	{ "command", no_argument,       0, 'c' },
	{ "debug",   no_argument,       0, 'd' },
	{ "dump",    no_argument,       0, 'D' },
	{ "help",    no_argument,       0, 'h' },
	{ "timeout", required_argument, 0, 't' },
	{ "version", no_argument,       0, 'v' },

	{ NULL }
};

static void usage()
{
	puts("ply - Dynamic tracing utility\n"
	     "\n"
	     "Usage:\n"
	     "  ply [options] <script_file>\n"
	     "  ply [options] -c <script_string>\n"
	     "\n"
	     "Options:\n"
	     "  -A                  ASCII output only, no Unicode.\n"
	     "  -c <script_string>  Execute script literate.\n"
	     "  -d                  Enable debug output.\n"
	     "  -D                  Dump generated BPF and exit.\n"
	     "  -h                  Print usage message and exit.\n"
	     "  -t <timeout>        Terminate trace after <timeout> seconds.\n"
	     "  -v                  Print version information.\n"
		);
}

static void version()
{
	fputs(PACKAGE "-" VERSION, stdout);
	if (strcmp(VERSION, GIT_VERSION))
		fputs("(" GIT_VERSION ")", stdout);

	printf(" (linux-version:%u~%u.%u.%u)\n",
	       LINUX_VERSION_CODE,
	       (LINUX_VERSION_CODE >> 16) & 0xff,
	       (LINUX_VERSION_CODE >>  8) & 0xff,
	       (LINUX_VERSION_CODE >>  0) & 0xff);
}

static int parse_opts(int argc, char **argv, FILE **sfp)
{
	int cmd = 0;
	int opt;

	while ((opt = getopt_long(argc, argv, sopts, lopts, NULL)) > 0) {
		switch (opt) {
		case 'A':
			G.ascii = 1;
			break;
		case 'c':
			cmd = 1;
			break;
		case 'd':
			G.debug = 1;
			break;
		case 'D':
			G.dump = 1;
			break;
		case 'h':
			usage();
			exit(0);
		case 't':
			G.timeout = strtol(optarg, NULL, 0);
			if (G.timeout <= 0) {
				_e("timeout must be a positive integer");
				return -EINVAL;
			}
			break;
		case 'v':
			version();
			exit(0);

		default:
			_e("unknown option '%c'. Try -h for usage.", opt);
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
		_eno("unable to read script");
		return -EIO;
	}

	return 0;
}

static void memlock_uncap(void)
{
	struct rlimit limit;
	rlim_t current;
	int err;

	err = getrlimit(RLIMIT_MEMLOCK, &limit);
	if (err) {
		_eno("unable to retrieve memlock limit, "
		     "maps are likely limited in size");
		return;
	}

	current = limit.rlim_cur;

	/* The total size of all maps that ply is allowed to create is
	 * limited by the amount of memory that can be locked into
	 * RAM. By default, this limit can be quite low (64kB on the
	 * author's system). So this simply tells the kernel to allow
	 * ply to use as much as it needs. */
	limit.rlim_cur = limit.rlim_max = RLIM_INFINITY;
	err = setrlimit(RLIMIT_MEMLOCK, &limit);
	if (err) {
		const char *suffix = "B";

		if (!(current & 0xfffff)) {
			suffix = "MB";
			current >>= 20;
		} else if (!(current & 0x3ff)) {
			suffix = "kB";
			current >>= 10;
		}

		_eno("could not remove memlock size restriction");
		_w("total map size is limited to %lu%s", current, suffix);
		return;
	}

	_d("unlimited memlock");
}

static void sigint(int sigint)
{
	return;
}

int main(int argc, char **argv)
{
	FILE *sfp, *enable;
	node_t *probe, *script;
	prog_t *prog = NULL;
	pvdr_t *pvdr;
	int err = 0, num;

	scriptfp = stdin;
	err = parse_opts(argc, argv, &sfp);
	if (err)
		goto err;

	memlock_uncap();

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
		
	if (G.dump)
		node_ast_dump(script);

	node_foreach(probe, script->script.probes) {
		err = -EINVAL;
		prog = compile_probe(probe);
		if (!prog)
			break;

		if (G.dump)
			continue;

		pvdr = node_get_pvdr(probe);
		num = pvdr->setup(probe, prog);
		if (num < 0) {
			if (num == -EINVAL)
				_e("probe rejected, ensure that ply was built "
				   "against the running kernel");
			break;
		}
	}

	if (G.dump)
		goto done;
	
	if (num < 0) {
		err = num;
		goto err;
	}

	if (G.timeout) {
		siginterrupt(SIGALRM, 1);
		signal(SIGALRM, sigint);
		alarm(G.timeout);
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

	fprintf(stderr, "de-activating probes\n");
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
