#include <assert.h>
#include <getopt.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/version.h>
#include <sys/resource.h>

#include <ply/ply.h>

static void usage()
{
	fputs("ply - Dynamic tracing utility\n"
	      "\n"
	      "Usage:\n"
	      "  ply [options] <ply-text>\n"
	      "  ply [options] <ply-file>\n"
	      "\n"
	      "Options:\n"
	      "  -d             Enable debug output.\n"
	      "  -e             Exit after compiling.\n"
	      "  -f <ply-text>  Execute script literal.\n"
	      "  -h             Print usage message and exit.\n"
	      "  -S             Show generated BPF.\n"
	      "  -v             Print version information.\n",
	      stderr);
}

static void memlock_uncap(void)
{
	struct rlimit limit;
	rlim_t current;
	int err;

	err = getrlimit(RLIMIT_MEMLOCK, &limit);
	if (err) {
		_e("unable to retrieve memlock limit, "
		   "maps are likely limited in size\n");
		return;
	}

	current = limit.rlim_cur;

	/* The total size of all maps that ply is allowed to create is
	 * limited by the amount of memory that can be locked into
	 * RAM. By default, this limit can be quite low (64kB on a
	 * standard x86_64 box running a recent kernel). So this
	 * simply tells the kernel to allow ply to use as much as it
	 * needs. */
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

		_w("could not remove memlock size restriction\n");
		_w("total map size is limited to %lu%s\n", current, suffix);
		return;
	}

	_d("unlimited memlock\n");
}

void dump(struct ply *ply)
{
	if (!ply->probes) {
		printf("NO PROBES\n");
		return;
	}

	printf("%s\n", ply->probes->probe ? : "<null>");

	if (ply->probes->ast)
		ast_fprint(stdout, ply->probes->ast);
	else
		printf("NO AST\n");

	printf("\n\n-- globals\n");
	symtab_dump(&ply->globals, stdout);
	printf("\n-- locals\n");
	symtab_dump(&ply->probes->locals, stdout);
	printf("-- ir\n");
	ir_dump(ply->probes->ir, stdout);
}

static void version()
{
	/* fputs(PACKAGE "-" VERSION, stdout); */
	/* if (strcmp(VERSION, GIT_VERSION)) */
	/* 	fputs("(" GIT_VERSION ")", stdout); */

	printf(" (linux-version:%u~%u.%u.%u)\n",
	       LINUX_VERSION_CODE,
	       (LINUX_VERSION_CODE >> 16) & 0xff,
	       (LINUX_VERSION_CODE >>  8) & 0xff,
	       (LINUX_VERSION_CODE >>  0) & 0xff);
}

static const char *sopts = "dehSv";
static struct option lopts[] = {
	{ "debug",   no_argument,       0, 'd' },
	{ "dry-run", no_argument,       0, 'e' },
	{ "help",    no_argument,       0, 'h' },
	{ "dump",    no_argument,       0, 'S' },
	{ "version", no_argument,       0, 'v' },

	{ NULL }
};

FILE *get_src(int argc, char **argv)
{
	if (!argc)
		return NULL;
	
	/* if the argument names an existing file that we have access
	 * to, use it as the source. */
	if (!access(argv[0], R_OK))
		return fopen(argv[0], "r");

	/* TODO concat multiple argvs to one string and parse that as
	 * a ply script */

	/* otherwise, parse the argument as a ply script. */
	return fmemopen(argv[0], strlen(argv[0]), "r");
}

int main(int argc, char **argv)
{
	struct ply *ply;
	struct ply_ev *ev;
	int err, opt;
	int f_debug, f_dryrun, f_dump;
	FILE *src;

	f_debug = f_dryrun = f_dump = 0;
	while ((opt = getopt_long(argc, argv, sopts, lopts, NULL)) > 0) {
		switch (opt) {
		case 'd':
			f_debug = 1;
			break;
		case 'e':
			f_dryrun = 1;
			break;
		case 'h':
			usage(); exit(0);
			break;
		case 'S':
			f_dump = 1;
			break;
		case 'v':
			version(); exit(0);
			break;

		default:
			_e("unknown option '%c'\n", opt);
			usage(); exit(1);
			break;
		}
	}

	src = get_src(argc - optind, &argv[optind]);
	if (!src) {
		_e("no input\n");
		usage(); exit(1);
	}
	
	/* TODO figure this out dynamically. terminfo? */
	ply_config.unicode = 1;

	ply_alloc(&ply);
	err = ply_fparse(ply, src);
	if (err)
		goto err;

	err = ply_compile(ply);
	if (err)
		goto err;

	if (f_dump)
		dump(ply);

	if (f_dryrun)
		goto unload;

	memlock_uncap();

	err = ply_load(ply);
	if (err)
		goto err;

	ply_start(ply);
	printf("starting\n");
	sleep(1);
	/* while (ply_poll(ply, &ev)) { */
	/* 	err = ply_ev_handle(ply, ev); */
	/* 	ply_ev_free(ply, ev); */
	/* 	if (err) */
	/* 		break; */
	/* } */
	printf("stopping\n");
	ply_stop(ply);

	if (!err)
		ply_maps_print(ply);

unload:
	ply_unload(ply);

err:
	if (err && f_dump)
		dump(ply);

	ply_free(ply);

	if (err)
		printf("ERR:%d\n", err);

	return err ? 1 : 0;
}
