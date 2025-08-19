/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */
#include <assert.h>
#include <getopt.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/version.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/wait.h>

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
	      "  -c COMMAND     Run COMMAND in a shell, exit upon completion.\n"
	      "  -d             Enable debug output.\n"
	      "  -e             Exit after compiling.\n"
	      "  -h             Print usage message and exit.\n"
	      "  -k             Keep going in face of trace buffer overruns.\n"
	      "  -S             Show generated BPF.\n"
	      "  -T             Run self-test.\n"
	      "  -u             Always turn off buffering of stdout/stderr.\n"
	      "  -v             Print version information.\n",
	      stderr);
}

static void self_test(char *plybin)
{
	static unsigned char script[] = {
#		include "self-test.bytes"
	};
	char *cmd;
	FILE *sh;

	if (asprintf(&cmd, "PLYBIN=%s /bin/sh", plybin) < 0)
		goto err;

	sh = popen(cmd, "w");
	free(cmd);
	if (!sh)
		goto err;

	if (fwrite(script, sizeof(script), 1, sh) != 1)
		goto err;

	exit(pclose(sh) ? 1 : 0);

err:
	_e("unable to run self-test\n");
	exit(1);
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
	struct ply_probe *pb;

	if (!ply->probes) {
		printf("NO PROBES\n");
		return;
	}

	printf("\n\n-- globals\n");
	symtab_dump(&ply->globals, stdout);

	ply_probe_foreach(ply, pb) {
		printf("\n\n-- probe\n");
		printf("%s\n", pb->probe ? : "<null>");

		printf("\n\n-- ast\n");
		if (pb->ast)
			ast_fprint(stdout, pb->ast);
		else
			printf("NO AST\n");

		printf("\n-- locals\n");
		symtab_dump(&pb->locals, stdout);
		printf("-- ir\n");
		ir_dump(pb->ir, stdout);
	}
}

static void version()
{
	printf("%s (linux-version:%u~%u.%u.%u)\n",
	       PACKAGE_STRING, LINUX_VERSION_CODE,
	       (LINUX_VERSION_CODE >> 16) & 0xff,
	       (LINUX_VERSION_CODE >>  8) & 0xff,
	       (LINUX_VERSION_CODE >>  0) & 0xff);
}

static const char *sopts = "c:dehkSTuv";
static struct option lopts[] = {
	{ "command",    required_argument, 0, 'c' },
	{ "debug",      no_argument,       0, 'd' },
	{ "dry-run",    no_argument,       0, 'e' },
	{ "help",       no_argument,       0, 'h' },
	{ "keep-going", no_argument,       0, 'k' },
	{ "dump",       no_argument,       0, 'S' },
	{ "self-test",  no_argument,       0, 'T' },
	{ "unbuffer",   no_argument,       0, 'u' },
	{ "version",    no_argument,       0, 'v' },

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

int inferior_prep(const char *cmd, int *infpid, int *inftrig)
{
	int err, pid, trig[2];

	err = pipe(trig);
	if (err)
		return err;

	*inftrig = trig[1];

	pid = fork();
	if (pid < 0)
		return pid;

	if (pid) {
		char str[16];

		*infpid = pid;

		/* allow scripts to reference the pid of the inferior
		 * as $target. */
		snprintf(str, sizeof(str), "%d", pid);
		setenv("target", str, 0);
		return 0;
	}

	/* wait for parent to compile and get ready */
	if (read(trig[0], &err, sizeof(err)) != sizeof(err))
		return -EINVAL;

	/* if parent sends us an error, don't run the command. most
	 * probably the script did not compile. */
	if (err)
		exit(0);

	return execl("/bin/sh", "sh", "-c", cmd, NULL);
}

static sigset_t orig_sigmask;

struct ply_return sig_handle(int fd)
{
	struct signalfd_siginfo  si;
	int status;

	if (read(fd, &si, sizeof(si)) != sizeof(si)) {
		return (struct ply_return) {
			.err = 1,
			.val = -EIO,
		};
	}

	switch (si.ssi_signo) {
	case SIGCHLD:
		_d("SIGCHLD\n");
		waitpid(0, &status, WNOHANG);
		return (struct ply_return) {
			.exit = 0,
			.val = 0,
		};
	case SIGINT:
		_d("SIGINT\n");
		return (struct ply_return) {
			.exit = 1,
			.val = 1,
		};
	}

	_e("Unexpected signal: %u\n", si.ssi_signo);
	return (struct ply_return) {
		.err = 1,
		.val = -EINVAL,
	};
}

void sig_exit(int fd)
{
	close(fd);
	sigprocmask(SIG_SETMASK, &orig_sigmask, NULL);
}

int sig_init(void)
{
	sigset_t mask;
	int fd;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGCHLD);

	if (sigprocmask(SIG_BLOCK, &mask, &orig_sigmask) == -1)
		return -errno;

	fd = signalfd(-1, &mask, SFD_CLOEXEC);
	if (fd == -1)
		return -errno;

	return fd;
}

int main(int argc, char **argv)
{
	struct ply_return ret = { .err = 1 };
	int opt, infpid, inftrig, sfd, ready;
	struct pollfd *fds = NULL;
	int f_dryrun, f_dump;
	char *cmd = NULL;
	struct ply *ply;
	nfds_t nfds;
	FILE *src;

	f_dryrun = f_dump = 0;
	while ((opt = getopt_long(argc, argv, sopts, lopts, NULL)) > 0) {
		switch (opt) {
		case 'c':
			cmd = optarg;
			break;
		case 'd':
			ply_config.verify = 1;
			ply_debug = 1;
			break;
		case 'e':
			f_dryrun = 1;
			ply_config.ksyms = 0;
			break;
		case 'h':
			usage(); exit(0);
			break;
		case 'k':
			ply_config.strict = 0;
			break;
		case 'S':
			f_dump = 1;
			break;
		case 'T':
			self_test(argv[0]); exit(1);
			break;
		case 'u':
			setvbuf(stdout, NULL, _IONBF, 0);
			setvbuf(stderr, NULL, _IONBF, 0);
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

	if (cmd && inferior_prep(cmd, &infpid, &inftrig))
		exit(1);

	/* TODO figure this out dynamically. terminfo? */
	ply_config.unicode = 1;

	ply_init();

	ply_alloc(&ply);
	ret.val = ply_fparse(ply, src);
	if (ret.val)
		goto err;

	ret.val = ply_compile(ply);

	if (f_dump)
		dump(ply);

	if (ret.val)
		goto err;

	if (f_dryrun)
		goto unload;

	sfd = sig_init();
	if (sfd < 0) {
		ret.val = sfd;
		goto err;
	}

	fds = malloc(sizeof(*fds));
	if (!fds) {
		ret.val = -ENOMEM;
		goto err;
	}

	*fds = (struct pollfd) {
		.fd = sfd,
		.events = POLLIN,
	};

	memlock_uncap();

	ret = ply_load(ply);
	if (ret.exit || ret.err)
		goto err;

	nfds = ply_get_nfds(ply);
	if (nfds) {
		fds = realloc(fds, (1 + nfds) * sizeof(*fds));
		if (!fds) {
			ret = (struct ply_return) {
				.err = 1,
				.val = -ENOMEM,
			};
			goto err;
		}

		ply_fill_pollset(ply, &fds[1]);
	}

	ply_start(ply);
	_d("ply: active\n");

	if (cmd) {
		int err = 0;

		if (write(inftrig, &err, sizeof(err)) != sizeof(err)) {
			fprintf(stderr, "ply: unable to start command\n");
			ret.err = 1;
			ret.val = -EIO;
			goto stop;
		}
	}

	for (;;) {
		ready = poll(fds, 1 + nfds, -1);
		if (ready < 0) {
			ret = (struct ply_return) {
				.err = 1,
				.val = errno,
			};
			break;
		}

		if (fds[0].revents & POLLIN) {
			ret = sig_handle(sfd);
			if (--ready == 0)
				break;
		}

		ply_return_fold(&ret, ply_service(ply, ready, &fds[1]));
		if (ret.err || ret.exit)
			break;
	}

	sig_exit(sfd);

stop:
	_d("ply: deactivating\n");
	ply_stop(ply);

	/* END probes may generate events, so do a final poll for them
	 * before shutting down.
	 */
	ready = poll(&fds[1], nfds, 0);
	if (ready > 0)
		ply_return_fold(&ret, ply_service(ply, ready, &fds[1]));

	free(fds);

	ply_maps_print(ply);

unload:
	ply_unload(ply);

err:
	ply_free(ply);

	if (ret.err) {
		if (ret.val)
			printf("ERR:%d\n", ret.val);

		return 1;
	}

	return ret.exit ? ret.val : 0;
}
