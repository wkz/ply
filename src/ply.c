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
	size_t ksize, vsize;

	for (mdyn = script->script.mdyns; mdyn; mdyn = mdyn->next) {
		if (dump) {
			mdyn->mapfd = dumpfd++;
			continue;
		}

		if (!strcmp(mdyn->map->string, "printf")) {
			ksize = mdyn->map->dyn.size;
			vsize = mdyn->map->call.vargs->next->dyn.size;
		} else {
			ksize = mdyn->map->map.rec->dyn.size;
			vsize = mdyn->map->dyn.size;
		}

		mdyn->mapfd = bpf_map_create(BPF_MAP_TYPE_HASH, ksize, vsize, 256);
		if (mdyn->mapfd <= 0) {
			_pe("failed creating map");
			return mdyn->mapfd;
		}
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

void printf_output(node_t *script, void *rec)
{
	node_t *call, *arg;
	int64_t *meta;
	size_t offs;
	char spec[16] = "%";
	char *fmt, *seg, *save, *end;

	meta = rec;
	if (*meta < 0 || *meta >= 64)
		return;

	call = script->script.printf[*meta];
	if (!call)
		return;

	fmt  = strdup(call->call.vargs->string);
	arg  = call->call.vargs->next->rec.vargs->next;
	offs = sizeof(*meta);
	for (seg = strtok_r(fmt, "%", &save); seg; seg = strtok_r(NULL, "%", &save)) {
		printf(seg);

		end = strpbrk(save, "cdiopsuxX");
		if (!end)
			break;

		strncpy(&spec[1], save, end - save + 1);
		spec[1 + (end - save) + 1] = '\0';
		if (*end == 's')
			printf(spec, rec + offs);
		else
			printf(spec, *((int64_t *)(rec + offs)));

		*end = '\0';
		save = end + 1;
		offs += arg->dyn.size;
		arg = arg->next;
	}
}

void printf_drain(node_t *script)
{
	node_t *call, *rec;
	mdyn_t *mdyn;
	int64_t key;
	char *val;
	int err;

	for (mdyn = script->script.mdyns; mdyn; mdyn = mdyn->next)
		if (!strcmp(mdyn->map->string, "printf"))
			break;

	if (!mdyn) {
		getchar();
		return;
	}

	call = mdyn->map;
	rec  = call->call.vargs->next;
	val  = malloc(rec->dyn.size);

	for (key = 0;;) {
		err = bpf_map_lookup(mdyn->mapfd, &key, val);
		if (err) {
			err = usleep(200000);
			if (err)
				break;
		} else {
			printf_output(script, val);
			bpf_map_delete(mdyn->mapfd, &key);
			key = (key + 1) & (PRINTF_BUF_LEN - 1);
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
			if (strcmp(mdyn->map->string, "printf"))
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
