/*
 * Copyright 2015-2017 Tobias Waldekranz <tobias@waldekranz.com>
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

/* Manages a cache of the contents in /proc/kallsyms, but in a binary
 * format with each symbol using a fixed amount of space. This let's
 * us lookup addresses using bsearch(3), making stacktrace resolution
 * much faster.
 *
 * The first and last symbols are the special `nullsym` and `endsym`
 * symbols defined below. These are always present but never included
 * in the range given to bsearch(3) thus making it safe to always look
 * at the previous and next record.
 */

#define _XOPEN_SOURCE		/* strptime */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/version.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <linux/capability.h>

#include <sys/mman.h>
#include <sys/stat.h>

#include <ply/ply.h>
#include <ply/kallsyms.h>

#define KALLSYMS    "/proc/kallsyms"
#define KSYMS_CACHE "/var/tmp/ply-ksyms"

static struct ksym nullsym = {
	.addr = 0,
	.sym = "NULL",
};

static struct ksym endsym = {
	.addr = UINTPTR_MAX,
	.sym = "END",
};

static int ksym_cmp(const void *_key, const void *_member)
{
	const struct ksym *key = _key, *member = _member;

	if (key->addr < member->addr)
		return -1;
	else if (key->addr > (member + 1)->addr)
		return 1;

	return 0;
}

const struct ksym *ksym_get(struct ksyms *ks, uintptr_t addr)
{
	struct ksym key = { .addr = addr };

	return bsearch(&key, ks->cache->sym,
		       ks->cache->hdr.n_syms - 1, sizeof(key), ksym_cmp);
}

static int ksym_write(FILE *fp, struct ksym *ksym)
{
	return fwrite(ksym, sizeof(*ksym), 1, fp) ? 0 : -EIO;
}

static int ksym_parse(FILE *fp, struct ksym *ksym)
{
	char line[0x80];
	char *p;

	while (fgets(line, sizeof(line), fp)) {
		ksym->addr = strtoul(line, &p, 16);
		if (ksym->addr == ULONG_MAX)
			continue;

		p++;
		if (*p != 't' && *p != 'T')
			continue;

		p += 2;
		p = strtok(p, " \t\n");
		if (!p)
			continue;

		strncpy(ksym->sym, p, sizeof(ksym->sym) - 1);
		return 0;
	}

	return EOF;
}

static int __ksyms_cache_open(struct ksyms *ks)
{
	struct stat st;
	int err, i;

	if (stat(KSYMS_CACHE, &st))
		return -errno;

	ks->cache_fd = open(KSYMS_CACHE, O_RDWR);
	if (ks->cache_fd < 0)
		return -errno;

	ks->cache = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED,
			 ks->cache_fd, 0);

	return (ks->cache == MAP_FAILED) ? -EIO : 0;
}

static int ksym_sort_cmp(const void *_a, const void *_b)
{
	const struct ksym *a = _a, *b = _b;

	return a->addr - b->addr;
}

static int ksyms_cache_sort(struct ksyms *ks)
{
	int err;

	err = __ksyms_cache_open(ks);
	if (err)
		return err;

	/* Sort everything between NULL and END */
	qsort(&ks->cache->sym[1], ks->cache->hdr.n_syms - 2,
	      sizeof(struct ksym), ksym_sort_cmp);

	err = msync(ks->cache, sizeof(ks->cache->hdr) +
		    ks->cache->hdr.n_syms * sizeof(struct ksym), MS_SYNC);
	if (err)
		return -errno;

	return 0;
}

/* Anyone may read /proc/kallsyms, but if the reader does not posses
 * the CAP_SYSLOG capability, all symbol addresses are set to zero. So
 * we make sure that we have it to avoid creating a useless cache. If
 * there is some less hacky way of getting this information without
 * depending on libcap, please refactor. */
static int ksyms_cache_cap(void)
{
	FILE *fp;
	char line[0x100];
	int err = -EPERM;
	uint64_t caps = 0;

	fp = fopen("/proc/self/status", "r");
	if (!fp)
		return err;

	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "CapEff:") != line)
			continue;

		caps = strtoull(&line[7], NULL, 16);
		err = 0;
		break;
	}

	fclose(fp);
	if (err)
		return err;

	return (caps & (1ULL << CAP_SYSLOG)) ? 0 : -EPERM;
}

static int ksyms_cache_build(struct ksyms *ks)
{
	struct ksym_cache_hdr hdr = { 0 };
	struct ksym ksym;
	FILE *cfp, *kfp;
	int err, i;

	_i("creating kallsyms cache\n");

	err = ksyms_cache_cap();
	if (err)
		goto out;

	kfp = fopen(KALLSYMS, "r");
	if (!kfp) {
		err = -errno;
		goto out;
	}

	cfp = fopen(KSYMS_CACHE, "w");
	if (!cfp) {
		err = -errno;
		goto close_kfp;
	}

	if (fseek(cfp, sizeof(hdr), SEEK_CUR)) {
		err = -errno;
		goto close_cfp;
	}

	err = ksym_write(cfp, &nullsym);
	if (err)
		goto close_cfp;
	hdr.n_syms++;

	while (!(err = ksym_parse(kfp, &ksym))) {
		err = ksym_write(cfp, &ksym);
		if (err)
			goto close_cfp;
		hdr.n_syms++;
	}

	if (err && (err != EOF))
		goto close_cfp;

	err = ksym_write(cfp, &endsym);
	if (err)
		goto close_cfp;
	hdr.n_syms++;

	rewind(cfp);
	if (!fwrite(&hdr, sizeof(hdr), 1, cfp))
		err = -EIO;

close_cfp:
	fclose(cfp);
	if (err)
		unlink(KSYMS_CACHE);

close_kfp:
	fclose(kfp);
out:
	if (!err)
		err = ksyms_cache_sort(ks);

	if (err)
		_w("unable to create kallsyms cache: %s\n", strerror(-err));

	return err;
}

static int ksyms_cache_open(struct ksyms *ks)
{
	struct stat procst, ksymsst;
	int err;

	err = __ksyms_cache_open(ks);
	if (err)
		return ksyms_cache_build(ks);

	if (stat("/proc", &procst) || stat(KSYMS_CACHE, &ksymsst))
		return ksyms_cache_build(ks);

	/* Use ctime of `/proc` as an approximation of system boot
	 * time and require that our cache is younger than that. */
	if (ksymsst.st_ctime < procst.st_ctime)
		return ksyms_cache_build(ks);

	return 0;
}

void ksyms_free(struct ksyms *ks)
{
	size_t size;

	size = sizeof(ks->cache->hdr) +
		sizeof(ks->cache->sym[0]) * ks->cache->hdr.n_syms;

	munmap(ks->cache, size);
	close(ks->cache_fd);
}

struct ksyms *ksyms_new(void)
{
	struct ksyms *ks;
	int err;

	ks = xcalloc(1, sizeof(*ks));

	err = ksyms_cache_open(ks);
	if (err)
		goto err;

	return ks;
err:
	free(ks);
	return NULL;
}
