#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/version.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ply/ply.h>
#include <ply/kallsyms.h>

#define KSYMS_CACHE "/tmp/ply.ksyms"

static int ksym_cmp(const void *_key, const void *_member)
{
	const ksym_t *key = _key, *member = _member;

	if (key->start < member->start)
		return -1;
	else if (key->end > member->end)
		return 1;

	return 0;
}

const ksym_t *ksym_get(ksyms_t *ks, uintptr_t addr)
{
	ksym_t key = { .start = addr, .end = addr };

	return bsearch(&key, ks->cache->sym,
		       ks->cache->hdr.n_syms, sizeof(key), ksym_cmp);
}

static int ksym_prepare(FILE *fp, struct ksym *ksym)
{
	char line[0x80];
	char *p;

	while (fgets(line, sizeof(line), fp)) {
		ksym->start = strtoul(line, &p, 16);
		if (ksym->start == ULONG_MAX)
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

static int ksyms_cache_build(const char *in, const char *out)
{
	struct ksym_cache_hdr hdr = { .version = LINUX_VERSION_CODE };
	struct ksym ksym[2];
	FILE *cfp, *kfp;
	int err, i;

	kfp = fopen(in, "r");
	if (!kfp) {
		err = -errno;
		goto out;
	}

	cfp = fopen(out, "w");
	if (!cfp) {
		err = -errno;
		goto close_kfp;
	}

	if (fseek(cfp, sizeof(hdr), SEEK_CUR)) {
		err = -errno;
		goto close_cfp;
	}

	err = ksym_prepare(kfp, &ksym[0]);
	if (err)
		goto close_cfp;

	for (i = 1;; i = !i) {
		err = ksym_prepare(kfp, &ksym[i]);
		if (err == EOF) {
			err = 0;
			break;
		} else if (err)
			goto close_cfp;

		ksym[!i].end = ksym[i].start - 1;
		if (!fwrite(&ksym[!i], sizeof(ksym[!i]), 1, cfp)) {
			err = -EIO;
			goto close_cfp;
		}

		hdr.n_syms++;
	}

	/* assume no function larger than 4k */
	ksym[i].end = ksym[i].start + 0x1000;
	if (!fwrite(&ksym[i], sizeof(ksym[i]), 1, cfp)) {
		err = -EIO;
		goto close_cfp;
	}

	rewind(cfp);
	if (!fwrite(&hdr, sizeof(hdr), 1, cfp))
		err = -EIO;

close_cfp:
	fclose(cfp);
	if (err) {
		_e("failed: %s", strerror(-err));
		unlink(out);
	}
close_kfp:
	fclose(kfp);
out:
	return err;
}

static int ksyms_cache_open(ksyms_t *ks)
{
	struct stat st;
	int err;

	if (stat(KSYMS_CACHE, &st)) {
		err = ksyms_cache_build("/proc/kallsyms", KSYMS_CACHE);
		if (err)
			return err;

		if (stat(KSYMS_CACHE, &st))
			return -errno;
	}

	ks->cache_fd = open(KSYMS_CACHE, O_RDONLY);
	if (ks->cache_fd < 0)
		return -errno;

	ks->cache = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE,
			 ks->cache_fd, 0);
	return ks->cache ? 0 : -ENOENT;
}

ksyms_t *ksyms_new(void)
{
	ksyms_t *ks;
	int err;

	ks = calloc(1, sizeof(*ks));
	assert(ks);

	err = ksyms_cache_open(ks);
	if (err)
		goto err;

	return ks;
err:
	free(ks);
	return NULL;
}
