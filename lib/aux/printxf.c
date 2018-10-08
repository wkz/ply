#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ply/printxf.h>

/* allow domains an easy way to defer standard specifiers to the
 * system's implementation. */
int printxf_vfprintf(struct printxf *pxf,
		     FILE *fp, const char *spec, va_list ap)
{
	return vfprintf(fp, spec, ap);
}

int __printxf_wsegment(FILE *fp, const char **fmt, size_t ssize, size_t *tsize)
{
	size_t wsize;

	wsize = fwrite(*fmt, 1, ssize, fp);
	*tsize += wsize;
	*fmt   += wsize;

	return (wsize < ssize) ? EOF : 0;
}

int __printxf(struct printxf *pxf, FILE *fp, const char *fmt,
	      void *priv, va_list ap)
{
	size_t tsize = 0, wsize, ssize;
	vfprintxf_fn handler;
	char spec[16];
	int type;

	if (!pxf)
		pxf = &printxf_default;

	if (!fmt)
		return 0;

	while (*fmt) {
		ssize = strcspn(fmt, "%");

		/* leading segment containing no format specifiers. */
		if (ssize && __printxf_wsegment(fp, &fmt, ssize, &tsize))
			break;

		if (fmt[0] == '\0') {
			/* this was the last segment */
			break;
		} else if ((fmt[0] == '%')
			   && ((fmt[1] == '\0') || (fmt[1] == '%'))) {
			/* "%" or "%%", write "%" */
			if (!fwrite("%", 1, 1, fp))
				break;

			tsize++;
			fmt += fmt[1] ? 2 : 1;
			continue;
		}
		
		ssize = strspn(fmt + 1, " #'*+,-.0123456789Lhjlqtz") + 1;

		if (!fmt[ssize]) {
			/* corner case. fmt ends with an unterminated
			 * format. e.g. "evilness: 100%" */
			__printxf_wsegment(fp, &fmt, ssize, &tsize);
			break;
		}

		type = fmt[ssize] & 0x7f;
		if ((priv && !pxf->xfprintxf[type])
		    || !pxf->vfprintxf[type]) {
			/* unsupported specifier, write the entire
			 * specifier unformatted to the output */
			if (__printxf_wsegment(fp, &fmt, ssize + 1, &tsize))
				break;

			continue;
		}

		ssize++;
		memset(spec, '\0', sizeof(spec));
		strncpy(spec, fmt, (ssize >= sizeof(spec)) ? sizeof(spec) - 1 : ssize);
		fmt += ssize;

		if (priv)
			tsize += pxf->xfprintxf[type](pxf, fp, spec, priv);
		else {
			va_list aq;
			char *tmp;

			va_copy(aq, ap);
			tsize += pxf->vfprintxf[type](pxf, fp, spec, aq);
			va_end(aq);

			/* After printing the specifier using a copy
			 * of `ap`, fast forward the original `ap` to
			 * the same state. */

			for (tmp = spec; *tmp; tmp++) {
				if (*tmp == '*') {
					int dummy_int = va_arg(ap, int);
				}
			}

			/* This is ugly, but this is the only portable
			 * way I can think of that let's us use our
			 * libc's vfprintf implementation. NOTE: We
			 * can assume nothing about the underlying
			 * type of `va_list` as it varies between
			 * architectures, we can only use the va_*
			 * family of functions/macros. */
			switch (type) {
			case 'a': case 'A':
			case 'e': case 'E':
			case 'f': case 'F':
			case 'g': case 'G':
				if (strstr(spec, "L")) {
					long double dummy_ld = va_arg(ap, long double);
				} else {
					double dummy_d = va_arg(ap, double);
				}
				break;

			case 'c':
			case 'd': case 'i':
			case 'o': case 'u':
			case 'x': case 'X':
				if (strstr(spec, "ll") || strstr(spec, "q")) {
					long long int dummy_ll = va_arg(ap, long long int);
				} else if (strstr(spec, "l")) {
					long int dummy_l = va_arg(ap, long int);
				} else {
					int dummy_int = va_arg(ap, int);
				}
				break;

			case 'p': case 's':
			default:
				/* Extensions must consume exactly one
				 * pointer. */
				do { void *dummy_ptr = va_arg(ap, void *); } while (0);
				break;
			}
		}
	}

	return tsize;
}

int xfprintxf(struct printxf *pxf, FILE *fp, const char *fmt, void *priv)
{
	va_list ap;

	return __printxf(pxf, fp, fmt, priv, ap);
}

int vfprintxf(struct printxf *pxf, FILE *fp, const char *fmt, va_list ap)
{
	return __printxf(pxf, fp, fmt, NULL, ap);
}

int fprintxf(struct printxf *pxf, FILE *fp, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vfprintxf(pxf, fp, fmt, ap);
	va_end(ap);
	return ret;
}

int vprintxf(struct printxf *pxf, const char *fmt, va_list ap)
{
	return vfprintxf(pxf, stdout, fmt, ap);
}

int printxf(struct printxf *pxf, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vprintxf(pxf, fmt, ap);
	va_end(ap);
	return ret;
}

struct printxf printxf_default = {
	.vfprintxf = {
		['a'] = printxf_vfprintf, ['A'] = printxf_vfprintf,
		['c'] = printxf_vfprintf, ['d'] = printxf_vfprintf,
		['e'] = printxf_vfprintf, ['E'] = printxf_vfprintf,
		['f'] = printxf_vfprintf, ['F'] = printxf_vfprintf,
		['g'] = printxf_vfprintf, ['G'] = printxf_vfprintf,
		['i'] = printxf_vfprintf, ['o'] = printxf_vfprintf,
		['p'] = printxf_vfprintf, ['s'] = printxf_vfprintf,
		['u'] = printxf_vfprintf,
		['x'] = printxf_vfprintf, ['X'] = printxf_vfprintf,
	},
};
