#include "ply.h"

char *str_escape(char *str)
{
	char *in, *out;

	for (in = out = str; *in; in++, out++) {
		if (*in != '\\')
			continue;

		in++;
		switch (*in) {
		case 'n':
			*out = '\n';
			break;
		case 'r':
			*out = '\r';
			break;
		case 't':
			*out = '\t';
			break;
		case '\\':
			*out = '\\';
			break;
		default:
			break;
		}
	}

	if (out < in)
		*out = '\0';

	return str;
}
