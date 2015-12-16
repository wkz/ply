#ifndef _DTL_H
#define _DTL_H

#include <stdio.h>

#define _d(_fmt, ...) fprintf(stderr, "DEBUG %s: " _fmt "\n", __func__, ##__VA_ARGS__)
#define _e(_fmt, ...) fprintf(stderr, "ERROR %s: " _fmt "\n", __func__, ##__VA_ARGS__)

#endif	/* _DTL_H */
