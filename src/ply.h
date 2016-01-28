#pragma once

#include <stdio.h>

#include "lang/ast.h"

#define PRINTF_BUF_LEN 64
#define PRINTF_META_OF (1 << 30)

#define _d(_fmt, ...) if (debug) { fprintf(stderr, "DEBUG %s: " _fmt "\n", __func__, ##__VA_ARGS__); }
#define _e(_fmt, ...) fprintf(stderr, "ERROR %s: " _fmt "\n", __func__, ##__VA_ARGS__)
#define _pe(_fmt, ...) _e("errno:%d " _fmt "\n", errno, ##__VA_ARGS__)

extern int debug;

char *str_escape(char *str);

int annotate_script(node_t *script);
