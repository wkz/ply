#pragma once

#include <stdio.h>

#include "lang/ast.h"

#define _d(_fmt, ...) fprintf(stderr, "DEBUG %s: " _fmt "\n", __func__, ##__VA_ARGS__)
#define _e(_fmt, ...) fprintf(stderr, "ERROR %s: " _fmt "\n", __func__, ##__VA_ARGS__)
#define _pe(_fmt, ...) _e("errno:%d " _fmt "\n", errno, ##__VA_ARGS__)

char *str_escape(char *str);

int annotate_script(node_t *script);
