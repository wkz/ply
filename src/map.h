#pragma once

#include "lang/ast.h"

void dump_sym(FILE *fp, node_t *integer, void *data);
int  cmp_node(node_t *n, const void *a, const void *b);

int map_setup   (node_t *script);
int map_teardown(node_t *script);
