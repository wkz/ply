#pragma once

#include "lang/ast.h"

void dump_sym(node_t *integer, void *data);

int map_setup   (node_t *script);
int map_teardown(node_t *script);
