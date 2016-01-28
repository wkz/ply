#pragma once

#include "lang/ast.h"

void map_dump(mdyn_t *mdyn);

int map_setup   (node_t *script);
int map_teardown(node_t *script);
