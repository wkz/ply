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

#ifndef _PLY_EVPIPE_H
#define _PLY_EVPIPE_H

#include <stdint.h>

#include <linux/perf_event.h>

#include <sys/queue.h>

struct evreturn {
	int val;
	unsigned err:1;
	unsigned exit:1;
};

typedef struct event {
	struct perf_event_header hdr;
	uint32_t size;

	uint64_t type;
	uint8_t  data[0];
} __attribute__((packed)) event_t;

typedef struct evhandler {
	TAILQ_ENTRY(evhandler) node;

	uint64_t type;
	void *priv;

	struct evreturn (*handle)(event_t *ev, void *priv);
} evhandler_t;

struct evqueue;

struct evpipe {
	int mapfd;

	uint32_t ncpus;
	struct pollfd *poll;
	struct evqueue *q;

	int strict;
};

void evhandler_register(evhandler_t *evh);

struct evreturn evpipe_loop(struct evpipe *evp);
int evpipe_init(struct evpipe *evp, size_t qsize, int strict);

#endif	/* _PLY_EVPIPE_H */
