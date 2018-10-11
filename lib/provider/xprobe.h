/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef _PLY_PROVIDER_XPROBE_H
#define _PLY_PROVIDER_XPROBE_H

struct xprobe {
	FILE *ctrl;
	const char *ctrl_name;

	char *pattern;
	char stem[0x40];

	size_t n_evs;
	int *evfds;

	char type;
};

int xprobe_detach(struct ply_probe *pb);
int xprobe_attach(struct ply_probe *pb);

#endif	/* _PLY_PROVIDER_XPROBE_H */
