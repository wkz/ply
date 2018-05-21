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

#ifndef _PLY_PERF_EVENT_H
#define _PLY_PERF_EVENT_H

#define TRACEPATH "/sys/kernel/debug/tracing/"

struct ply_probe;

int perf_event_attach(struct ply_probe *pb, const char *name);

int perf_event_enable (int group_fd);
int perf_event_disable(int group_fd);

#endif	/* _PLY_PERF_EVENT_H */
