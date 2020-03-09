/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef _PLY_BPF_SYSCALL_H
#define _PLY_BPF_SYSCALL_H

#include <unistd.h>

#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <linux/version.h>

int bpf_prog_load(enum bpf_prog_type type,
		  const struct bpf_insn *insns, int insn_cnt,
		  char *vlog, size_t vlog_sz);

int bpf_map_create(enum bpf_map_type type, int key_sz, int val_sz, int entries);

int bpf_map_lookup(int fd, void *key, void *val);
int bpf_map_update(int fd, void *key, void *val, int flags);
int bpf_map_delete(int fd, void *key);
int bpf_map_next  (int fd, void *key, void *next_key);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0))
#define LINUX_HAS_STACKMAP
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0))
#define LINUX_HAS_TRACEPOINT
#endif

int perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
		    int cpu, int group_fd, unsigned long flags);

#endif	/* _PLY_BPF_SYSCALL_H */
