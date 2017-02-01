/*
 * Copyright 2015-2016 Tobias Waldekranz <tobias@waldekranz.com>
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

#include <string.h>
#include <unistd.h>

#include <sys/syscall.h>

#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <linux/version.h>
#include <sys/syscall.h>

#include <ply/bpf-syscall.h>

char bpf_log_buf[LOG_BUF_SIZE];

static __u64 ptr_to_u64(const void *ptr)
{
        return (__u64) (unsigned long) ptr;
}

int bpf_prog_load(enum bpf_prog_type type,
		  const struct bpf_insn *insns, int insn_cnt)
{
	union bpf_attr attr;

	/* required since the kernel checks that unused fields and pad
	 * bytes are zeroed */
	memset(&attr, 0, sizeof(attr));

	attr.kern_version = LINUX_VERSION_CODE;
	attr.prog_type    = type;
	attr.insns        = ptr_to_u64(insns);
	attr.insn_cnt     = insn_cnt;
	attr.license      = ptr_to_u64("GPL");
	attr.log_buf      = ptr_to_u64(bpf_log_buf);
	attr.log_size     = LOG_BUF_SIZE;
	attr.log_level    = 1;

	return syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
}

int bpf_map_create(enum bpf_map_type type, int key_sz, int val_sz, int entries)
{
	union bpf_attr attr;

	/* required since the kernel checks that unused fields and pad
	 * bytes are zeroed */
	memset(&attr, 0, sizeof(attr));

	attr.map_type = type;
	attr.key_size = key_sz;
	attr.value_size = val_sz;
	attr.max_entries = entries;

	return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}


static int bpf_map_op(enum bpf_cmd cmd, int fd,
		      void *key, void *val_or_next, int flags)
{
	union bpf_attr attr =  {
		.map_fd = fd,
		.key = ptr_to_u64(key),
		.value = ptr_to_u64(val_or_next),
		.flags = flags,
	};

	return syscall(__NR_bpf, cmd, &attr, sizeof(attr));
}

int bpf_map_lookup(int fd, void *key, void *val)
{
	return bpf_map_op(BPF_MAP_LOOKUP_ELEM, fd, key, val, 0);
}

int bpf_map_update(int fd, void *key, void *val, int flags)
{
	return bpf_map_op(BPF_MAP_UPDATE_ELEM, fd, key, val, flags);
}

int bpf_map_delete(int fd, void *key)
{
	return bpf_map_op(BPF_MAP_DELETE_ELEM, fd, key, NULL, 0);
}

int bpf_map_next(int fd, void *key, void *next_key)
{
	return bpf_map_op(BPF_MAP_GET_NEXT_KEY, fd, key, next_key, 0);
}

long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
		     int cpu, int group_fd, unsigned long flags)
{
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
		      group_fd, flags);
	return ret;
}
