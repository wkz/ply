#ifndef _LIBBPF_H
#define _LIBBPF_H

#include <linux/bpf.h>

#define LOG_BUF_SIZE 0x1000

extern char bpf_log_buf[LOG_BUF_SIZE];

int bpf_prog_load(const struct bpf_insn *insns, int insn_cnt);

int bpf_map_create(enum bpf_map_type type, int key_sz, int val_sz, int entries);

int bpf_map_lookup(int fd, void *key, void *val);
int bpf_map_update(int fd, void *key, void *val, int flags);
int bpf_map_delete(int fd, void *key, void *val);
int bpf_map_next  (int fd, void *key, void *next_key);

#endif	/* _LIBBPF_H */
