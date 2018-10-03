#ifndef _PLY_PROVIDER_KPROBE_H
#define _PLY_PROVIDER_KPROBE_H

extern const struct func kprobe_regs_func;

int kprobe_ir_pre(struct ply_probe *pb);

#endif	/* _PLY_PROVIDER_KPROBE_H */
