#ifndef _PLY_PROVIDER_XPROBE_H
#define _PLY_PROVIDER_XPROBE_H

int   xprobe_stem  (struct ply_probe *pb, char type, char *stem, size_t size);
int   xprobe_create(FILE *ctrl, const char *stem, const char *func);
int   xprobe_glob  (struct ply_probe *pb, glob_t *gl);
char *xprobe_func  (struct ply_probe *pb, char *path);

#endif	/* _PLY_PROVIDER_XPROBE_H */
