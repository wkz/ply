#ifndef _PLY_BUILT_IN_H
#define _PLY_BUILT_IN_H

#define __ply_built_in __attribute__((	\
     section("built_ins"),		\
     aligned(__alignof__(struct func))	\
))

extern const struct func __start_built_ins;
extern const struct func __stop_built_ins;

#endif	/* _PLY_BUILT_IN_H */
