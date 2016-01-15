kprobe:SyS_open {
	/* opens[comm()] += 1; */
	trace("pc: %p\n", reg("pc"));
}

/* kprobe:SyS_* { */
/* 	sc[func()] += 1; */
/* } */

/* ply:END { */
/* 	hbar(sc); */
/* } */

/* kprobe:SyS_open / pid() != 63 / { */
/*         trace("open from %d\n", pid()); */
/* } */

/* kprobe:SyS_open / !strcmp("sh", comm()) / { */
/* 	trace("open from sh\n"); */
/* } */

/* kprobe:SyS_read { */
/* 	/\* a = pid() + (5 * 9); *\/ */

/* 	b = a + 1; */

/* 	sz[comm(), pid()] @ count(); */
/* } */

/* kprobe:SyS_write { */
/* 	a = 1; */
/* } */

