kprobe:SyS_open {
	opens[pid()] += 1;
	/* trace("opens[%d] = %d\n", pid(), opens[pid()]); */
}

/* kprobe:SyS_open / pid() != 63 / { */
/*         trace("open from %d\n", pid()); */
/* } */

/* kprobe:SyS_open / comm() == "sh" / { */
/* 	trace("open from ash\n"); */
/* } */

/* kprobe:SyS_read { */
/* 	/\* a = pid() + (5 * 9); *\/ */

/* 	b = a + 1; */

/* 	sz[comm(), pid()] @ count(); */
/* } */

/* kprobe:SyS_write { */
/* 	a = 1; */
/* } */

