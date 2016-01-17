kprobe:SyS_open {
	/* opens[comm()] += 1; */
	/* trace("pc: %p\n", reg("pc")); */
	/* opens[0, 1, "hejsansaaa"] += 1; */
	/* opens[0] = "hej"; */
	/* test[0] = opens["hoj", 0x1337, 1]; */
	/* opens["lol", 1, 1] = ["wow", "hej"]; */
	opens[comm()] += 1;	
}

/* kprobe:SyS_* { */
/* 	opens["hej", pid(), 1] = ["BU!", 2]; */
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

