
kprobe:SyS_read {
	/* a = pid() + (5 * 9); */

	b = a + 1;

	sz[comm(), pid()] @ count();
}

kprobe:SyS_write {
	a = 1;
}
