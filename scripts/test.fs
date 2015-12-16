
kprobe:SyS_read / comm() == "ash" / {
	trace("pid:%d\n", pid())
}

kprobe:SyS_* {
	s[func(), comm()] = @count()
}


--

kprobe:SyS_read / comm() == "ash" / {
	ash = true
}

kprobe:mdio_* / ash / {
	trace("> %s\", func())
}

kprobe:mdio_*:return / ash / {
	trace("< %s\", func())
}
