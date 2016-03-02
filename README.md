ply
===

A dynamic tracer for Linux.

`ply` compiles ply-scripts into Linux [BPF][1] programs that can be
attached to kprobes in the kernel. The script has a C-like syntax,
taking inspiration from `awk(1)`. The compiler is very rudimentary and
only supports a handful of built-in functions and access to CPU
registers in probes at present. On the other hand, the only run-time
dependency is libc, which means you can run it on just about any Linux
based system with a modern kernel.

For a more complete documentation of the ply-script language, see
[wkz.github.io/ply][2].

Build and Installation
----------------------

`ply` uses GNU's autotools as its build system. When building from
a Git clone, use the following steps:

```
./autogen.sh   # to generate the configure script
./configure
make
make install   # you probably need to be root for this
```

If you are *not* building against the kernel that your distro has
installed, you need to tell `configure` where to find it:

```
./configure --with-kerneldir=/path/to/shiny/linux
```

Examples
-------

### Syscall Count

```
#!/usr/bin/env ply

kprobe:SyS_*
{
	$syscalls[func].count()
}
```

This probe will be attached to all functions whose name starts with
`SYS_`, i.e. all syscalls. On each syscall, the probe will fire and
index into the user-defined map `$syscalls` using the built-in
variable `func` as the key and bump a counter.

`ply` will compile the script, attach it to the matching probes and
start collecting data. On exit, `ply` will dump the value of all
user-defined variables and maps:

```
wkz@wkz-box:~$ sudo syscall-count.ply
331 probes active
^Cde-activating probes

$syscalls:
sys_mprotect        	       1
sys_readv           	       1
sys_newlstat        	       1
sys_access          	       2
sys_bind            	       3
sys_getsockname     	       3
sys_rt_sigaction    	       4
sys_ftruncate       	       4
sys_unlink          	       4
sys_pselect6        	       4
sys_timerfd_settime 	       4
sys_dup             	       5
sys_fdatasync       	       5
sys_lseek           	      17
sys_inotify_add_watch	      21
sys_newstat         	      24
sys_recvfrom        	      31
sys_connect         	      33
sys_socket          	      36
sys_getsockopt      	      42
sys_epoll_ctl       	      58
sys_pread64         	      66
sys_openat          	      67
sys_setsockopt      	      85
sys_newuname        	     112
sys_getdents        	     136
sys_timer_settime   	     159
sys_pwrite64        	     172
sys_rt_sigprocmask  	     380
sys_clock_gettime   	     407
sys_nanosleep       	    1183
sys_newfstat        	    1657
sys_open            	    1663
sys_close           	    1899
sys_madvise         	    2251
sys_sendmsg         	    3980
sys_sendto          	    4024
sys_fcntl           	    6534
sys_ppoll           	    7436
sys_mmap            	   10801
sys_setitimer       	   14201
sys_select          	   14624
sys_munmap          	   14778
sys_mmap_pgoff      	   14887
sys_epoll_wait      	   14898
sys_writev          	   19516
sys_write           	   22644
sys_read            	   28700
sys_poll            	   53401
sys_futex           	   78401
sys_ioctl           	  146141
sys_recvmsg         	  181933
```

### Distributions

```
#!/usr/bin/env ply

kprobe:SyS_read
{
	$sizes.quantize(arg(2))
}
```

This example shows a very simple script that instruments the `read(2)`
syscall and records the distribution of the `size` argument,
i.e. argument 2 (zero indexed), into the user-defined variable
`$sizes`.

```
wkz@wkz-box:~$ sudo read-dist.ply
1 probe active
^Cde-activating probes

$sizes:
[   0,    1]	    2089
[   2,    4)	     434
[   4,    8)	    6334
[   8,   16)	    9738
[  16,   32)	    1645
[  32,   64)	      16
[  64,  128)	      24
[ 128,  256)	      63
[ 256,  512)	     102
[ 512,   1k)	     200
[  1k,   2k)	     433
[  2k,   4k)	     750
[  4k,   8k)	    1492
[  8k,  16k)	    1157
[ 16k,  32k)	    5703
[ 32k,  64k)	      26
[ 64k, 128k)	      48
```

Motivation
----------

The intention of `ply` is to be a lightweight alternative to
[bcc][3]. Both in terms of dependencies and in usage. `bcc` requires
LLVM which rules out many embedded platforms. `ply` has no run-time
dependencies and only depends on flex and bison to build. By using the
[Little Language][4] approach, scripts are easy to write and
modify. C, while being an extremely powerful and elegant language does
not offer the same exploratory feeling as say `awk`, which `ply` more
closely resembles.


[1]: https://www.kernel.org/doc/Documentation/networking/filter.txt
[2]: https://wkz.github.io/ply
[3]: https://github.com/iovisor/bcc
[4]: http://c2.com/cgi/wiki?LittleLanguage