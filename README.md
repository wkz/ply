ply
===

A dynamic tracer for Linux that lets you:

   * Extract arbitrary data, i.e register values, function arguments,
     stack/heap data, stack traces.

   * Perform in-kernel aggregations on arbitrary data.

`ply` follows the [Little Language][1] approach of yore, compiling ply
scripts into Linux [BPF][2] programs that are attached to kprobes and
tracepoints in the kernel. The scripts have a C-like syntax, heavily
inspired by `dtrace(1)` and by extension `awk(1)`.

The primary goals of `ply` are:

   * Expose most of the BPF tracing feature-set in such a way that new
     scripts can be whipped up very quickly to test different
     hypotheses.

   * Keep dependencies to a minimum. Right now Flex and Bison are
     required at build-time, leaving `libc` as the only runtime
     dependency. Thus, `ply` is well suited for embedded targets.

For a more complete documentation and language reference, see
[wkz.github.io/ply][3].

If you need more fine-grained control over the kernel/userspace
interaction in your tracing, checkout the [bcc][4] project which
compiles C programs to BPF using LLVM in combination with a python
userspace recipient to give you the full six degrees of freedom.


Examples
-------

### Syscall Count

```
kprobe:SyS_*
{
	@[func()].count();
}
```

This probe will be attached to all functions whose name starts with
`SyS_`, i.e. all syscalls. On each syscall, the probe will fire and
index into the user-defined map `@` using the built-in function
`func()` as the key and bump a counter. Map names always start with
'@' and for scripts where there is only one map it is idiomatic to
simply call it '@'.

`ply` will compile the script, attach it to the matching probes and
start collecting data. On exit, the value of all user-defined maps are
dumped:

```
wkz@wkz-x260:~$ sudo ply -c 'kprobe:SyS_*{ @[func()].count(); }'
341 probes active
^Cde-activating probes

@:
sys_tgkill          	       1
sys_mprotect        	       1
sys_lseek           	       1
sys_readv           	       1
sys_rename          	       1
sys_statfs          	       1
sys_bind            	       2
sys_access          	       4
sys_fdatasync       	       5
sys_times           	       6
<REDACTED LINES>
sys_epoll_wait      	    7211
sys_ppoll           	    9836
sys_poll            	   13446
sys_futex           	   20034
sys_ioctl           	   23806
sys_recvmsg         	   23989
sys_write           	   24791
sys_read            	   32168
```

### Read Distribution

```
kretprobe:SyS_read
{
	@[""].quantize(retval());
}
```

This example shows a very simple script that instruments the return of
the `read(2)` syscall and records the distribution of the return
argument. Due to a quirk in the language, a key must be supplied, so
the empty string is used as a dummy.

```
wkz@wkz-x260:~$ sudo ply -c 'kretprobe:SyS_read{ @[""].quantize(retval()); }'
1 probe active
^Cde-activating probes

@:

	         < 0	    8869 ┤███████                         │
	           0	     565 ┤▌                               │
	           1	   13460 ┤██████████▋                     │
	[   2,    3]	    1915 ┤█▌                              │
	[   4,    7]	    1736 ┤█▍                              │
	[   8,   15]	   10054 ┤████████                        │
	[  16,   31]	    2583 ┤██                              │
	[  32,   63]	     769 ┤▋                               │
	[  64,  127]	      55 ┤                                │
	[ 128,  255]	       5 ┤                                │
	[ 256,  511]	     202 ┤▏                               │
	[ 512,   1k)	      27 ┤                                │
	[  1k,   2k)	     157 ┤▏                               │
	[  2k,   4k)	       4 ┤                                │
	[  4k,   8k)	      20 ┤                                │
	[  8k,  16k)	       6 ┤                                │
	[ 16k,  32k)	      23 ┤                                │
	[ 32k,  64k)	      20 ┤                                │
```


### Opensnoop

```
#!/usr/bin/env ply

kprobe:SyS_open
{
	printf("%s: %s\n", comm(), mem(arg(0), "128s"));
}
```

Every time a process calls `open` print the calling process's `comm`,
i.e. executable name, and the filename by extracting a 128-byte string
from the address of the first argument.

```
wkz@wkz-x260:~$ sudo ./opensoop.ply
1 probe active
ply: /sys/kernel/debug/tracing/events/enable
BrowserBlocking: /home/wkz/.config/google-chrome/Default/Cookies-journal
BrowserBlocking: /var/tmp/etilqs_802095c1ff1111c4
BrowserBlocking: /home/wkz/.config/google-chrome/Default
irqbalance: /proc/interrupts
irqbalance: /proc/stat
irqbalance: /proc/irq/18/smp_affinity
irqbalance: /proc/irq/122/smp_affinity
irqbalance: /proc/irq/11/smp_affinity
irqbalance: /proc/irq/123/smp_affinity
irqbalance: /proc/irq/16/smp_affinity
irqbalance: /proc/irq/1/smp_affinity
irqbalance: /proc/irq/8/smp_affinity
irqbalance: /proc/irq/9/smp_affinity
irqbalance: /proc/irq/12/smp_affinity
irqbalance: /proc/irq/120/smp_affinity
irqbalance: /proc/irq/121/smp_affinity
systemd-timesyn: /var/lib/systemd/clock
chrome: /proc/self/status
chrome: /proc/self/status
Chrome_IOThread: /dev/shm/.com.google.Chrome.3Y4k6r
CompositorTileW: /dev/shm/.com.google.Chrome.RXT4wj
CompositorTileW: /dev/shm/.com.google.Chrome.n3cWXa
Chrome_IOThread: /dev/shm/.com.google.Chrome.phCOo2
Chrome_IOThread: /dev/shm/.com.google.Chrome.D90KPT
Chrome_IOThread: /dev/shm/.com.google.Chrome.RUgLgL
Chrome_IOThread: /dev/shm/.com.google.Chrome.3VxUHC
chrome: /proc/self/status
chrome: /proc/self/status
chrome: /proc/self/status
chrome: /proc/self/status
chrome: /proc/self/status
chrome: /proc/self/status
chrome: /proc/self/status
chrome: /proc/self/status
SimpleCacheWork: /home/wkz/.cache/google-chrome/Default/Cache/ad851e438fd4ed16_0
SimpleCacheWork: /home/wkz/.cache/google-chrome/Default/Cache/ad851e438fd4ed16_1
SimpleCacheWork: /home/wkz/.cache/google-chrome/Default/Cache/ad851e438fd4ed16_s
SimpleCacheWork: /home/wkz/.cache/google-chrome/Default/Cache/88c6f731c72489c0_0
SimpleCacheWork: /home/wkz/.cache/google-chrome/Default/Cache/88c6f731c72489c0_1
SimpleCacheWork: /home/wkz/.cache/google-chrome/Default/Cache/88c6f731c72489c0_s
Chrome_FileUser: /proc/19152/task
Chrome_FileUser: /proc/19152/task/19152/status
Chrome_FileUser: /proc/19152/task/19153/status
Chrome_FileUser: /proc/19152/task/19154/status
Chrome_FileUser: /proc/19152/task
Chrome_FileUser: /proc/19152/task/19152/status
Chrome_FileUser: /proc/19152/task/19153/status
Chrome_FileUser: /proc/19152/task
Chrome_FileUser: /proc/19152/task/19152/status
Chrome_FileUser: /proc/19152/task/19153/status
WRN evqueue_drain       : lost 6 events
Chrome_IOThread: /dev/shm/.com.google.Chrome.RBxACy
Chrome_IOThread: /dev/shm/.com.google.Chrome.l8blxu
Chrome_IOThread: /dev/shm/.com.google.Chrome.HYebsq
^Cde-activating probes
```


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


Maintainers
-----------

`ply` is developed and maintained by [Tobias Waldekranz][5]. Please
direct all bug reports and pull requests towards the official
[Github][6] repo.

[1]: http://c2.com/cgi/wiki?LittleLanguage
[2]: https://www.kernel.org/doc/Documentation/networking/filter.txt
[3]: https://wkz.github.io/ply
[4]: https://github.com/iovisor/bcc
[5]: mailto://tobias@waldekranz.com
[6]: https://github.com/iovisor/ply
