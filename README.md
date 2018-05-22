IMPORTANT
=========

The branch you are viewing shows version 2 of ply which is still under
**HEAVY** development. Documentation and examples are **not** in sync
with the implementation. See the v1.x branch for the (less un)stable
version of `ply`.

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
	@.quantize(retval());
}
```

This example shows a very simple script that instruments the return of
the `read(2)` syscall and records the distribution of the return
argument.

```
wkz@wkz-x260:~$ sudo ply -c 'kretprobe:SyS_read{ @.quantize(retval()); }'
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

### Stack Traces

```
kprobe:i2c_transfer
{
	printf("%v\n", stack())
}
```

Sometimes it can be useful to know how a particular location is
reached. kprobes can get the current stack trace via the `stack()`
function. In this example, the stack trace is simply printed to
stdout, but it can also be used as a map key in an
aggregation. I.e. it is possible to do frequency counting based on how
a function was reached.

```
root@chaos:~ $ ply -c 'kprobe:i2c_transfer { printf("%v\n", stack()) }' &
root@chaos:~ $ 1 probe active

root@chaos:~ $ hwclock -r

	i2c_transfer
	i2c_smbus_read_i2c_block_data+0x58
	ds1307_native_smbus_read_block_data+0x88
	ds1307_get_time+0x38
	__rtc_read_time+0x54
	rtc_read_time+0x3c
	rtc_dev_ioctl+0x318
	do_vfs_ioctl+0xa0
	sys_ioctl+0x44
	__sys_trace_return
Mon Feb 20 18:33:33 2017  0.000000 seconds
root@chaos:~ $ fg
ply -c "kprobe:i2c_transfer { printf(\"%v\n\", stack()) }"
^Cde-activating probes
root@chaos:~ $
```

### Opensnoop

```
#!/usr/bin/env ply

kprobe:SyS_open
{
	printf("%16s(%5d): %s\n", comm(), pid(), mem(arg(0), "128s"));
}
```

Every time a process calls `open` print the calling process's `comm`,
i.e. executable name, PID and the filename by extracting a 128-byte
string from the address of the first argument.

```
wkz@wkz-x260:~$ sudo ./opensoop.ply
1 probe active
             ply(28836): /sys/kernel/debug/tracing/events/enable
 SimpleCacheWork( 5818): /home/wkz/.cache/google-chrome/Default/Cache/37586f4b9464a393_0
      irqbalance( 1083): /proc/interrupts
      irqbalance( 1083): /proc/stat
      irqbalance( 1083): /proc/irq/18/smp_affinity
      irqbalance( 1083): /proc/irq/126/smp_affinity
      irqbalance( 1083): /proc/irq/128/smp_affinity
      irqbalance( 1083): /proc/irq/122/smp_affinity
      irqbalance( 1083): /proc/irq/11/smp_affinity
      irqbalance( 1083): /proc/irq/124/smp_affinity
      irqbalance( 1083): /proc/irq/16/smp_affinity
      irqbalance( 1083): /proc/irq/1/smp_affinity
      irqbalance( 1083): /proc/irq/8/smp_affinity
      irqbalance( 1083): /proc/irq/9/smp_affinity
      irqbalance( 1083): /proc/irq/12/smp_affinity
      irqbalance( 1083): /proc/irq/120/smp_affinity
      irqbalance( 1083): /proc/irq/121/smp_affinity
 Chrome_IOThread( 5361): /dev/shm/.org.chromium.Chromium.59XkZF
 SimpleCacheWork( 5818): /home/wkz/.cache/google-chrome/Default/Cache/37586f4b9464a393_0
     Core Thread( 5368): /home/wkz/.config/spotify/Users/wkz-user/pending-messages.tmp
     Core Thread( 5368): /home/wkz/.config/spotify/Users/wkz-user/pending-messages.tmp
 SimpleCacheWork( 5818): /home/wkz/.cache/google-chrome/Default/Cache/37586f4b9464a393_0
 SimpleCacheWork( 5818): /home/wkz/.cache/google-chrome/Default/Cache/37586f4b9464a393_0
      irqbalance( 1083): /proc/interrupts
      irqbalance( 1083): /proc/stat
      irqbalance( 1083): /proc/irq/18/smp_affinity
      irqbalance( 1083): /proc/irq/126/smp_affinity
      irqbalance( 1083): /proc/irq/128/smp_affinity
      irqbalance( 1083): /proc/irq/122/smp_affinity
      irqbalance( 1083): /proc/irq/11/smp_affinity
      irqbalance( 1083): /proc/irq/124/smp_affinity
      irqbalance( 1083): /proc/irq/16/smp_affinity
      irqbalance( 1083): /proc/irq/1/smp_affinity
      irqbalance( 1083): /proc/irq/8/smp_affinity
      irqbalance( 1083): /proc/irq/9/smp_affinity
      irqbalance( 1083): /proc/irq/12/smp_affinity
      irqbalance( 1083): /proc/irq/120/smp_affinity
      irqbalance( 1083): /proc/irq/121/smp_affinity
 SimpleCacheWork( 5818): /home/wkz/.cache/google-chrome/Default/Cache/37586f4b9464a393_0
 SimpleCacheWork( 5740): /home/wkz/.cache/google-chrome/Default/Cache/37586f4b9464a393_0
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
