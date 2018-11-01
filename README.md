ply
===

Documentation and language reference is available at
[wkz.github.io/ply][3].

A light-weight dynamic tracer for Linux that leverages the kernel's
BPF VM in concert with kprobes and tracepoints to attach probes to
arbitrary points in the kernel. Most tracers that generate BPF
bytecode are based on the LLVM based BCC toolchain. ply on the other
hand has no required external dependencies except for `libc`. In
addition to `x86_64`, ply also runs on `aarch64`, `arm`, and
`powerpc`. Adding support for more ISAs is easy.

`ply` follows the [Little Language][1] approach of yore, compiling ply
scripts into Linux [BPF][2] programs that are attached to kprobes and
tracepoints in the kernel. The scripts have a C-like syntax, heavily
inspired by `dtrace(1)` and, by extension, `awk(1)`.

The primary goals of `ply` are:

   * Expose most of the BPF tracing feature-set in such a way that new
     scripts can be whipped up very quickly to test different
     hypotheses.

   * Keep dependencies to a minimum. Right now Flex and Bison are
     required at build-time, leaving `libc` as the only runtime
     dependency. Thus, `ply` is well suited for embedded targets.

If you need more fine-grained control over the kernel/userspace
interaction in your tracing, checkout the [bcc][4] project which
compiles C programs to BPF using LLVM in combination with a python
userspace recipient to give you the full six degrees of freedom.


Examples
--------

### Syscall Tracing

**`read()` return size, summarized as a power-of-2 histogram:**
```
ply 'kretprobe:SyS_read { @["size"] = quantize(retval); }'
```

**`read()` request size, as a power-of-2 histogram, for reads > 1 kB, grouped by pid:**
```
ply 'kprobe:SyS_read / arg2 > 1024 / { @[pid] = quantize(arg2); }'
```

**`open()` Print process name, pid and the file that was opened:**
```
ply 'kprobe:do_sys_open { printf("%v(%v): %s\n", comm, pid, str(arg1)); }'
```

**Count all system calls by syscall type:**
```
ply 'kprobe:SyS_* { @[caller] = count(); }'
```

**Count all system calls by process name and pid:**
```
ply 'kprobe:SyS_* { @[comm, pid] = count(); }'
```

### Stack Traces

**Frequency count all different paths to `schedule`:**
```
ply 'kprobe:schedule { @[stack] = count(); }'
```

### Tracepoints

**Monitor all incoming TCP resets:**
```
ply 'tracepoint:tcp/tcp_receive_reset {
	printf("saddr:%v port:%v->%v\n",
		data->saddr, data->sport, data->dport);
}'
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
