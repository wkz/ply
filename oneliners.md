# ply one-liners

Some sample one-liners using ply: a Linux dynamic tracer using BPF.

### Syscall Tracing

**`read()` return size, summarized as a power-of-2 histogram:**
```
ply -c 'kretprobe:SyS_read { @.quantize(retval()) }'
```

**`read()` request size, as a power-of-2 histogram, for reads > 1 kB, grouped by pid:**
```
ply -c 'kprobe:SyS_read / arg(2) > 1024 / { @[pid()].quantize(arg(2)); }'
```

**`open()` Print process name, pid and the file that was opened:**
```
ply -c 'kprobe:SyS_open { printf("%16s(%5d): %s\n", comm(), pid(), mem(arg(0), "128s")) }'
```

**Count all system calls by syscall type:**
```
ply -c 'kprobe:SyS_* { @[func()].count() }'
```

**Count all system calls by process name and pid:**
```
ply -c 'kprobe:SyS_* { @[comm(), pid()].count() }'
```

### Stack Traces

**Frequency count all different paths to `schedule`:**
```
ply -c 'kprobe:schedule { @[stack()].count() }'
```

### Profile

**Sample process names on-cpu 1000 times per second:**
```
ply -c 'profile:1000 { @c[comm()].count();}'
```

