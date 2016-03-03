# ply one-liners

Some sample one-liners using ply: a Linux dynamic tracer using BPF.

**Syscall read() request size, summarized as a power-of-2 histogram:**
```
ply -c 'kprobe:SyS_read { $bytes.quantize(arg(2)); }'
```

**Syscall read() request size, as a power-of-2 histogram, for reads > 1024 bytes:**
```
ply -c 'kprobe:SyS_read /arg(2) > 1024/ { $bytes.quantize(arg(2)); }'
```

**Syscall read() requests larger than 100 Kbytes, as per-event output with timestamp, process name, and size:**
```
ply -c 'kprobe:SyS_read /arg(2) > 102400/ { printf("%d %s requested %d bytes\n", nsecs, execname, arg(2)); }'
```

**Count syscall read() by CPU ID:**
```
ply -c 'kprobe:SyS_read { $reads[cpu].count() }'
```

**Count all system calls by syscall type:**
```
ply -c 'kprobe:SyS_* { $syscalls[func].count() }'
```

**Count all system calls by process name:**
```
ply -c 'kprobe:SyS_* { $syscalls[execname].count() }'
```

**Syscall read() request size, as a power-of-2 histogram, measured for 5 seconds:**
```
ply -t 5 -c 'kprobe:SyS_read { $bytes.quantize(arg(2)); }'
```

Apart from one-liners, ply can also execute scripts. For more about ply, see: https://github.com/iovisor/ply
