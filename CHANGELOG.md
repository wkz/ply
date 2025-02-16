# Changelog

## [2.4.0] - 2025-02-16

### Added

- New architecture: mips (yejq)
- New architecture: loongarch (wuruilong)
- Output buffering can now be unconditionally disabled
- New provider: profile (Ism Hong)

### Fixed

- Incorrect stack management when accessing tracepoint data (Bjorn
  Andersson)


## [2.3.0] - 2022-11-29

Add support for riscv64. Minimum supported kernel version is now 5.5.

### Changed

- New implementation of `BEGIN`/`END` which is more reliable across
  architectures. (Mingzheng Xing)

### Added

- New architecture: riscv64 (Mingzheng Xing)


## [2.2.0] - 2021-11-26

### Changed

- kprobe wildcards are now filtered through
  available_filter_functions, if available, making them much more
  reliable.

### Added

- Self-test (ply -T) to automatically diagnose the most common
  configuration issues.
- `sum()` aggregation (Namhyung Kim).
- `BEGIN` and `END` probes that run at the beginning/end of a script
  (Namhyung Kim).
- `interval` provider to run a probe at a specified interval (Namhyung
  Kim).
- Access to dynamic tracepoint data, i.e. members marked with the
  `__data_loc` attribute.

### Fixed

- A bunch of parsing errors from weird scripts. Found via fuzzing done
  by Juraj Vijtiuk.
- Static linking is now supported (Namhyung Kim)
- Data layout issues with some tracepoints.

## [2.1.1] - 2020-04-22

### Changed

- Disable the kernel verifier output by default. Newer kernels
  generates __massive__ amounts of verifier output for certain BPF
  programs. It expects to be able to store up to 16MB (!) of text. On
  some systems using `ply`, that is half of the total system
  RAM. Instead, the verifier output is now enabled by specifying the
  `-d`/`--debug` option.

### Added

- Allow lossy tracing. By default ply will exit when it detects loss
  of any trace events. The new `-k`/`--keep-going` option allows the
  user to disable this safety check.
- `ply` can now be built against alternative libcs. In particular
  Glibc and musl are known to work.
- VPATH builds are now supported.
- Basic automatic test system. This ensures that basic ply can be
  built against all supported architectures and that basic probes work
  as expected.

### Fixed

- When expanding wildcards in probe specifiers, avoid symbols that we
  know are untraceable.
- Symbol lookups (typically in stack traces) now always return the
  correct symbol.
- Multiple references to `stack` no longer results in a `SIGSEGV`.
- The type information from `caller`/`retval` is now retained in all
  cases.

## [2.1.0] - 2018-11-01

### Added

- `tracepoint` provider to use the kernel's stable tracepoints.
- `delete` keyword to remove associations from a map.
- Numeric constants can now be in binary using the `0b` prefix.
- Numeric constants can be grouped by insering `_`'s, i.e. one million
  could be written as `1_000_000` a 32-bit address could be written as
  `0xc1ab_dead`

### Fixed

- Architecture specific files are now a part of the distribution
  tarball (#10).
- Multiple off-by-one issues with string literals have been fixed
  (#14).
- Unary operators now work with arguments that require AST rewrites
  (#11).

## [2.0.0] - 2018-10-18

The entire compiler has been re-written using the lessons learned from
the limitations of v1. There is now a proper type system that be
extended to describe all C types, there is an intermediate
representation (IR) that makes instruction selection much easier. Some
NIH accidents regarding the grammar have been corrected to align with
existing work (DTrace). Error messages on invalid scripts should be
more helpful, though there is still much to be done in this area.

### Changed
- Everything

### Removed
- Tracepoint provider. Not ported to v2 yet.
- Profile provider. Not ported to v2 yet.
- uprobe provider. Not ported to v2 yet.

### Added
- PowerPC support.
