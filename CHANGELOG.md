# Changelog

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
