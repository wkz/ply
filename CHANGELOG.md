# Changelog

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
