Testing
=======

Build and test `ply` for/on multiple architectures. Toolchains and
root filesystems are automatically downloaded, the user only has to
make sure that the `squashfs-tools` and `qemu-system` packages are
installed, in order to use it.

OS profile images from the [NetBox][1] project provide the root
filesystems; toolchains are fetched from Bootlin's [toolchain
site][2]. The following machine types are supported:

| Machine | NetBox Platform |
|---------|-----------------|
| aarch64 | envoy           |
| armv5   | basis           |
| armv7   | dagger          |
| powerpc | coronet         |
| x86_64  | zero            |

Three primary `make` targets per machine are provided for the
end-user:

- `MACH-build`: Verify that `ply` can be successfully built for `MACH`
  without warnings.
- `MACH-check`: Verify that the `ply` test suite can be successfully
  run on `MACH` (implies `MACH-build`).
- `MACH-shell`: Start an interactive session to a QEMU instance
  running `MACH` (implies `MACH-build`).

Machine names and NetBox platform names may be used interchangeably,
i.e. `make armv7-check` is equivalent to `make dagger-check`.

[1]: https://github.com/westermo/netbox
[2]: https://toolchains.bootlin.com
