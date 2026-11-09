# Local QEMU WHPX build

English | [中文](qemu-build.zh-CN.md)

The executable is a local QEMU 11.1.0 build with
[`qemu-11.1-whpx-xsave-ecx.patch`](../../../scripts/patches/qemu-11.1-whpx-xsave-ecx.patch).
It is separate from AgentProvenance's CLI and the original Windows QEMU install.
The original executable, launcher and VM backing image are retained; testing uses
an independent qcow2 overlay.

Sources: [official QEMU archive](https://download.qemu.org/qemu-11.1.0.tar.xz),
[WHPX implementation](https://github.com/qemu/qemu/blob/v11.1.0/target/i386/whpx/whpx-all.c),
[QEMU build instructions](https://www.qemu.org/docs/master/devel/build-environment.html).
`source-identity.json` records the archive and executable SHA-256 values.
`qemu-dependencies.json` records the downloaded MSYS2 dependency packages.

The local build uses Ubuntu's MinGW-w64 POSIX compiler, Ninja and Python. MSYS2
MINGW64 glib2, pixman, libslirp and zlib headers/import libraries are extracted
into a separate dependency directory; their pkg-config prefixes point there.
Configure in a separate build directory after applying the patch:

```sh
patch -p1 < /path/to/AgentProvenance/scripts/patches/qemu-11.1-whpx-xsave-ecx.patch
mkdir build-whpx
cd build-whpx
QEMU_DEPS=/absolute/path/to/mingw64
PKG_CONFIG=/usr/bin/pkg-config \
PKG_CONFIG_LIBDIR="$QEMU_DEPS/lib/pkgconfig" \
../configure --target-list=x86_64-softmmu \
  --cross-prefix=x86_64-w64-mingw32- \
  --disable-werror --disable-docs --disable-tools --disable-guest-agent \
  --disable-tcg --enable-whpx --enable-slirp --disable-rust \
  --extra-cflags="-I$QEMU_DEPS/include" \
  --extra-ldflags="-L$QEMU_DEPS/lib"
ninja -j6 qemu-system-x86_64.exe
```

The Windows executable uses the extracted DLL dependencies. `libssp-0.dll` and
`libwinpthread-1.dll` come from the original QEMU 11.1.0 installation; their hashes
are recorded with the runtime. Firmware is read from that installation's `share`
directory with `-L`. The selected accelerator remains `whpx`, and the CPU model
remains `max`.

The patch restores the XSAVE component attributes, including the supervisor-state
bit for CET. Validation checks CPUID, boot messages, explicitly enabled shadow
stacks, context switches and the native sensor suite. It does not modify Windows
security settings or disable CET.
