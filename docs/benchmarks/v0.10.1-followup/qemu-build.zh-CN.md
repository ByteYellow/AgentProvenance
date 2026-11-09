# 本地 QEMU WHPX 构建

[English](qemu-build.md) | 中文

当前程序基于 QEMU 11.1.0，应用了
[`qemu-11.1-whpx-xsave-ecx.patch`](../../../scripts/patches/qemu-11.1-whpx-xsave-ecx.patch)。
它独立于 AgentProvenance CLI 和原来的 Windows QEMU 安装。原版程序、启动脚本和虚拟机基础镜像均保留，测试使用单独的 qcow2 差分镜像。

源码来自 [QEMU 官方源码包](https://download.qemu.org/qemu-11.1.0.tar.xz)，修改位置是 [WHPX 实现](https://github.com/qemu/qemu/blob/v11.1.0/target/i386/whpx/whpx-all.c)。工具安装可参考 [QEMU 官方构建说明](https://www.qemu.org/docs/master/devel/build-environment.html)。源码包与程序的 SHA-256 在 `source-identity.json` 中；下载的 MSYS2 依赖包记录在 `qemu-dependencies.json` 中。

本机构建使用 Ubuntu 的 MinGW-w64 POSIX 编译器、Ninja 和 Python。MSYS2 MINGW64 的 glib2、pixman、libslirp、zlib 头文件与导入库放在独立目录，pkg-config 的前缀改为该目录。应用补丁后，在单独的构建目录执行：

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

Windows 程序使用解包后的 DLL；其中 `libssp-0.dll` 和 `libwinpthread-1.dll` 沿用原 QEMU 11.1.0 安装中的文件，运行库校验值已记录。固件通过 `-L` 指向原安装的 `share` 目录。加速器仍为 `whpx`，CPU 模型仍为 `max`。

补丁补齐了 XSAVE 组件属性，包括 CET 的 supervisor 状态位。验收检查 CPUID、启动日志、显式启用的影子栈、上下文切换和原生采集。不修改 Windows 安全设置，也不关闭 CET。
