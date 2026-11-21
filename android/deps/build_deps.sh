#!/bin/bash
# Cross-compile FFTW3f and OpenSSL libcrypto for Android arm64-v8a (API 29).
set -euo pipefail
D=${MESH_DEPS_DIR:-$HOME/Android/deps}
NDK=${ANDROID_NDK_HOME:-$HOME/Android/sdk/ndk/27.2.12479018}
TC=$NDK/toolchains/llvm/prebuilt/linux-x86_64
API=29
ABI=arm64-v8a
PREFIX=$D/$ABI
mkdir -p "$D/src" "$PREFIX"
cd "$D/src"
log() { echo "[deps] $*"; }

if [ ! -f "$PREFIX/lib/libfftw3f.a" ]; then
  log "FFTW 3.3.10"
  [ -f fftw-3.3.10.tar.gz ] || curl -fsSLO https://www.fftw.org/fftw-3.3.10.tar.gz
  echo "56c932549852cddcfafdab3820b0200c7742675be92179e59e6215b340e26467  fftw-3.3.10.tar.gz" | sha256sum -c -
  rm -rf fftw-3.3.10 && tar xzf fftw-3.3.10.tar.gz && cd fftw-3.3.10
  ./configure --host=aarch64-linux-android --prefix="$PREFIX" \
     --enable-float --enable-neon --enable-threads --with-combined-threads \
     --disable-fortran --disable-doc --enable-static --disable-shared \
     CC="$TC/bin/aarch64-linux-android$API-clang" AR="$TC/bin/llvm-ar" RANLIB="$TC/bin/llvm-ranlib" \
     CFLAGS="-O3 -fPIC" > ../fftw-configure.log
  make -j"$(nproc)" > ../fftw-make.log && make install > /dev/null
  cd ..
fi

if [ ! -f "$PREFIX/lib/libcrypto.a" ]; then
  log "OpenSSL 3.0.15 (libcrypto)"
  [ -f openssl-3.0.15.tar.gz ] || curl -fsSLO https://github.com/openssl/openssl/releases/download/openssl-3.0.15/openssl-3.0.15.tar.gz
  echo "23c666d0edf20f14249b3d8f0368acaee9ab585b09e1de82107c66e1f3ec9533  openssl-3.0.15.tar.gz" | sha256sum -c -
  rm -rf openssl-3.0.15 && tar xzf openssl-3.0.15.tar.gz && cd openssl-3.0.15
  export ANDROID_NDK_ROOT=$NDK PATH=$TC/bin:$PATH
  ./Configure android-arm64 -D__ANDROID_API__=$API no-shared no-tests no-engine \
     --prefix="$PREFIX" --libdir=lib > ../openssl-configure.log
  make -j"$(nproc)" build_libs > ../openssl-make.log
  make install_dev > /dev/null
  cd ..
fi
log "DONE"
ls -la "$PREFIX/lib"/*.a
