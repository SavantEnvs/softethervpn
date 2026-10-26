#!/usr/bin/env bash
#
# mayhem/build.sh — build SoftEther VPN's fuzz harnesses (sanitized) and the oracle (normal flags).
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem; re-runnable and offline.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
# Two UBSan checks are relaxed for idioms upstream relies on everywhere; ASan and every other UBSan
# check keep halting:
#  - `function`: comparator callbacks (e.g. bsearch's CompareHamcore) are cast to the libc signature
#    and the check fires at startup before any input is read.
#  - `alignment`: packet parsers cast byte offsets inside the input buffer to packed-header structs
#    (TcpIp.c IPV6_HEADER_PACKET_INFO etc.), so any IPv6 frame would halt the fuzzer.
case "$SANITIZER_FLAGS" in *undefined*) SANITIZER_FLAGS="$SANITIZER_FLAGS -fno-sanitize=function,alignment" ;; esac
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# The submodules the Unix build needs (the OQS ones are switched off with -DOQS_ENABLE=OFF).
for f in 3rdparty/BLAKE2/ref/blake2s-ref.c 3rdparty/tinydir/tinydir.h \
         src/Mayaqua/3rdparty/cpu_features/CMakeLists.txt src/libhamcore/CMakeLists.txt; do
  [ -e "$f" ] || { echo "missing submodule file $f (git submodule update --init)" >&2; exit 1; }
done

# 1) Sanitized, SanCov-instrumented library build (mayaqua + cedar), then re-archive its objects
#    into one static archive so every harness is a single self-contained executable.
FUZZ_DIR="$SRC/build/fuzz"
cmake -S . -B "$FUZZ_DIR" -G Ninja -DCMAKE_BUILD_TYPE=Release -DOQS_ENABLE=OFF \
      -DCMAKE_C_COMPILER="$CC" \
      -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link" >/dev/null
cmake --build "$FUZZ_DIR" -j"$MAYHEM_JOBS" --target cedar mayaqua libhamcore

rm -f "$FUZZ_DIR/libsoftether_all.a"
find "$FUZZ_DIR/src/Mayaqua" "$FUZZ_DIR/src/Cedar" -path '*CMakeFiles/*' -name '*.o' -print0 \
  | sort -z | xargs -0 ar rcs "$FUZZ_DIR/libsoftether_all.a"
HAMCORE_A="$(find "$FUZZ_DIR/src/libhamcore" -name '*.a' | head -n1)"
CPUF_A="$(find "$FUZZ_DIR/src/Mayaqua/3rdparty/cpu_features" -name '*.a' | head -n1)"

DEFS="-DUNIX -DOS_UNIX -DUNIX_LINUX -DCPU_64 -DNDEBUG -DVPN_SPEED -DSKIP_OQS_PROVIDER \
-D_REENTRANT -DREENTRANT -D_THREAD_SAFE -D_THREADSAFE -DTHREAD_SAFE -DTHREADSAFE -D_FILE_OFFSET_BITS=64 -fsigned-char"
LIBS="$FUZZ_DIR/libsoftether_all.a $HAMCORE_A $CPUF_A -lssl -lcrypto -lz -lsodium -lncurses -lreadline -liconv -lm -lrt -lpthread"
# libiconv is part of glibc on Linux; only link it if it exists separately.
if ! echo 'int main(void){return 0;}' | $CC -x c - -liconv -o /dev/null 2>/dev/null; then
  LIBS="${LIBS/-liconv /}"
fi

# 2) Harnesses: fuzzer binary + standalone run-once reproducer, LSan off at build time.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$FUZZ_DIR/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$FUZZ_DIR/standalone_main.o"

HARNESSES="fuzz_pack fuzz_packet fuzz_openvpn fuzz_ike fuzz_l2tp fuzz_ppp fuzz_sstp fuzz_cfg fuzz_json"
for h in $HARNESSES; do
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $DEFS $LIB_FUZZING_ENGINE -I"$SRC/src" -I"$SRC/mayhem" \
      "mayhem/$h.c" "$FUZZ_DIR/lsan_off.o" $LIBS -o "$SRC/$h"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $DEFS -I"$SRC/src" -I"$SRC/mayhem" \
      "mayhem/$h.c" "$FUZZ_DIR/standalone_main.o" "$FUZZ_DIR/lsan_off.o" $LIBS -o "$SRC/$h-standalone"
done

# 3) Oracle build: the project exactly as upstream builds it (no sanitizers), plus the KAT probe.
ORACLE_DIR="$SRC/build/oracle"
cmake -S . -B "$ORACLE_DIR" -G Ninja -DCMAKE_BUILD_TYPE=Release -DOQS_ENABLE=OFF \
      -DCMAKE_C_COMPILER="$CC" -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" >/dev/null
cmake --build "$ORACLE_DIR" -j"$MAYHEM_JOBS"
$CC -O1 $COVERAGE_FLAGS $DEFS -I"$SRC/src" -I"$SRC/mayhem" mayhem/kat.c -L"$ORACLE_DIR" -lcedar -lmayaqua \
    -Wl,-rpath,"$ORACLE_DIR" -o "$ORACLE_DIR/kat"

# The harnesses read the string tables from hamcore.se2 next to the executable.
cp "$ORACLE_DIR/hamcore.se2" "$SRC/hamcore.se2"
