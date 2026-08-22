#!/usr/bin/env bash
# Builds and installs rz-ghidra — the Rizin plugin Milestone 3's decompiler
# is built on (see docs/DECOMPILER.md). It's a self-contained port of
# Ghidra's C++ decompiler: Ghidra itself (the Java application) is never
# involved, only its decompiler source, vendored as a git submodule.
#
# Requires Rizin already installed (scripts/build_rizin.sh) — rz-ghidra is
# a plugin for it, not a standalone tool. Pins to the rz-ghidra tag that
# matches build_rizin.sh's RIZIN_VERSION's *minor* line (rz-ghidra doesn't
# always cut a tag per Rizin patch release — checked directly via
# `git ls-remote --tags`, there is no rz-0.7.4 tag, so rz-0.7.0 is the
# closest compatible one for Rizin v0.7.4).
set -euo pipefail

RZ_GHIDRA_TAG="${RZ_GHIDRA_TAG:-rz-0.7.0}"
PREFIX="${PREFIX:-/usr/local}"
WORK="${WORK:-$(mktemp -d)}"

echo "== installing build dependencies =="
sudo apt-get update -qq
sudo apt-get install -y cmake git bison flex

echo "== cloning rz-ghidra $RZ_GHIDRA_TAG =="
git clone --branch "$RZ_GHIDRA_TAG" --depth 1 https://github.com/rizinorg/rz-ghidra.git "$WORK/rz-ghidra"

echo "== fetching submodules (Ghidra's decompiler C++ source, pugixml) =="
git -C "$WORK/rz-ghidra" -c protocol.version=2 submodule update --init --depth 1

echo "== configuring =="
cmake -S "$WORK/rz-ghidra" -B "$WORK/rz-ghidra/build" \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" -DCMAKE_BUILD_TYPE=Release

echo "== building (compiles Ghidra's decompiler + sleigh spec generation; expect it to take a while) =="
cmake --build "$WORK/rz-ghidra/build" -j"$(nproc)"

echo "== installing to $PREFIX (includes the sleigh spec files the decompiler needs) =="
sudo cmake --install "$WORK/rz-ghidra/build"
sudo ldconfig

echo
echo "rz-ghidra installed. compass-cli --function <name> --decompile <binary> should now work"
echo "(no Compass rebuild needed — the plugin is dlopen'd by Rizin at runtime, not linked at build time)."
