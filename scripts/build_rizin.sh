#!/usr/bin/env bash
# Builds and installs Rizin (librz) from source — the target production
# analysis backend (see docs/ARCHITECTURE.md). Not needed to build Compass
# itself (it falls back to radare2 automatically, see
# src/core/CMakeLists.txt), but running this first makes Rizin the default
# backend.
#
# This exists because Rizin isn't packaged for common distros (checked:
# not in Ubuntu 24.04's repos) — building from source is the only way to
# get it today. Two things this script works around that a naive
# `meson setup && ninja` hits:
#   - Rizin's tree-sitter subproject downloads a GitHub release tarball
#     that a restrictive outbound proxy may 403 (this was hit and fixed in
#     the environment this was developed in) — using the system
#     libtree-sitter-dev package sidesteps that download entirely.
#   - Everything else Rizin's build needs (capstone, pcre2, tree-sitter-c,
#     sigdb, ...) fetches via `git clone` through meson's wrap-git
#     mechanism, which is unaffected.
set -euo pipefail

RIZIN_VERSION="${RIZIN_VERSION:-v0.7.4}"
PREFIX="${PREFIX:-/usr/local}"
WORK="${WORK:-$(mktemp -d)}"

echo "== installing build dependencies =="
sudo apt-get update -qq
sudo apt-get install -y meson ninja-build pkg-config cmake git libtree-sitter-dev

echo "== cloning rizin $RIZIN_VERSION =="
git clone --depth 1 --branch "$RIZIN_VERSION" https://github.com/rizinorg/rizin.git "$WORK/rizin"

echo "== configuring (system tree-sitter, to avoid the blocked download above) =="
meson setup "$WORK/rizin/build" "$WORK/rizin" --prefix="$PREFIX" -Dblob=false -Duse_sys_tree_sitter=enabled

echo "== building (this is a real ~2000-target build; expect it to take a while) =="
ninja -C "$WORK/rizin/build" -j"$(nproc)"

echo "== installing to $PREFIX =="
sudo ninja -C "$WORK/rizin/build" install
sudo ldconfig

echo
echo "Rizin installed. Reconfigure Compass to pick it up:"
echo "  rm -rf build && cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo"
echo "Look for: \"Compass: Rizin (librz) found\" in the configure output."
