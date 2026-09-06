# RetDec evaluation

## What this is

A scoping evaluation of [avast/retdec](https://github.com/avast/retdec) against
what Compass already has, done **before** committing to any integration —
same standard the project already holds itself to for `GhidraDecompilerBackend`
(evaluated and explicitly rejected in favor of rz-ghidra, see
[docs/DECOMPILER.md](DECOMPILER.md) and ROADMAP.md's Milestone 3) and for
choosing Rizin/radare2's own signature subsystems over a hand-rolled one (see
"Signature/FLIRT-style function matching" in [ARCHITECTURE.md](ARCHITECTURE.md)).
Every claim below was checked directly against RetDec's own source and
GitHub metadata (cloned at the commit noted below), not recalled from
memory or inferred from the project's name/reputation.

**Bottom line: do not adopt RetDec as a Compass dependency right now.**
Every capability it offers either duplicates something Compass already has
from a healthier source, or costs far more to integrate than it's shown to
be worth. One narrow piece — its in-repo compiler/packer/installer YARA
rules — is a real, cheap candidate for a *future*, separate, much smaller
follow-on, not for RetDec adoption as such. Details and reasoning below.

## What RetDec actually is (verified, not assumed)

Checked against `avast/retdec` cloned at commit `9450585` (HEAD as of this
evaluation, dated 2026-05-20, titled "Improved detection of PyInstaller")
and the GitHub API's repository metadata for the same repo:

- **License**: MIT (`LICENSE`, confirmed), plus a small amount of zlib/libpng
  licensed code (PeLib, `LICENSE-PELIB`). Not a licensing obstacle — more
  permissive than rz-ghidra's LGPL-3.0.
- **Not archived.** `archived: false` in the GitHub API response; the repo
  has ongoing commits (`pushed_at: 2026-05-26`).
- **But its own README carries an explicit maintenance warning**, quoted
  verbatim from `README.md`'s top banner:
  > The RetDec project is currently in a **limited maintenance mode** due to
  > a lack of resources: Pull Requests are welcomed... Issues are reacted on
  > with delays up to one quarter... Only a very limited development is
  > carried on.
- **Last tagged release: `v5.0`, 2022-12-08** (`git ls-remote --tags`
  confirms no tag newer than `v5.0`). All commits since then live under an
  unreleased `# dev` heading in `CHANGELOG.md` — real activity, but nothing
  cut as a release in over three years.
- **What v5.0 changed**: RetDec became a real, embeddable library rather
  than a set of Python-orchestrated standalone binaries — confirmed via
  `retdec-config.cmake` (a `find_package(retdec COMPONENTS ...)`-style
  per-component CMake config), public headers under `include/retdec/`, and
  `src/retdectool` as a minimal example consumer of `retdec::retdec`.
- **Supported architectures** (README, cross-checked against `src/`):
  x86/x86-64, ARM/ARM64, MIPS, PIC32, PowerPC. **Formats**: ELF, PE, Mach-O,
  COFF, AR, Intel HEX, raw.
- **Build cost is the headline problem.** RetDec vendors a *patched LLVM
  fork* (`https://github.com/avast/llvm`, pinned to a specific commit in
  `cmake/deps.cmake`) and builds it from source via `ExternalProject_Add`
  (`deps/llvm/CMakeLists.txt`) — plus its own pinned builds of Capstone,
  YARA, yaramod, Keystone, and Googletest, all fetched and compiled as part
  of RetDec's own build. The README states an installed RetDec needs
  **"approximately 5 to 6 GB of free disk space."** This is a categorically
  heavier dependency than rz-ghidra, which Compass deliberately chose
  *because* it avoids exactly this class of cost — see "Why runtime, not
  build time" in DECOMPILER.md: rz-ghidra is a Rizin plugin, dlopen'd at
  runtime, with nothing to vendor or build into Compass itself.

## Component-by-component comparison

### 1. Decompiler (`bin2llvmir` + `llvmir2hll`) vs. rz-ghidra

RetDec's decompiler pipeline lifts machine code to LLVM IR (`bin2llvmir`),
then structures that IR into C or a Python-like output language
(`llvmir2hll`) — a fundamentally different IR and pipeline from Ghidra's
p-code, which is what rz-ghidra (already integrated, see DECOMPILER.md)
wraps. Both are mature, real decompilers built on a large existing
project rather than written from scratch — architecturally the same kind
of choice Compass already made once.

Adding RetDec as a second/alternative `decompile()` path would mean: vendor
a patched LLVM fork and build it as part of Compass's build (the ~5-6 GB
cost above), maintain that build against a project in limited-maintenance
mode with no release in 3+ years, and do it all for a benefit that hasn't
been measured — nobody has compared RetDec's and rz-ghidra's decompiled
output on Compass's own fixtures to know if it's even better on any axis
that matters here.

**Not recommended.** If this is ever revisited, the correct first step is a
quality bake-off against the exact fixtures `scripts/decompile_smoke_test.sh`
already exercises — not integration work up front.

### 2. Function/library-code signature matching vs. FLIRT/zignatures

RetDec doesn't use FLIRT. It identifies statically-linked library code with
its own YARA-pattern toolchain (`bin2pat`/`idr2pat`/`pat2yara`/`patterngen`
under `src/`), matched against a pattern database it downloads separately —
`cmake/deps.cmake` pins `SUPPORT_PKG_URL` to
`avast/retdec-support` release **`2019-03-08`**. RetDec's own shipped
function-signature data hasn't been refreshed in roughly seven years, even
while the main repo keeps receiving commits.

Compass's existing signature matching (`exportSignatures()`/
`applySignatures()`, see ARCHITECTURE.md) uses Rizin's real FLIRT
implementation and radare2's zignatures — both generated live from each
backend's *current* toolchain, and already verified end to end
(`scripts/signature_smoke_test.sh`).

**Not recommended.** There's nothing here that improves on what's shipped;
the RetDec side is the less current of the two.

### 3. Unpacking (`retdec-unpacker`) vs. Compass's sandbox

"Generic unpacker" is the name of one RetDec plugin, not a generic
emulation-based unpacker — the actual dedicated packer-stub plugins under
`src/unpackertool/plugins/` are exactly two real ones, **UPX and MPRESS**
(plus an `example` template), matched via hardcoded stub signatures
(`upx_stub_signatures.cpp`) and RetDec's own decompressor implementation.
`retdec-decompiler`'s preprocessing step calls this in-process
(`retdec::unpackertool::_main`, confirmed in `src/retdec-decompiler`) —
it does not shell out to a system `upx` binary, despite what the top-level
README's platform install instructions ("install UPX... if you want to use
UPX unpacker") suggest at a glance.

Compass's sandbox (docs/SANDBOX.md) currently does no static unpacking
before detonation — a packed sample is detonated as-is and its behavior
captured dynamically, which sidesteps the packer-identification problem
rather than solving it.

**Marginal, not recommended now.** Pulling in an LLVM build for two packers'
worth of stub-matching is a heavy trade for a narrow capability. If
static pre-unpacking ever becomes an actual sandbox roadmap item, a direct,
standalone dependency scoped to the packer(s) that matter is very likely
cheaper than linking all of `retdec-unpacker` (which itself is the
motivation for wanting RetDec as a library) — worth a fresh, separate
evaluation at that time rather than deciding it here.

### 4. Compiler/packer/installer YARA rules (`support/yara_patterns/tools/`)

This is a different asset from #2's stale, separately-downloaded
`retdec-support` package: these `.yara` files (`compilers.yara`,
`packers.yara`, `installers.yara`, etc.) live directly in the `retdec` git
repo, not in the pinned 2019 tarball. The repo's HEAD commit as of this
evaluation is titled "Improved detection of PyInstaller" — consistent
with the project still landing packer/installer-detection improvements,
though this evaluation did not diff that specific commit against the yara
files to confirm it touched them (a shallow clone can't produce a
meaningful diff against a parent it doesn't have).

**The one real candidate for narrow future adoption**: importing just these
rule files and running them through a YARA dependency Compass already has
reason to use (Rizin/radare2 both bundle YARA) for compiler/packer/installer
fingerprinting — entirely independent of RetDec's decompiler, LLVM
dependency, or unpacker code. Not scoped further here, per this task's
"evaluate first" request — a real follow-on candidate, not a decision made
by this doc.

## Recommendation

Do not add RetDec as a Compass dependency. Nothing it offers clears the bar
Compass has already set for itself (reuse over reimplementation, verified
against real behavior, weighed against integration/maintenance cost) better
than what's already shipped, except possibly the narrow YARA-rules case in
§4 — which is worth a small, separate, future evaluation of its own, not a
reason to pull in RetDec as a whole.

## What would change this conclusion

- A RetDec release/maintenance shift (a new tag, the maintenance-mode
  banner lifted) that changes the cost/risk side of the calculation.
- A concrete, measured gap in rz-ghidra's decompile output on real Compass
  fixtures that RetDec's LLVM-based pipeline is shown (not assumed) to
  close.
- An actual sandbox roadmap item requiring static pre-unpacking, at which
  point re-evaluate #3 specifically against narrower, single-purpose
  alternatives, not against adopting `retdec-unpacker` wholesale.
