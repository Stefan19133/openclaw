#!/usr/bin/env python3
"""Patch openclaw 2026.4.x bundled-runtime-root to reduce mirror re-stage thrashing.

Bug investigated:
  ``materializeBundledRuntimeMirrorDistFile`` in
  ``/usr/lib/node_modules/openclaw/dist/bundled-runtime-root-*.js`` uses
  ``fs.realpathSync(src) === fs.realpathSync(dst)`` to detect "already
  materialized". This check is wrong for hard links: ``realpathSync`` returns
  the path you passed in (not the source path), so for hard-linked targets
  the equality is never true. On hosts where ``protected_hardlinks=1``
  (Linux default) the unprivileged gateway user cannot hardlink files owned
  by root either, so ``fs.linkSync`` fails and the function falls back to
  ``fs.copyFileSync`` — which does not preserve mtime, so even a "same content"
  check on (size, mtime) would never match. Without the fix, every gateway
  boot ``rmSync + copyFileSync`` ~1100 dist/*.js files, hammering the disk
  for ~5 minutes during which msteams does not listen.

What the patch fixes (4 surgical edits):

  1. Replace the realpath-equality check with a layered idempotency check
     (stat.dev/ino + stat.size/mtimeMs).
  2. After ``fs.copyFileSync`` in materializeBundledRuntimeMirrorDistFile,
     propagate src.mtime to target via fs.utimesSync.
  3. Same propagation in copyBundledPluginRuntimeRoot (different indent).
  4. Inject ``__openclawPluginMirrorIsInSync`` and short-circuit
     mirrorBundledPluginRuntimeRoot when the per-plugin mirror is already
     in sync via a recursive size+mtime walk.

Measured impact on the SSJN VPS (1 vCPU / 4 GB / sda1 ext4, openclaw
2026.4.26, 9 enabled plugins):

  * Boot time: ~5 min  →  ~3 min (msteams listening on :3979)
  * Disk write rate during boot: ~7000 kB/s sustained → ~119 kB/s
  * Files re-written per boot in plugin-runtime-deps:  ~1106 → ~675

Edits 1+2 (the dist/ materialization path) deliver the biggest measurable
win — they eliminate the disk-throttling kernel D-state. Edits 3+4 (the
per-plugin mirror short-circuit) are correct in isolation (the helper
function returns ``true`` when called by hand on aligned mtimes) but the
gateway still re-mirrors plugin trees at boot. The per-plugin re-mirror is
no longer the dominant cost (small files, no kernel throttling), so the
remaining ~3 min boot is now CPU-bound, not I/O-bound.

The 3+4 path needs more upstream investigation: either ``mirrorBundledPlugin
RuntimeRoot`` is being called multiple times per plugin per boot (only the
first call would benefit from the guard), or another code path resets the
mirror's mtime between calls. Logging instrumentation is needed in the
bundle to confirm.

Idempotent:
  - "already patched" detected by presence of all four new forms
  - keeps a ``.bak`` of the original file on first run
  - re-running ``--check`` reports what would change

Usage on the VPS (root needed since the file is under /usr/lib):

    sudo python3 vps-patch-runtime-mirror.py            # apply
    sudo python3 vps-patch-runtime-mirror.py --check    # verify-only, no write
    sudo python3 vps-patch-runtime-mirror.py --revert   # restore .bak

After ``npm install -g openclaw@<x>`` the bundle is replaced; re-run the
script to re-apply the patch. (Auto-reapplication via a systemd
``ExecStartPre`` is feasible but requires a sudoers NOPASSWD rule, which is
out of scope for this script.)
"""
from __future__ import annotations

import argparse
import glob
import shutil
import sys
from pathlib import Path

BUNDLE_GLOB = "/usr/lib/node_modules/openclaw/dist/bundled-runtime-root-*.js"

# ---- Edit #1 — idempotency check inside materializeBundledRuntimeMirrorDistFile.
OLD_CHECK_PRISTINE = (
    "if (fs.realpathSync(sourcePath) === fs.realpathSync(targetPath) "
    "&& !fs.lstatSync(targetPath).isSymbolicLink()) return;"
)
# Form left by an older (incomplete) version of this patch — treat as "needs upgrade".
OLD_CHECK_PARTIAL = (
    "{ const s1 = fs.statSync(sourcePath); const s2 = fs.statSync(targetPath); "
    "if (s1.dev === s2.dev && s1.ino === s2.ino "
    "&& !fs.lstatSync(targetPath).isSymbolicLink()) return; }"
)
NEW_CHECK = (
    "{ const s1 = fs.statSync(sourcePath); const s2 = fs.statSync(targetPath); "
    "if (s1.dev === s2.dev && s1.ino === s2.ino "
    "&& !fs.lstatSync(targetPath).isSymbolicLink()) return; "
    "if (s1.size === s2.size && Math.floor(s1.mtimeMs / 1000) === Math.floor(s2.mtimeMs / 1000) "
    "&& !fs.lstatSync(targetPath).isSymbolicLink()) return; }"
)

# ---- Edit #2 — propagate source mtime to the target after copy/link.
# This snippet appears in TWO functions with different indentation depths:
#   * materializeBundledRuntimeMirrorDistFile  → 1-tab `try {` + 2-tab body
#   * copyBundledPluginRuntimeRoot             → 2-tab `try {` + 3-tab body
# We patch BOTH so the (size, mtime) idempotency checks in #1 and #3 match on
# later boots. The replacement preserves the per-function indentation.
OLD_TAIL_A = (
    "try {\n"
    "\t\tconst sourceMode = fs.statSync(sourcePath).mode;\n"
    "\t\tfs.chmodSync(targetPath, sourceMode | 384);\n"
    "\t} catch {}"
)
NEW_TAIL_A = (
    "try {\n"
    "\t\tconst srcStat = fs.statSync(sourcePath);\n"
    "\t\tfs.chmodSync(targetPath, srcStat.mode | 384);\n"
    "\t\tfs.utimesSync(targetPath, srcStat.atime, srcStat.mtime);\n"
    "\t} catch {}"
)
OLD_TAIL_B = (
    "try {\n"
    "\t\t\tconst sourceMode = fs.statSync(sourcePath).mode;\n"
    "\t\t\tfs.chmodSync(targetPath, sourceMode | 384);\n"
    "\t\t} catch {}"
)
NEW_TAIL_B = (
    "try {\n"
    "\t\t\tconst srcStat = fs.statSync(sourcePath);\n"
    "\t\t\tfs.chmodSync(targetPath, srcStat.mode | 384);\n"
    "\t\t\tfs.utimesSync(targetPath, srcStat.atime, srcStat.mtime);\n"
    "\t\t} catch {}"
)

# ---- Edit #3 — short-circuit mirrorBundledPluginRuntimeRoot when the existing
# mirror is already in sync with the source (recursive size+mtime walk). This
# is the per-plugin mirror copy that runs unconditionally for every loaded
# plugin at every gateway start (~675 files in our deployment).
OLD_MIRROR_GUARD = (
    "if (path.resolve(mirrorRoot) === path.resolve(params.pluginRoot)) return mirrorRoot;\n"
    "\t\tconst tempDir = fs.mkdtempSync"
)
NEW_MIRROR_GUARD = (
    "if (path.resolve(mirrorRoot) === path.resolve(params.pluginRoot)) return mirrorRoot;\n"
    "\t\tif (__openclawPluginMirrorIsInSync(params.pluginRoot, mirrorRoot)) return mirrorRoot;\n"
    "\t\tconst tempDir = fs.mkdtempSync"
)

# ---- Edit #4 — inject the helper `__openclawPluginMirrorIsInSync` right
# before the function that uses it. Same exclusion as
# copyBundledPluginRuntimeRoot ("node_modules" is skipped). Returns false on
# any structural difference, missing entry, or size/mtime mismatch — so the
# unconditional rebuild path runs whenever it should.
OLD_HELPER_ANCHOR = "function mirrorBundledPluginRuntimeRoot(params) {"
NEW_HELPER_BLOCK = (
    "function __openclawPluginMirrorIsInSync(sourceRoot, mirrorRoot) {\n"
    "\ttry {\n"
    "\t\tif (!fs.existsSync(mirrorRoot)) return false;\n"
    "\t\tconst stack = [[sourceRoot, mirrorRoot]];\n"
    "\t\twhile (stack.length) {\n"
    "\t\t\tconst [src, dst] = stack.pop();\n"
    "\t\t\tconst sl = fs.lstatSync(src);\n"
    "\t\t\tif (!fs.existsSync(dst)) return false;\n"
    "\t\t\tconst dl = fs.lstatSync(dst);\n"
    "\t\t\tif (sl.isSymbolicLink() !== dl.isSymbolicLink()) return false;\n"
    "\t\t\tif (sl.isDirectory() !== dl.isDirectory()) return false;\n"
    "\t\t\tif (sl.isSymbolicLink()) {\n"
    "\t\t\t\tif (fs.readlinkSync(src) !== fs.readlinkSync(dst)) return false;\n"
    "\t\t\t\tcontinue;\n"
    "\t\t\t}\n"
    "\t\t\tif (sl.isFile()) {\n"
    "\t\t\t\tconst ss = fs.statSync(src);\n"
    "\t\t\t\tconst ds = fs.statSync(dst);\n"
    "\t\t\t\tif (ss.size !== ds.size) return false;\n"
    "\t\t\t\tif (Math.floor(ss.mtimeMs / 1000) !== Math.floor(ds.mtimeMs / 1000)) return false;\n"
    "\t\t\t\tcontinue;\n"
    "\t\t\t}\n"
    "\t\t\tif (sl.isDirectory()) {\n"
    "\t\t\t\tconst se = fs.readdirSync(src).filter((n) => n !== \"node_modules\").sort();\n"
    "\t\t\t\tconst de = fs.readdirSync(dst).filter((n) => n !== \"node_modules\").sort();\n"
    "\t\t\t\tif (se.length !== de.length) return false;\n"
    "\t\t\t\tfor (let i = 0; i < se.length; i += 1) {\n"
    "\t\t\t\t\tif (se[i] !== de[i]) return false;\n"
    "\t\t\t\t\tstack.push([path.join(src, se[i]), path.join(dst, de[i])]);\n"
    "\t\t\t\t}\n"
    "\t\t\t}\n"
    "\t\t}\n"
    "\t\treturn true;\n"
    "\t} catch { return false; }\n"
    "}\n"
    "function mirrorBundledPluginRuntimeRoot(params) {"
)


def find_bundle() -> Path:
    matches = glob.glob(BUNDLE_GLOB)
    if not matches:
        sys.exit(f"no openclaw bundle file matched {BUNDLE_GLOB}")
    if len(matches) > 1:
        sys.exit(f"unexpected: multiple bundle files matched {BUNDLE_GLOB}: {matches}")
    return Path(matches[0])


def is_fully_patched(text: str) -> bool:
    return (
        NEW_CHECK in text
        and NEW_TAIL_A in text
        and NEW_TAIL_B in text
        and OLD_TAIL_A not in text
        and OLD_TAIL_B not in text
        and NEW_MIRROR_GUARD in text
        and NEW_HELPER_BLOCK in text
    )


def apply_patch(check: bool) -> int:
    f = find_bundle()
    text = f.read_text(encoding="utf-8")

    if is_fully_patched(text):
        print(f"[patch] {f.name}: already patched (full)")
        return 0

    # Edit #1: idempotency check (accept pristine or partial form).
    has_pristine_check = OLD_CHECK_PRISTINE in text
    has_partial_check = OLD_CHECK_PARTIAL in text
    has_new_check = NEW_CHECK in text
    needs_check_edit = not has_new_check
    if needs_check_edit and not (has_pristine_check or has_partial_check):
        print(
            f"[patch] {f.name}: idempotency-check region not found; "
            f"likely a different openclaw version. Refusing.",
            file=sys.stderr,
        )
        return 2

    # Edit #2: tail mtime-propagation. Two distinct patterns (different
    # indentation per containing function). Each must end up patched.
    needs_tail_a = OLD_TAIL_A in text and NEW_TAIL_A not in text
    needs_tail_b = OLD_TAIL_B in text and NEW_TAIL_B not in text
    has_tail_a = OLD_TAIL_A in text or NEW_TAIL_A in text
    has_tail_b = OLD_TAIL_B in text or NEW_TAIL_B in text
    if not (has_tail_a and has_tail_b):
        print(
            f"[patch] {f.name}: copy-tail regions not found; refusing.",
            file=sys.stderr,
        )
        return 2

    # Edit #3: per-plugin mirror short-circuit guard.
    has_new_guard = NEW_MIRROR_GUARD in text
    has_pristine_guard = OLD_MIRROR_GUARD in text
    needs_guard_edit = not has_new_guard
    if needs_guard_edit and not has_pristine_guard:
        print(
            f"[patch] {f.name}: mirror-guard region not found; refusing.",
            file=sys.stderr,
        )
        return 2

    # Edit #4: helper function injection (only inject if absent and the anchor
    # has not already been moved by edit #3 — we use the unmodified anchor).
    has_new_helper = NEW_HELPER_BLOCK in text or "__openclawPluginMirrorIsInSync" in text
    needs_helper_edit = not has_new_helper
    if needs_helper_edit and OLD_HELPER_ANCHOR not in text:
        print(
            f"[patch] {f.name}: helper-anchor not found; refusing.", file=sys.stderr
        )
        return 2

    if check:
        what = []
        if needs_check_edit:
            what.append("idempotency-check upgrade")
        if needs_tail_a:
            what.append("mtime-propagation A (materialize)")
        if needs_tail_b:
            what.append("mtime-propagation B (copy)")
        if needs_guard_edit:
            what.append("per-plugin mirror guard")
        if needs_helper_edit:
            what.append("helper injection")
        print(f"[patch] {f.name}: would apply: {', '.join(what) or '(nothing)'}")
        return 1 if what else 0

    backup = f.with_suffix(f.suffix + ".bak")
    if not backup.exists():
        shutil.copy2(f, backup)
        print(f"[patch] backup written to {backup}")

    new_text = text
    if needs_check_edit:
        old = OLD_CHECK_PARTIAL if has_partial_check else OLD_CHECK_PRISTINE
        new_text = new_text.replace(old, NEW_CHECK, 1)
    if needs_tail_a:
        new_text = new_text.replace(OLD_TAIL_A, NEW_TAIL_A, 1)
    if needs_tail_b:
        new_text = new_text.replace(OLD_TAIL_B, NEW_TAIL_B, 1)
    if needs_helper_edit:
        new_text = new_text.replace(OLD_HELPER_ANCHOR, NEW_HELPER_BLOCK, 1)
    if needs_guard_edit:
        new_text = new_text.replace(OLD_MIRROR_GUARD, NEW_MIRROR_GUARD, 1)

    if new_text == text or not is_fully_patched(new_text):
        sys.exit("[patch] internal error: post-replace verification failed")

    f.write_text(new_text, encoding="utf-8")
    print(
        f"[patch] {f.name}: patched (idempotency + mtime-propagation + "
        f"per-plugin mirror guard + helper)"
    )
    return 0


def revert_patch() -> int:
    f = find_bundle()
    backup = f.with_suffix(f.suffix + ".bak")
    if not backup.exists():
        sys.exit(f"[patch] no backup at {backup}; cannot revert")
    shutil.copy2(backup, f)
    print(f"[patch] reverted {f.name} from {backup}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="report status without writing")
    parser.add_argument(
        "--revert", action="store_true", help="restore the .bak (revert the patch)"
    )
    args = parser.parse_args()
    if args.revert:
        return revert_patch()
    return apply_patch(check=args.check)


if __name__ == "__main__":
    sys.exit(main())
