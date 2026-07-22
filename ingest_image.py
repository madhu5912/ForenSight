"""
ForenSight - Resilient disk-image ingestion.

Automatic fallback chain (the user never sees raw errors):
    1. Try tsk_recover DIRECTLY on the image (works if TSK has libewf for E01)
    2. If 0 files → try with common partition offsets (2048, 63, 128)
    3. If still 0 → try ewfmount (FUSE, zero extra disk space, needs sudo)
    4. If ewfmount fails/unavailable → try ewfexport normalize-to-raw
       (checks disk space first; uses $HOME/tmp if /tmp is too small)
    5. For AFF/VMDK/VHD → normalize-to-raw via affconvert/qemu-img

The user runs ONE command and gets the files, or a clear explanation of what's missing.

Supported:  .dd .raw .img .001 .e01 .ex01 .aff .aff4 .vmdk .vhd .vhdx .qcow2 .dmg .iso

Usage:
    python ingest_image.py rm1.E01 --case LEAK_RM1 --examiner "I. Robin"
    python ingest_image.py *.dd --case CASE01 --all
"""
import os
import shutil
import tempfile
import argparse
import subprocess
from datetime import datetime, timezone

from pipeline import run_pipeline
from acquisition import sha256_of_file
import case_metadata

NATIVE_TSK_EXT = (".dd", ".raw", ".img", ".001", ".e01", ".ex01", ".iso")
CONVERT_EXT = (".aff", ".aff4", ".vmdk", ".vhd", ".vhdx", ".qcow2", ".dmg")
EWF_EXT = (".e01", ".ex01")
COMMON_OFFSETS = [0, 2048, 63, 128, 1]      # most-likely partition offsets


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------
def _run(cmd, sudo=False):
    """Run a command, optionally with sudo (only if not already root)."""
    if sudo and os.geteuid() != 0:
        cmd = ["sudo"] + cmd
    print(f"    $ {' '.join(cmd)}")
    return subprocess.run(cmd, capture_output=True, text=True)


def _run_quiet(cmd, sudo=False):
    if sudo and os.geteuid() != 0:
        cmd = ["sudo"] + cmd
    return subprocess.run(cmd, capture_output=True, text=True)


def _tool(name):
    return shutil.which(name) is not None


def _count_files(d):
    return sum(len(fs) for _, _, fs in os.walk(d)) if os.path.isdir(d) else 0


def _free_space_bytes(path):
    """Free bytes on the filesystem containing `path`."""
    try:
        st = os.statvfs(path)
        return st.f_bavail * st.f_frsize
    except Exception:
        return 0


def _ewf_media_size(image_path):
    """Read the ACTUAL uncompressed media size from an E01 header using ewfinfo.
    This is critical: the E01 file on disk can be 50x smaller than the raw it expands to.
    Returns the size in bytes, or 0 if ewfinfo is unavailable."""
    if not _tool("ewfinfo"):
        return 0
    res = _run_quiet(["ewfinfo", image_path])
    if res.returncode != 0:
        return 0
    for line in res.stdout.splitlines():
        # Line looks like: "  Media size:    3.7 GiB (4004511744 bytes)"
        if "media size" in line.lower() and "(" in line:
            try:
                inside = line.split("(")[1].split(")")[0]
                return int(inside.split()[0])
            except (IndexError, ValueError):
                pass
    return 0


def _best_workdir(raw_size_needed):
    """Pick a temp directory that has enough space for a raw conversion.
    `raw_size_needed` must be the ACTUAL uncompressed size, not the compressed file size.
    Prefers /tmp, falls back to $HOME/tmp, then the current directory."""
    needed = int(raw_size_needed * 1.1)      # 10% headroom
    candidates = [tempfile.gettempdir(),
                  os.path.join(os.path.expanduser("~"), "tmp"),
                  os.getcwd()]
    for candidate in candidates:
        os.makedirs(candidate, exist_ok=True)
        free = _free_space_bytes(candidate)
        if free >= needed:
            d = tempfile.mkdtemp(prefix="forensight_norm_", dir=candidate)
            print(f"    -> work dir: {candidate} "
                  f"({free // 2**20} MiB free, need {needed // 2**20} MiB)")
            return d
    # Last resort: use CWD anyway and let the OS error if it truly runs out
    print(f"[!] No directory has {needed // 2**20} MiB free; trying CWD anyway")
    return tempfile.mkdtemp(prefix="forensight_norm_", dir=os.getcwd())


def _chown_to_caller(path):
    """If we're running as root (via sudo), give ownership back to the real user
    so the pipeline can read the extracted files without permission issues."""
    uid = os.environ.get("SUDO_UID")
    gid = os.environ.get("SUDO_GID")
    if uid and gid:
        for root, dirs, files in os.walk(path):
            os.chown(root, int(uid), int(gid))
            for f in files:
                try:
                    os.chown(os.path.join(root, f), int(uid), int(gid))
                except OSError:
                    pass


# ---------------------------------------------------------------------------
# Partition detection
# ---------------------------------------------------------------------------
def mmls_report(image_path, sudo=False):
    """Return (offset, fs_label, partitions_text) from mmls."""
    res = _run(["mmls", image_path], sudo=sudo)
    if res.returncode != 0:
        return 0, "", ""
    offset, fs_label = 0, ""
    lines = []
    for line in res.stdout.splitlines():
        if line.strip():
            lines.append(line.strip())
        low = line.lower()
        if any(fs in low for fs in ("ntfs", "fat", "exfat", "hfs",
                                     "0x07", "0x0c", "0x0b", "0x83")):
            parts = line.split()
            if len(parts) >= 3 and parts[2].isdigit():
                offset = int(parts[2])
                fs_label = " ".join(parts[5:]) if len(parts) > 5 else fs_label
    return offset, fs_label, " | ".join(lines[-6:])


# ---------------------------------------------------------------------------
# File extraction (with automatic offset probing)
# ---------------------------------------------------------------------------
def try_recover(image_path, offset, outdir, recover_all, sudo=False):
    """Run tsk_recover at a given offset. Returns number of files recovered."""
    os.makedirs(outdir, exist_ok=True)
    cmd = ["tsk_recover", "-e" if recover_all else "-a"]
    if offset:
        cmd += ["-o", str(offset)]
    cmd += [image_path, outdir]
    res = _run(cmd, sudo=sudo)
    n = _count_files(outdir)
    return n


def recover_with_fallback(image_path, outdir, recover_all, sudo=False):
    """Try to extract files, probing multiple partition offsets if needed.
    Returns (n_files, offset_used, fs_label, partitions_text)."""
    # Step 1: ask mmls for the right offset
    offset, fs_label, partitions = mmls_report(image_path, sudo=sudo)
    print(f"    -> mmls offset {offset}, filesystem '{fs_label or 'n/a'}'")

    n = try_recover(image_path, offset, outdir, recover_all, sudo=sudo)
    if n > 0:
        return n, offset, fs_label, partitions

    # Step 2: mmls offset didn't work — probe common offsets
    print("[*] No files at detected offset; probing common partition offsets...")
    for probe in COMMON_OFFSETS:
        if probe == offset:
            continue
        # clear the output dir for each attempt
        shutil.rmtree(outdir, ignore_errors=True)
        n = try_recover(image_path, probe, outdir, recover_all, sudo=sudo)
        if n > 0:
            print(f"    -> found {n} files at offset {probe}")
            return n, probe, fs_label, partitions

    return 0, offset, fs_label, partitions


# ---------------------------------------------------------------------------
# E01 handling: ewfmount fallback (zero extra disk space)
# ---------------------------------------------------------------------------
def ewfmount_extract(image_path, outdir, recover_all):
    """Mount E01 via ewfmount (FUSE), then tsk_recover from the mount.
    Uses sudo automatically. Returns (n_files, offset, fs_label, partitions)."""
    if not _tool("ewfmount"):
        print("[!] ewfmount not available. Install: sudo apt install ewf-tools")
        return 0, 0, "", ""

    mountpoint = outdir + "_ewf_mnt"

    # Clean any stale mount from a previous failed run (common cause of ewfmount failure)
    if os.path.ismount(mountpoint):
        print("    -> cleaning stale mount from previous run")
        _run_quiet(["umount", mountpoint], sudo=True)
    if os.path.isdir(mountpoint):
        shutil.rmtree(mountpoint, ignore_errors=True)
    os.makedirs(mountpoint, exist_ok=True)

    try:
        print("[*] Mounting E01 with ewfmount (zero extra disk space)")
        res = _run(["ewfmount", image_path, mountpoint], sudo=True)
        raw = os.path.join(mountpoint, "ewf1")

        if res.returncode != 0 or not os.path.exists(raw):
            # Show the ACTUAL error, not just the version string
            errmsg = (res.stderr or res.stdout or "unknown error").strip()
            # Filter out version lines to show the real error
            err_lines = [l for l in errmsg.splitlines()
                         if not l.strip().isdigit() and "ewfmount" not in l.lower()]
            print(f"[!] ewfmount failed: {' '.join(err_lines) or errmsg}")
            return 0, 0, "", ""

        print("[*] Extracting from mounted image")
        n, offset, fs_label, partitions = recover_with_fallback(
            raw, outdir, recover_all, sudo=True)
        _chown_to_caller(outdir)
        return n, offset, fs_label, partitions
    finally:
        _run_quiet(["umount", mountpoint], sudo=True)
        shutil.rmtree(mountpoint, ignore_errors=True)


# ---------------------------------------------------------------------------
# Normalize-to-raw (for AFF/VMDK/VHD and as a last E01 resort)
# ---------------------------------------------------------------------------
def normalize_to_raw(image_path, workdir):
    """Convert to raw. Returns the raw path or None on failure."""
    ext = os.path.splitext(image_path)[1].lower()
    raw_out = os.path.join(workdir, "normalized.raw")

    if ext in (".vmdk", ".vhd", ".vhdx", ".qcow2", ".dmg"):
        if not _tool("qemu-img"):
            print("[!] qemu-img not found. Install: sudo apt install qemu-utils")
            return None
        res = _run(["qemu-img", "convert", "-O", "raw", image_path, raw_out])
    elif ext in (".aff", ".aff4"):
        if not _tool("affconvert"):
            print("[!] affconvert not found. Install: sudo apt install afflib-tools")
            return None
        res = _run(["affconvert", "-r", "-O", workdir, image_path])
        cands = [f for f in os.listdir(workdir) if f.endswith(".raw")]
        raw_out = os.path.join(workdir, cands[0]) if cands else raw_out
    elif ext in EWF_EXT:
        if not _tool("ewfexport"):
            print("[!] ewfexport not found. Install: sudo apt install ewf-tools")
            return None
        base = os.path.join(workdir, "normalized")
        res = _run(["ewfexport", "-u", "-t", base, "-f", "raw", image_path])
        raw_out = base + ".raw" if os.path.exists(base + ".raw") else base
    else:
        print(f"[!] Don't know how to normalize '{ext}'.")
        return None

    if res.returncode != 0 or not os.path.exists(raw_out):
        print(f"[!] Conversion to raw failed: {(res.stderr or '').strip()[:200]}")
        return None
    print(f"    -> normalized to {raw_out}")
    return raw_out


# ---------------------------------------------------------------------------
# Deleted / hidden file detection (from the image, before extraction)
# ---------------------------------------------------------------------------
def list_deleted(image_path, offset, sudo=False):
    cmd = ["fls", "-r", "-p"] + (["-o", str(offset)] if offset else []) + [image_path]
    res = _run_quiet(cmd, sudo=sudo)
    deleted = set()
    if res.returncode != 0:
        return deleted
    for line in res.stdout.splitlines():
        if "\t" not in line:
            continue
        left, path = line.split("\t", 1)
        tokens = left.split()
        if not tokens:
            continue
        if tokens[0].startswith("r/") and "*" in tokens and not path.startswith("$"):
            deleted.add(path.strip())
    return deleted


def list_hidden(image_path, offset, sudo=False, cap=4000):
    cmd = ["fls", "-r", "-p"] + (["-o", str(offset)] if offset else []) + [image_path]
    res = _run_quiet(cmd, sudo=sudo)
    if res.returncode != 0:
        return set()
    entries = []
    for line in res.stdout.splitlines():
        if "\t" not in line:
            continue
        left, path = line.split("\t", 1)
        tokens = left.split()
        if not tokens or not tokens[0].startswith("r/") or path.startswith("$"):
            continue
        inode = tokens[-1].rstrip(":")
        entries.append((inode, path.strip()))
    if len(entries) > cap:
        print(f"    -> {len(entries)} files; skipping hidden-attribute scan for speed")
        return set()
    hidden = set()
    for inode, path in entries:
        icmd = ["istat"] + (["-o", str(offset)] if offset else []) + [image_path, inode]
        r = _run_quiet(icmd, sudo=sudo)
        if r.returncode == 0 and "hidden" in r.stdout.lower():
            hidden.add(path)
    return hidden


# ---------------------------------------------------------------------------
# Main ingestion logic (the resilient fallback chain)
# ---------------------------------------------------------------------------
def ingest(image_path, case_id, examiner, outdir, recover_all, normalize, hash_image):
    if not os.path.isfile(image_path):
        here = ", ".join(sorted(os.listdir("."))[:15]) or "(empty)"
        raise SystemExit(f"Image file not found: '{image_path}'\n"
                         f"Files in current folder: {here}")

    ext = os.path.splitext(image_path)[1].lower()
    image_size = os.path.getsize(image_path)
    workdir = None
    raw_for_analysis = image_path    # the image used for fls/istat metadata
    n = 0
    offset, fs_label, partitions = 0, "", ""

    try:
        # ================================================================
        # STEP 1: formats that MUST be normalized (AFF/VMDK/VHD/QCOW2)
        # ================================================================
        if ext in CONVERT_EXT:
            print(f"[*] Normalizing {ext} to raw")
            workdir = _best_workdir(image_size)
            raw = normalize_to_raw(image_path, workdir)
            if not raw:
                raise SystemExit(f"Cannot normalize {ext}. Check the error above.")
            n, offset, fs_label, partitions = recover_with_fallback(
                raw, outdir, recover_all)
            raw_for_analysis = raw

        # ================================================================
        # STEP 2: E01 — try direct, then ewfmount, then ewfexport
        # ================================================================
        elif ext in EWF_EXT:
            # 2a: try tsk_recover directly (works if TSK has libewf)
            print("[*] Trying direct E01 read (TSK + libewf)")
            n, offset, fs_label, partitions = recover_with_fallback(
                image_path, outdir, recover_all)

            if n == 0:
                # 2b: ewfmount (zero disk space, needs sudo)
                print("[*] Direct read failed; trying ewfmount (zero extra disk space)")
                shutil.rmtree(outdir, ignore_errors=True)
                n, offset, fs_label, partitions = ewfmount_extract(
                    image_path, outdir, recover_all)
                raw_for_analysis = os.path.join(outdir + "_ewf_mnt", "ewf1")

            if n == 0:
                # 2c: normalize via ewfexport (needs disk space)
                # CRITICAL: use ewfinfo to get the ACTUAL uncompressed media size.
                # The compressed E01 file can be 50x smaller than the raw it expands to.
                actual_raw_size = _ewf_media_size(image_path) or (image_size * 50)
                free_tmp = _free_space_bytes(tempfile.gettempdir())
                print(f"[*] ewfmount failed; trying ewfexport "
                      f"(raw size ~{actual_raw_size // 2**20} MiB, "
                      f"/tmp has {free_tmp // 2**20} MiB free)")
                workdir = _best_workdir(actual_raw_size)
                raw = normalize_to_raw(image_path, workdir)
                if raw:
                    shutil.rmtree(outdir, ignore_errors=True)
                    n, offset, fs_label, partitions = recover_with_fallback(
                        raw, outdir, recover_all)
                    raw_for_analysis = raw

        # ================================================================
        # STEP 3: raw / dd / img / iso — direct read
        # ================================================================
        else:
            print("[*] Reading raw image directly")
            n, offset, fs_label, partitions = recover_with_fallback(
                image_path, outdir, recover_all)

        # ================================================================
        # RESULT
        # ================================================================
        print(f"    -> {n} files extracted to {outdir}/")
        if n == 0:
            print("[!] 0 files extracted after all attempts.")
            print("    Possible causes:")
            print("    - The image may be encrypted or use an unsupported filesystem")
            print("    - For E01: install ewf-tools (sudo apt install ewf-tools)")
            print("    - Try running with sudo: sudo python ingest_image.py ...")
            return

        # Read deleted/hidden metadata from the image (not the extracted folder)
        # Use the image (or mounted raw) that tsk tools can read
        analysis_img = raw_for_analysis if os.path.exists(str(raw_for_analysis)) \
            else image_path
        deleted_rel = list_deleted(analysis_img, offset)
        hidden_rel = list_hidden(analysis_img, offset)
        if deleted_rel:
            print(f"[*] {len(deleted_rel)} deleted file(s) detected")
        if hidden_rel:
            print(f"[*] {len(hidden_rel)} hidden file(s) detected")

        def to_abs(relset):
            out = set()
            for rel in relset:
                candidate = os.path.realpath(os.path.join(outdir, rel))
                if os.path.exists(candidate):
                    out.add(candidate)
            return out
        deleted_abs, hidden_abs = to_abs(deleted_rel), to_abs(hidden_rel)
        if deleted_abs:
            print(f"    -> {len(deleted_abs)} deleted file(s) tagged")
        if hidden_abs:
            print(f"    -> {len(hidden_abs)} hidden file(s) tagged")

        print("[*] Running ForenSight pipeline on extracted files")
        run_pipeline(outdir, case_id, examiner,
                     deleted_paths=deleted_abs, hidden_paths=hidden_abs)

        # Populate Evidence Source from the image
        img_hash = ""
        if hash_image:
            print("[*] Hashing the source image (SHA-256)")
            img_hash = sha256_of_file(image_path)
        case_metadata.set_evidence_source(
            case_id,
            EvidenceFileName=os.path.basename(image_path),
            EvidenceFilePath=os.path.abspath(image_path),
            EvidenceFileType=f"disk image ({ext.lstrip('.').upper() or 'raw'})",
            EvidenceFileSize=f"{image_size} bytes (image); {n} files extracted",
            EvidenceFileChecksum=img_hash,
            EvidenceFileSystemTime=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            EvidenceFileFileSystem=fs_label or "not determined",
            EvidenceFilePartitionsInfo=partitions or "no partition table (bare filesystem)",
            EvidenceFileWriteBlockMethod="Forensic image; read-only extraction "
                                         "(The Sleuth Kit, no writes to source)")
        print("[+] Evidence Source populated from the image.")
    finally:
        if workdir:
            shutil.rmtree(workdir, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description="Ingest forensic disk image(s)")
    ap.add_argument("image", nargs="+",
                    help="one or more image paths (.E01/.dd/.raw/.aff/.vmdk/...)")
    ap.add_argument("--case", required=True,
                    help="Case ID (REQUIRED — all images go under the same case)")
    ap.add_argument("--examiner", default="unknown")
    ap.add_argument("--out", default="recovered_files",
                    help="base output dir (each image gets a subfolder)")
    ap.add_argument("--all", action="store_true",
                    help="also recover deleted/unallocated files (tsk_recover -e)")
    ap.add_argument("--normalize", action="store_true",
                    help="force convert-to-raw (needed for AFF/VMDK/VHD)")
    ap.add_argument("--no-image-hash", action="store_true",
                    help="skip hashing the source image (faster for large images)")
    args = ap.parse_args()
    for img in args.image:
        imgname = os.path.splitext(os.path.basename(img))[0]
        outdir = (os.path.join(args.out, imgname) if len(args.image) > 1
                  else args.out)
        print(f"\n{'='*60}\n[*] Ingesting: {img}\n{'='*60}")
        try:
            ingest(img, args.case, args.examiner, outdir, args.all,
                   args.normalize, not args.no_image_hash)
        except SystemExit as e:
            print(f"[ERROR] {e}")


if __name__ == "__main__":
    main()
