"""
ForenSight - Evidence viewing helpers (used by the dashboard).

Dependency-light, fail-safe helpers to preview an evidence file and to open it in the
host's default application. Every function degrades gracefully if the file is missing,
unreadable, empty, binary, or very large - so the dashboard never crashes mid-demo.
"""
import os
import shutil
import subprocess

PREVIEW_LIMIT = 4096   # bytes read for a text preview
HEX_BYTES = 256        # bytes shown in a hex preview


def classify(path):
    """Return one of: missing, unreadable, empty, text, binary."""
    if not os.path.exists(path):
        return "missing"
    try:
        with open(path, "rb") as f:
            chunk = f.read(PREVIEW_LIMIT)
    except (OSError, PermissionError):
        return "unreadable"
    if not chunk:
        return "empty"
    try:
        chunk.decode("utf-8")
        return "text"
    except UnicodeDecodeError:
        return "binary"


def text_preview(path, limit=PREVIEW_LIMIT):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read(limit)


def hex_preview(path, nbytes=HEX_BYTES):
    with open(path, "rb") as f:
        data = f.read(nbytes)
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_part:<47}  {ascii_part}")
    return "\n".join(lines)


def open_in_default_app(path):
    """Open a file or folder in the host's default application.
    Returns (ok, message). Used for 'redirect to the evidence' on the desktop."""
    if not os.path.exists(path):
        return False, "path does not exist"
    opener = next((c for c in ("xdg-open", "open", "explorer.exe")
                   if shutil.which(c)), None)
    if not opener:
        return False, "no opener available (headless session?)"
    try:
        subprocess.Popen([opener, path],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True, f"opened with {opener}"
    except Exception as e:                      # never propagate to the UI
        return False, str(e)
