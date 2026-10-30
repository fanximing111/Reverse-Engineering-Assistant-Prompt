#!/usr/bin/env python3
"""
bin_info.py — Zero-dependency PE / ELF header & section inspector.

Part of ZETA CYBERLAB toolkit: https://github.com/fanximing111/Reverse-Engineering-Assistant-Prompt

Usage:
    python bin_info.py <file> [--imports]

Works on:
    PE32 / PE32+  (.exe / .dll)  — headers, sections, optional data dirs, imports
    ELF32 / ELF64                 — header, sections (names resolved)

No third-party dependencies (pure stdlib). Exit code 0 on success.
"""
import argparse
import struct
import sys

MACHINE = {
    0x014C: "x86", 0x8664: "x86-64", 0x01C0: "ARM", 0xAA64: "ARM64",
    0x01C2: "ARM Thumb", 0x01F0: "PowerPC",
}
ELF_MACHINE = {2: "SPARC", 3: "x86", 8: "MIPS", 20: "PowerPC",
               40: "ARM", 62: "x86-64", 183: "AArch64"}
SUBSYSTEM = {1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI",
             5: "OS2_CUI", 7: "POSIX_CUI", 9: "WINDOWS_CE_GUI",
             10: "EFI_APPLICATION", 14: "XBOX"}
ELF_TYPE = {0: "ET_NONE", 1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"}
DATA_DIRS = ["Export", "Import", "Resource", "Exception", "Security",
             "BaseReloc", "Debug", "Arch", "GlobalPtr", "TLS",
             "LoadConfig", "BoundImport", "IAT", "DelayImport", "COM", "Reserved"]


def rva_to_off(sections, rva):
    for s in sections:
        if s["va"] <= rva < s["va"] + max(s["vsize"], s["rsize"]):
            return rva - s["va"] + s["raw"]
    return None


def read_cstr(data, off, maxlen=256):
    if off is None or off < 0 or off >= len(data):
        return "<bad-rva>"
    end = data.find(b"\x00", off, off + maxlen)
    return data[off:end].decode("latin-1", "replace")


def parse_pe(data):
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("not a PE file (missing MZ)")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("not a PE file (missing PE signature)")
    coff = e_lfanew + 4
    machine, nsec, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, coff)
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    pe32p = magic == 0x20B
    if magic not in (0x10B, 0x20B):
        raise ValueError(f"unknown optional header magic 0x{magic:X}")
    ep = struct.unpack_from("<I", data, opt + 16)[0]
    image_base = struct.unpack_from("<Q" if pe32p else "<I", data, opt + 24)[0]
    subsystem = struct.unpack_from("<H", data, opt + 68)[0]
    ndirs_off = opt + (108 if pe32p else 92)
    ndirs = struct.unpack_from("<I", data, ndirs_off)[0]
    dirs_off = ndirs_off + 4

    sec_tbl = opt + opt_size
    sections = []
    for i in range(nsec):
        base = sec_tbl + i * 40
        name = data[base:base + 8].rstrip(b"\x00").decode("latin-1", "replace")
        vsize, va, rsize, raw = struct.unpack_from("<IIII", data, base + 8)
        chars = struct.unpack_from("<I", data, base + 36)[0]
        flags = "".join(c for bit, c in
                        [(0x20, "X"), (0x40, "R"), (0x80, "W"),
                         (0x02000000, "D"), (0x04000000, "N")] if chars & bit)
        sections.append({"name": name, "vsize": vsize, "va": va,
                         "rsize": rsize, "raw": raw, "flags": flags})

    ts = struct.unpack_from("<I", data, coff + 4)[0]
    import datetime
    link_time = datetime.datetime.fromtimestamp(
        ts, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if ts else "N/A"

    print("=" * 62)
    print("PE32+ (64-bit)" if pe32p else "PE32 (32-bit)")
    print("=" * 62)
    print(f"Machine      : {MACHINE.get(machine, hex(machine))} (0x{machine:X})")
    print(f"TimeDateStamp: {link_time} UTC")
    print(f"EntryPoint   : 0x{image_base + ep:X} (RVA 0x{ep:X})")
    print(f"ImageBase    : 0x{image_base:X}")
    print(f"Subsystem    : {SUBSYSTEM.get(subsystem, hex(subsystem))}")
    print(f"Sections     : {nsec}   DataDirectories: {ndirs}")
    print("-" * 62)
    print(f"{'Name':10} {'VirtAddr':>10} {'VirtSize':>10} {'RawPtr':>10} {'Flags':>6}")
    for s in sections:
        print(f"{s['name']:10} 0x{s['va']:08X} 0x{s['vsize']:08X} "
              f"0x{s['raw']:08X} {s['flags']:>5}")

    print("-" * 62)
    for i in range(min(ndirs, 16)):
        rva, size = struct.unpack_from("<II", data, dirs_off + i * 8)
        if rva:
            print(f"DATA_DIR[{i:2}] {DATA_DIRS[i]:12} RVA 0x{rva:08X}  size 0x{size:X}")

    if not argparse_imports:
        return
    imp_rva = struct.unpack_from("<I", data, dirs_off + 8)[0]
    if not imp_rva:
        print("\nNo import directory.")
        return
    off = rva_to_off(sections, imp_rva)
    print("\nImports:")
    while True:
        oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", data, off)
        if name_rva == 0 and ft == 0:
            break
        dll = read_cstr(data, rva_to_off(sections, name_rva))
        thunk_rva = oft or ft
        toff = rva_to_off(sections, thunk_rva)
        funcs = []
        if toff is not None:
            step, fmt = (8, "<Q") if pe32p else (4, "<I")
            ordinal_flag = 1 << (63 if pe32p else 31)
            for k in range(4096):
                val = struct.unpack_from(fmt, data, toff + k * step)[0]
                if val == 0:
                    break
                if val & ordinal_flag:
                    funcs.append(f"#{val & 0xFFFF}")
                else:
                    hoff = rva_to_off(sections, val & 0xFFFFFF)
                    funcs.append(read_cstr(data, hoff + 2))
        print(f"  {dll}: {', '.join(funcs) if funcs else '<none>'}")
        off += 20


def parse_elf(data):
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        raise ValueError("corrupted ELF ident")
    en = "<" if ei_data == 1 else ">"
    is64 = ei_class == 2
    fmt_hdr = (en + ("HHIQQQIHHHHHH" if is64 else "HHIIIIIHHHHHH"))
    (e_type, e_machine, _ver, e_entry, _phoff, e_shoff, _flags,
     _ehsize, _phesize, _phnum, shesize, shnum, shstrndx) = \
        struct.unpack_from(fmt_hdr, data, 16)
    print("=" * 62)
    print(f"ELF{'64' if is64 else '32'}-bit, {'little' if ei_data == 1 else 'big'}-endian")
    print("=" * 62)
    print(f"Type       : {ELF_TYPE.get(e_type, e_type)}")
    print(f"Machine    : {ELF_MACHINE.get(e_machine, e_machine)} (0x{e_machine:X})")
    print(f"EntryPoint : 0x{e_entry:X}")
    print(f"Sections   : {shnum} (strtab index {shstrndx})")
    if shnum == 0:
        return
    fmt_sec = en + ("IIQQQQIIQQ" if is64 else "IIIIIIIIII")
    shs = []
    for i in range(shnum):
        shs.append(struct.unpack_from(fmt_sec, data, e_shoff + i * shesize))
    stroff = shs[shstrndx][4]  # sh_offset of shstrtab
    print("-" * 62)
    print(f"{'Name':18} {'Type':>6} {'Addr':>14} {'Size':>10}")
    for sh in shs:
        name_off, sh_type, _f, addr, _o, size = sh[0], sh[1], sh[2], sh[3], sh[4], sh[5]
        nend = data.find(b"\x00", stroff + name_off)
        name = data[stroff + name_off:nend].decode("latin-1", "replace") or "<null>"
        print(f"{name:18} {sh_type:>6} 0x{addr:012X} 0x{size:08X}")


def main():
    global argparse_imports
    ap = argparse.ArgumentParser(description="PE/ELF binary inspector (stdlib only)")
    ap.add_argument("file")
    ap.add_argument("--imports", action="store_true", help="PE: dump import table")
    args = ap.parse_args()
    argparse_imports = args.imports
    with open(args.file, "rb") as f:
        data = f.read()
    try:
        if data[:2] == b"MZ":
            parse_pe(data)
        elif data[:4] == b"\x7fELF":
            parse_elf(data)
        else:
            raise ValueError("unsupported format (not MZ / ELF)")
    except Exception as e:
        print(f"[!] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
