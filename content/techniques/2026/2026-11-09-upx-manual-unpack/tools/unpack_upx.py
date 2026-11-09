#!/usr/bin/env python3
"""Educational unpacker for x64 PE files packed with UPX's default stub.

1. Finds the tail jump statically: the first `jmp rel32` after the entry point whose
   target lies in the UPX0 section (preferring one right after `sub rsp,-0x80`).
2. Runs the file under the Windows debug API, breaks on that jump, single-steps and
   reads RIP: that is the original entry point (OEP).
3. Dumps the image, finds the import address table (IAT) by resolving pointers to
   exports of the loaded DLLs, and writes a new PE with a rebuilt import directory.

It handles only UPX's default stub and has no anti-analysis or loader features.
Run it only inside an isolated VM, on files you are allowed to run.
Usage: python unpack_upx.py PACKED.exe OUT.exe LOG.json   (Windows x64, needs pefile)
"""
from __future__ import annotations

import json
import os
import struct
import sys
from collections import Counter
from dataclasses import dataclass, field

SUB_RSP_M80 = b"\x48\x83\xec\x80"
PAGE = 0x1000


class UnpackError(Exception):
    pass


@dataclass(frozen=True)
class TailJump:
    rva: int
    target_rva: int
    pattern: bool


@dataclass(frozen=True)
class Candidate:
    dll: str
    name: str
    forwarded: bool


@dataclass
class RawBlock:
    iat_rva: int
    entries: list = field(default_factory=list)


@dataclass
class IatBlock:
    dll: str
    iat_rva: int
    names: list


@dataclass
class ImportSection:
    data: bytes
    dir_rva: int
    dir_size: int
    iat_patches: list


@dataclass
class Trace:
    base: int
    oep_rva: int
    image: bytes
    modules: list


# --- pure functions -------------------------------------------------------

def find_tail_jump(stub: bytes, stub_rva: int, start_rva: int, target_lo: int, target_hi: int) -> TailJump:
    """Scan `stub` (mapped at `stub_rva`) from `start_rva` for a jmp rel32 into [target_lo, target_hi)."""
    first = None
    for off in range(max(0, start_rva - stub_rva), len(stub) - 4):
        if stub[off] != 0xE9:
            continue
        rva = stub_rva + off
        target = rva + 5 + struct.unpack_from("<i", stub, off + 1)[0]
        if not target_lo <= target < target_hi:
            continue
        if off >= 4 and stub[off - 4:off] == SUB_RSP_M80:
            return TailJump(rva, target, True)
        if first is None:
            first = TailJump(rva, target, False)
    if first is None:
        raise UnpackError("no jmp rel32 into UPX0 after the entry point")
    return first


def find_iat_region(image: bytes, index: dict) -> list:
    """Largest run of 8-byte slots that point at known exports, split into blocks at zero slots."""
    hits = [off for off in range(0, len(image) - 7, 8) if struct.unpack_from("<Q", image, off)[0] in index]
    regions, current = [], []
    for off in hits:
        if current and not (off - current[-1] == 8 or
                            (off - current[-1] == 16 and struct.unpack_from("<Q", image, off - 8)[0] == 0)):
            regions.append(current)
            current = []
        current.append(off)
    if current:
        regions.append(current)
    if not regions:
        raise UnpackError("no pointers to exports found in the dump")
    region = max(regions, key=len)
    blocks, block = [], None
    for off in region:
        if block is None or off - (block.iat_rva + 8 * len(block.entries)) != 0:
            block = RawBlock(off)
            blocks.append(block)
        block.entries.append(index[struct.unpack_from("<Q", image, off)[0]])
    return blocks


def choose_blocks(raw: list) -> list:
    """Pick one DLL per block: one that explains every slot, preferring the forwarding DLL."""
    out = []
    for rb in raw:
        common = set.intersection(*({c.dll for c in cands} for cands in rb.entries))
        if not common:
            raise UnpackError(f"IAT block at {rb.iat_rva:#x} mixes DLLs")
        fwd = Counter(c.dll for cands in rb.entries for c in cands if c.forwarded and c.dll in common)
        dll = sorted(common, key=lambda d: (-fwd[d], d))[0]
        names = [sorted(c.name for c in cands if c.dll == dll)[0] for cands in rb.entries]
        out.append(IatBlock(dll, rb.iat_rva, names))
    return out


def build_import_section(blocks: list, section_rva: int) -> ImportSection:
    """Descriptors, then lookup tables, then DLL names and hint/name entries."""
    desc_size = (len(blocks) + 1) * 20
    ilt_offsets, off = [], desc_size
    for b in blocks:
        ilt_offsets.append(off)
        off += (len(b.names) + 1) * 8
    strings = bytearray()
    dll_name_rvas, hint_rvas = [], []
    for b in blocks:
        dll_name_rvas.append(section_rva + off + len(strings))
        strings += b.dll.encode() + b"\0"
        if len(strings) % 2:
            strings += b"\0"
        rvas = []
        for name in b.names:
            rvas.append(section_rva + off + len(strings))
            strings += b"\0\0" + name.encode() + b"\0"
            if len(strings) % 2:
                strings += b"\0"
        hint_rvas.append(rvas)
    data = bytearray(off) + strings
    patches = []
    for i, b in enumerate(blocks):
        struct.pack_into("<IIIII", data, i * 20, section_rva + ilt_offsets[i], 0, 0, dll_name_rvas[i], b.iat_rva)
        for j, rva in enumerate(hint_rvas[i]):
            struct.pack_into("<Q", data, ilt_offsets[i] + 8 * j, rva)
            patches.append((b.iat_rva + 8 * j, rva))
    return ImportSection(bytes(data), section_rva, desc_size, patches)


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def rebuild_pe(image: bytes, base: int, oep_rva: int, blocks: list) -> bytes:
    """Turn a memory dump into a PE file whose raw layout equals its memory layout."""
    img = bytearray(image)
    pe_off = struct.unpack_from("<I", img, 0x3C)[0]
    coff = pe_off + 4
    nsec, opt_size = struct.unpack_from("<H", img, coff + 2)[0], struct.unpack_from("<H", img, coff + 16)[0]
    opt = coff + 20
    if struct.unpack_from("<H", img, opt)[0] != 0x20B:
        raise UnpackError("not a PE32+ image")
    sec_table = opt + opt_size
    size_of_image = struct.unpack_from("<I", img, opt + 56)[0]
    first_va = min(struct.unpack_from("<I", img, sec_table + 40 * i + 12)[0] for i in range(nsec))
    if sec_table + 40 * (nsec + 1) > first_va:
        raise UnpackError("no room in the headers for one more section")

    # The stub drops the write bit from the in-memory section table, but the unpacked code
    # writes to .data inside these sections; mark them code + initialized data, RWX.
    for i in range(nsec):
        h = sec_table + 40 * i
        vsize, va = struct.unpack_from("<II", img, h + 8)
        struct.pack_into("<II", img, h + 16, min(_align(vsize, PAGE), size_of_image - va), va)
        struct.pack_into("<I", img, h + 36, 0xE0000060)

    new_rva = _align(size_of_image, PAGE)
    imports = build_import_section(blocks, new_rva)
    for rva, value in imports.iat_patches:
        struct.pack_into("<Q", img, rva, value)
    raw = _align(len(imports.data), PAGE)
    h = sec_table + 40 * nsec
    struct.pack_into("<8sIIIIIIHHI", img, h, b".idata2", len(imports.data), new_rva, raw, new_rva, 0, 0, 0, 0, 0xC0000040)
    struct.pack_into("<H", img, coff + 2, nsec + 1)

    struct.pack_into("<I", img, opt + 16, oep_rva)
    struct.pack_into("<Q", img, opt + 24, base)
    struct.pack_into("<II", img, opt + 32, PAGE, PAGE)
    struct.pack_into("<II", img, opt + 56, new_rva + raw, first_va)
    struct.pack_into("<I", img, opt + 64, 0)
    dllch = struct.unpack_from("<H", img, opt + 70)[0] & ~0x0040 & ~0x0020
    struct.pack_into("<H", img, opt + 70, dllch)
    dd = opt + 112
    struct.pack_into("<II", img, dd + 8 * 1, imports.dir_rva, imports.dir_size)
    struct.pack_into("<II", img, dd + 8 * 4, 0, 0)
    struct.pack_into("<II", img, dd + 8 * 5, 0, 0)
    struct.pack_into("<II", img, dd + 8 * 11, 0, 0)
    iat_lo = min(b.iat_rva for b in blocks)
    iat_hi = max(b.iat_rva + 8 * (len(b.names) + 1) for b in blocks)
    struct.pack_into("<II", img, dd + 8 * 12, iat_lo, iat_hi - iat_lo)
    return bytes(img[:new_rva]) + imports.data + bytes(raw - len(imports.data))


# --- Windows debugging --------------------------------------------------

def _win():
    import ctypes as C
    from ctypes import wintypes as W

    class STARTUPINFOW(C.Structure):
        _fields_ = [("cb", W.DWORD), ("lpReserved", W.LPWSTR), ("lpDesktop", W.LPWSTR), ("lpTitle", W.LPWSTR),
                    ("dwX", W.DWORD), ("dwY", W.DWORD), ("dwXSize", W.DWORD), ("dwYSize", W.DWORD),
                    ("dwXCountChars", W.DWORD), ("dwYCountChars", W.DWORD), ("dwFillAttribute", W.DWORD),
                    ("dwFlags", W.DWORD), ("wShowWindow", W.WORD), ("cbReserved2", W.WORD),
                    ("lpReserved2", C.c_void_p), ("hStdInput", W.HANDLE), ("hStdOutput", W.HANDLE),
                    ("hStdError", W.HANDLE)]

    class PROCESS_INFORMATION(C.Structure):
        _fields_ = [("hProcess", W.HANDLE), ("hThread", W.HANDLE), ("dwProcessId", W.DWORD), ("dwThreadId", W.DWORD)]

    class EXCEPTION_RECORD(C.Structure):
        _fields_ = [("ExceptionCode", W.DWORD), ("ExceptionFlags", W.DWORD), ("ExceptionRecord", C.c_void_p),
                    ("ExceptionAddress", C.c_void_p), ("NumberParameters", W.DWORD),
                    ("ExceptionInformation", C.c_ulonglong * 15)]

    class EXCEPTION_DEBUG_INFO(C.Structure):
        _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("dwFirstChance", W.DWORD)]

    class CREATE_PROCESS_DEBUG_INFO(C.Structure):
        _fields_ = [("hFile", W.HANDLE), ("hProcess", W.HANDLE), ("hThread", W.HANDLE), ("lpBaseOfImage", C.c_void_p),
                    ("dwDebugInfoFileOffset", W.DWORD), ("nDebugInfoSize", W.DWORD), ("lpThreadLocalBase", C.c_void_p),
                    ("lpStartAddress", C.c_void_p), ("lpImageName", C.c_void_p), ("fUnicode", W.WORD)]

    class LOAD_DLL_DEBUG_INFO(C.Structure):
        _fields_ = [("hFile", W.HANDLE), ("lpBaseOfDll", C.c_void_p), ("dwDebugInfoFileOffset", W.DWORD),
                    ("nDebugInfoSize", W.DWORD), ("lpImageName", C.c_void_p), ("fUnicode", W.WORD)]

    class U(C.Union):
        _fields_ = [("Exception", EXCEPTION_DEBUG_INFO), ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
                    ("LoadDll", LOAD_DLL_DEBUG_INFO), ("raw", C.c_byte * 160)]

    class DEBUG_EVENT(C.Structure):
        _fields_ = [("dwDebugEventCode", W.DWORD), ("dwProcessId", W.DWORD), ("dwThreadId", W.DWORD), ("u", U)]

    k32 = C.WinDLL("kernel32", use_last_error=True)
    psapi = C.WinDLL("psapi", use_last_error=True)
    sig = {
        "CreateProcessW": (W.BOOL, [W.LPCWSTR, W.LPWSTR, C.c_void_p, C.c_void_p, W.BOOL, W.DWORD, C.c_void_p,
                                    W.LPCWSTR, C.POINTER(STARTUPINFOW), C.POINTER(PROCESS_INFORMATION)]),
        "WaitForDebugEvent": (W.BOOL, [C.POINTER(DEBUG_EVENT), W.DWORD]),
        "ContinueDebugEvent": (W.BOOL, [W.DWORD, W.DWORD, W.DWORD]),
        "ReadProcessMemory": (W.BOOL, [W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]),
        "WriteProcessMemory": (W.BOOL, [W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]),
        "VirtualProtectEx": (W.BOOL, [W.HANDLE, C.c_void_p, C.c_size_t, W.DWORD, C.POINTER(W.DWORD)]),
        "FlushInstructionCache": (W.BOOL, [W.HANDLE, C.c_void_p, C.c_size_t]),
        "OpenThread": (W.HANDLE, [W.DWORD, W.BOOL, W.DWORD]),
        "GetThreadContext": (W.BOOL, [W.HANDLE, C.c_void_p]),
        "SetThreadContext": (W.BOOL, [W.HANDLE, C.c_void_p]),
        "TerminateProcess": (W.BOOL, [W.HANDLE, W.UINT]),
        "CloseHandle": (W.BOOL, [W.HANDLE]),
    }
    for name, (res, args) in sig.items():
        fn = getattr(k32, name)
        fn.restype, fn.argtypes = res, args
    psapi.EnumProcessModulesEx.restype = W.BOOL
    psapi.EnumProcessModulesEx.argtypes = [W.HANDLE, C.POINTER(C.c_void_p), W.DWORD, C.POINTER(W.DWORD), W.DWORD]
    psapi.GetModuleFileNameExW.restype = W.DWORD
    psapi.GetModuleFileNameExW.argtypes = [W.HANDLE, C.c_void_p, W.LPWSTR, W.DWORD]
    return C, W, k32, psapi, STARTUPINFOW, PROCESS_INFORMATION, DEBUG_EVENT


CONTEXT_SIZE, OFF_FLAGS, OFF_EFLAGS, OFF_RIP = 0x4D0, 0x30, 0x44, 0xF8
CONTEXT_CONTROL = 0x100001
DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED = 0x00010002, 0x80010001
EXC_BREAKPOINT, EXC_SINGLE_STEP = 0x80000003, 0x80000004


def trace_to_oep(path: str, tail_rva: int, timeout_ms: int = 30000) -> Trace:
    C, W, k32, psapi, STARTUPINFOW, PROCESS_INFORMATION, DEBUG_EVENT = _win()
    si, pi = STARTUPINFOW(), PROCESS_INFORMATION()
    si.cb = C.sizeof(si)
    flags = 0x00000002 | 0x08000000  # DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW
    if not k32.CreateProcessW(os.path.abspath(path), None, None, None, False, flags, None,
                              os.path.dirname(os.path.abspath(path)), C.byref(si), C.byref(pi)):
        raise UnpackError(f"CreateProcessW failed: {C.get_last_error()}")
    ctx_raw = (C.c_ubyte * (CONTEXT_SIZE + 16))()
    ctx = (C.addressof(ctx_raw) + 15) & ~15

    def rw(addr, size):
        buf, n = (C.c_ubyte * size)(), C.c_size_t()
        ok = k32.ReadProcessMemory(pi.hProcess, C.c_void_p(addr), buf, size, C.byref(n))
        return bytes(buf) if ok and n.value == size else None

    def write(addr, data):
        old, n = W.DWORD(), C.c_size_t()
        k32.VirtualProtectEx(pi.hProcess, C.c_void_p(addr), len(data), 0x40, C.byref(old))
        ok = k32.WriteProcessMemory(pi.hProcess, C.c_void_p(addr), data, len(data), C.byref(n))
        k32.VirtualProtectEx(pi.hProcess, C.c_void_p(addr), len(data), old.value, C.byref(W.DWORD()))
        k32.FlushInstructionCache(pi.hProcess, C.c_void_p(addr), len(data))
        if not ok:
            raise UnpackError(f"WriteProcessMemory failed: {C.get_last_error()}")

    def context(tid, update=None):
        th = k32.OpenThread(0x001F03FF, False, tid)
        try:
            C.memset(ctx, 0, CONTEXT_SIZE)
            struct.pack_into("<I", (C.c_ubyte * CONTEXT_SIZE).from_address(ctx), OFF_FLAGS, CONTEXT_CONTROL)
            if not k32.GetThreadContext(th, ctx):
                raise UnpackError(f"GetThreadContext failed: {C.get_last_error()}")
            view = (C.c_ubyte * CONTEXT_SIZE).from_address(ctx)
            if update:
                update(view)
                if not k32.SetThreadContext(th, ctx):
                    raise UnpackError(f"SetThreadContext failed: {C.get_last_error()}")
            return struct.unpack_from("<Q", view, OFF_RIP)[0]
        finally:
            k32.CloseHandle(th)

    base = bp = original = None
    stepping, result = False, None
    ev = DEBUG_EVENT()
    try:
        while True:
            if not k32.WaitForDebugEvent(C.byref(ev), timeout_ms):
                raise UnpackError("timed out waiting for a debug event")
            code, status = ev.dwDebugEventCode, DBG_CONTINUE
            if code == 3:
                info = ev.u.CreateProcessInfo
                if info.hFile:
                    k32.CloseHandle(info.hFile)
                base = info.lpBaseOfImage
                bp = base + tail_rva
                original = rw(bp, 1)
                if original is None or original != b"\xe9":
                    raise UnpackError(f"expected E9 at the tail jump, found {original!r}")
                write(bp, b"\xcc")
            elif code == 6:
                if ev.u.LoadDll.hFile:
                    k32.CloseHandle(ev.u.LoadDll.hFile)
            elif code == 1:
                rec = ev.u.Exception.ExceptionRecord
                addr = rec.ExceptionAddress or 0
                if rec.ExceptionCode == EXC_BREAKPOINT and addr == bp:
                    write(bp, original)

                    def arm(view):
                        struct.pack_into("<Q", view, OFF_RIP, bp)
                        eflags = struct.unpack_from("<I", view, OFF_EFLAGS)[0]
                        struct.pack_into("<I", view, OFF_EFLAGS, eflags | 0x100)
                    context(ev.dwThreadId, arm)
                    stepping = True
                elif rec.ExceptionCode == EXC_SINGLE_STEP and stepping:
                    oep = context(ev.dwThreadId)
                    result = _snapshot(C, W, psapi, pi.hProcess, rw, base, oep)
                    k32.TerminateProcess(pi.hProcess, 0)
                elif rec.ExceptionCode == EXC_BREAKPOINT:
                    pass  # the loader's initial breakpoint
                else:
                    if not ev.u.Exception.dwFirstChance:
                        raise UnpackError(f"unhandled exception {rec.ExceptionCode:#x} at {addr:#x}")
                    status = DBG_EXCEPTION_NOT_HANDLED
            elif code == 5:
                break
            k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status)
    finally:
        k32.TerminateProcess(pi.hProcess, 1)
        k32.CloseHandle(pi.hThread)
        k32.CloseHandle(pi.hProcess)
    if result is None:
        raise UnpackError("the process exited before reaching the OEP")
    return result


def _snapshot(C, W, psapi, hproc, rw, base, oep) -> Trace:
    head = rw(base, PAGE)
    pe_off = struct.unpack_from("<I", head, 0x3C)[0]
    size = struct.unpack_from("<I", head, pe_off + 24 + 56)[0]
    image = bytearray()
    for off in range(0, size, PAGE):
        image += rw(base + off, PAGE) or bytes(PAGE)
    arr, needed = (C.c_void_p * 1024)(), W.DWORD()
    if not psapi.EnumProcessModulesEx(hproc, arr, C.sizeof(arr), C.byref(needed), 3):
        raise UnpackError(f"EnumProcessModulesEx failed: {C.get_last_error()}")
    modules = []
    for i in range(needed.value // C.sizeof(C.c_void_p)):
        buf = C.create_unicode_buffer(32768)
        psapi.GetModuleFileNameExW(hproc, arr[i], buf, 32768)
        modules.append((buf.value, arr[i]))
    return Trace(base, oep - base, bytes(image), modules)


def build_export_index(modules: list, main_base: int) -> dict:
    """address -> candidates, including names that reach the address through forwarders."""
    import pefile
    index, names, forwarders = {}, {}, []
    for path, mbase in modules:
        if mbase == main_base:
            continue
        dll = os.path.basename(path).lower()
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        table = names.setdefault(dll, {})
        for sym in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []):
            name = sym.name.decode() if sym.name else f"#{sym.ordinal}"
            if sym.forwarder:
                forwarders.append((dll, name, sym.forwarder.decode()))
            else:
                table[name] = mbase + sym.address
                index.setdefault(mbase + sym.address, []).append(Candidate(dll, name, False))
        pe.close()
    for dll, name, target in forwarders:
        mod, _, func = target.partition(".")
        mod = mod.lower() + ".dll"
        hosts = [mod] if mod in names else [m for m in names if mod.startswith(("api-ms-", "ext-ms-"))]
        for host in hosts:
            addr = names[host].get(func)
            if addr is not None:
                index.setdefault(addr, []).append(Candidate(dll, name, True))
                break
    return index


def main(argv: list) -> int:
    if len(argv) != 4:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    packed, out_path, log_path = argv[1:]
    import pefile
    try:
        pe = pefile.PE(packed)
        secs = {s.Name.rstrip(b"\0").decode(errors="replace"): s for s in pe.sections}
        if "UPX0" not in secs or "UPX1" not in secs:
            raise UnpackError("sections UPX0/UPX1 not found; not UPX's default layout")
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        upx0, upx1 = secs["UPX0"], secs["UPX1"]
        tj = find_tail_jump(upx1.get_data(), upx1.VirtualAddress, ep, upx0.VirtualAddress,
                            upx0.VirtualAddress + upx0.Misc_VirtualSize)
        pe.close()
        trace = trace_to_oep(packed, tj.rva)
        blocks = choose_blocks(find_iat_region(trace.image, build_export_index(trace.modules, trace.base)))
        with open(out_path, "wb") as fh:
            fh.write(rebuild_pe(trace.image, trace.base, trace.oep_rva, blocks))
    except (UnpackError, OSError, pefile.PEFormatError) as exc:
        print(f"unpack failed: {exc}", file=sys.stderr)
        return 1
    log = {
        "packed": os.path.basename(packed), "entry_rva": hex(ep), "tail_jump_rva": hex(tj.rva),
        "tail_jump_pattern": tj.pattern, "static_target_rva": hex(tj.target_rva), "oep_rva": hex(trace.oep_rva),
        "load_base": hex(trace.base), "image_size": hex(len(trace.image)),
        "iat": [{"dll": b.dll, "iat_rva": hex(b.iat_rva), "functions": b.names} for b in blocks],
        "output": os.path.basename(out_path),
    }
    with open(log_path, "w", encoding="utf-8") as fh:
        json.dump(log, fh, indent=2)
    print(json.dumps({k: log[k] for k in ("tail_jump_rva", "static_target_rva", "oep_rva")}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
