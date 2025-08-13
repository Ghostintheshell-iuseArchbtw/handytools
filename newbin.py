#!/usr/bin/env python3
"""
bin_report.py — Advanced static triage & HTML report generator for PE/ELF/Mach-O binaries.

Usage:
  python bin_report.py [options] <files_or_dirs>...

Examples:
  python bin_report.py Themida64.exe Virtualizer.exe vmprotect_gui --out report.html --json
  python bin_report.py /path/to/binaries --recurse --out binary_report.html

Features:
  • File summary: size, hashes, type, arch, compile time, overall entropy, imphash (PE)
  • PE: directories, sections & flags, imports (best-effort), exports, debug dir presence,
        TLS directory presence/callbacks (best-effort), base reloc blocks (summary),
        entrypoint section, overlay size, resource summary, entry point bytes hex
  • ELF: DT_NEEDED dependencies, sections, program headers, entry point bytes hex
  • Mach-O: dylibs, segments, entry point, entry point bytes hex
  • String-based clusters for anti-debug / VM markers (indicative only)
  • Packer detection based on section names, entropy, markers
  • Charts: overall file entropy + top section entropies (if matplotlib present)
  • Single, sleek HTML with inline base64 images, embedded CSS (dark theme), sortable tables
  • Optional JSON dumps (static + extended)
  • Attempt to handle packed binaries with basic unpacking guidance for common packers like UPX

This tool provides basic guidance for unpacking common packers but does not automatically defeat advanced protections.
"""

from __future__ import annotations
import os, sys, io, math, hashlib, struct, argparse, json, base64, datetime
from typing import List, Dict, Any, Tuple
from collections import Counter, defaultdict
from datetime import timezone

# -------- Optional matplotlib (charts). Tool runs without it. --------
HAS_MPL = True
try:
    import matplotlib.pyplot as plt
except Exception:
    HAS_MPL = False

# --------------------- Utilities ---------------------
def compute_hashes(data: bytes) -> Dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

def shannon_entropy(b: bytes) -> float:
    if not b: return 0.0
    counts = Counter(b); total = len(b); ent = 0.0
    for c in counts.values():
        p = c / total
        ent -= p * math.log2(p)
    return ent

def extract_ascii_strings(b: bytes, min_len: int = 5, limit: int = 100000) -> List[str]:
    out=[]; cur=bytearray()
    for by in b:
        if 32 <= by <= 126:
            cur.append(by)
            if len(cur) >= 8192:
                out.append(cur.decode('ascii','ignore')); cur.clear()
        else:
            if len(cur) >= min_len:
                out.append(cur.decode('ascii','ignore'))
            cur.clear()
        if len(out) >= limit: break
    if len(cur) >= min_len and len(out) < limit:
        out.append(cur.decode('ascii','ignore'))
    return out

def extract_utf16le(b: bytes, min_len=5, limit=50000) -> List[str]:
    out=[]; cur=bytearray(); i=0; n=len(b)
    while i+1<n:
        ch = b[i] | (b[i+1]<<8)
        if 32 <= ch <= 126 and b[i+1]==0:
            cur.append(b[i]); cur.append(b[i+1])
        else:
            if len(cur)>=min_len*2:
                try: out.append(cur.decode('utf-16le','ignore'))
                except: pass
            cur.clear()
        if len(out)>=limit: break
        i+=2
    if len(cur)>=min_len*2 and len(out) < limit:
        try: out.append(cur.decode('utf-16le','ignore'))
        except: pass
    return out

# --------------------- Packer Detection ---------------------
PACKER_SECTION_NAMES = {
    "UPX": [".upx0", ".upx1", ".upx2"],
    "VMProtect": [".vmp0", ".vmp1", ".vmp2"],
    "Themida": [".themida", ".scode"],
    "ASPack": [".aspack", ".adata"],
    "PECompact": [".pec", ".pec1"],
    "FSG": [".fsg"],
    "ASProtect": [".asprot", ".adata"],
    "Enigma": [".enigma1", ".enigma2"],
    "Obsidium": [".obsidium"],
}

def detect_packer(md: Dict[str, Any], ent: float, markers: List[str], sections: List[Dict]) -> List[str]:
    detected = []
    section_names = [s.get("name", "") for s in sections]
    for packer, sig_sections in PACKER_SECTION_NAMES.items():
        if any(sig in name for name in section_names for sig in sig_sections):
            detected.append(packer)
    if ent > 7.2:
        detected.append("High Entropy (Possible Packer/Compression)")
    for m in markers:
        if m in PACKER_MARKERS:
            detected.append(m)
    return sorted(set(detected))

# --------------------- Binary Parsing ---------------------
MACHINE_MAP = {0x014c:"x86",0x8664:"x64",0x01c0:"ARM",0xAA64:"ARM64"}
ELF_MACHINE_MAP={0x03:"x86",0x3E:"x86-64",0x28:"ARM",0xB7:"ARM64"}
MACHO_MACHINE_MAP = {0x1000007: "x64", 0x7: "x86", 0x100000c: "ARM64"}
DIR_NAMES = ["EXPORT","IMPORT","RESOURCE","EXCEPTION","SECURITY","BASERELOC","DEBUG","ARCHITECTURE","GLOBALPTR","TLS","LOAD_CONFIG","BOUND_IMPORT","IAT","DELAY_IMPORT","COM_DESCRIPTOR","RESERVED"]

def is_pe(b: bytes) -> bool:
    if len(b) < 0x40 or b[:2] != b"MZ": return False
    pe_off = struct.unpack_from("<I", b, 0x3C)[0]
    return pe_off + 4 <= len(b) and b[pe_off:pe_off+4] == b"PE\x00\x00"

def is_elf(b: bytes) -> bool:
    return len(b) >= 4 and b[:4] == b"\x7fELF"

def is_macho(b: bytes) -> bool:
    return len(b) >= 4 and b[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")

def parse_pe_metadata(b: bytes) -> Dict[str, Any]:
    md={"is_pe":False,"arch":None,"pe_offset":None,"compile_time_utc":None,"num_sections":None,"sections":[],"entry_point_rva":None}
    if not is_pe(b): return md
    pe_off = struct.unpack_from("<I", b, 0x3C)[0]
    md["is_pe"]=True; md["pe_offset"]=pe_off
    coff_off=pe_off+4
    machine,num_sections,timestamp,_,_,size_opt = struct.unpack_from("<HHIIIH", b, coff_off)
    md["arch"]=MACHINE_MAP.get(machine, hex(machine))
    md["num_sections"]=num_sections
    try: md["compile_time_utc"]=datetime.datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except: md["compile_time_utc"]=None
    opt_off=coff_off+20
    if opt_off + size_opt > len(b): return md
    md["entry_point_rva"]=struct.unpack_from("<I", b, opt_off+16)[0]
    sec_off=opt_off+size_opt
    sections=[]
    for i in range(num_sections):
        sh=sec_off+i*40
        if sh+40>len(b): break
        name=b[sh:sh+8].rstrip(b"\x00").decode("ascii","replace")
        virt_size, virt_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", b, sh+8)
        chars = struct.unpack_from("<I", b, sh+36)[0]
        sec_bytes=b[raw_ptr:raw_ptr+raw_size] if raw_ptr+raw_size<=len(b) else b""
        sections.append({"name":name,"virtual_size":virt_size,"virtual_address":virt_addr,"raw_size":raw_size,"raw_ptr":raw_ptr,"entropy":round(shannon_entropy(sec_bytes),3) if sec_bytes else None, "chars": chars})
    md["sections"]=sections
    return md

def parse_elf_metadata(b: bytes) -> Dict[str, Any]:
    md={"is_elf":False,"class":None,"machine":None,"endianness":None,"entry_point":None,"sections":[], "program_headers": []}
    if not is_elf(b): return md
    md["is_elf"]=True
    elf_class=b[4]; md["class"]="ELF32" if elf_class==1 else "ELF64" if elf_class==2 else str(elf_class)
    md["endianness"]="LE" if b[5]==1 else "BE" if b[5]==2 else "Unknown"
    endian="<" if md["endianness"]=="LE" else ">"
    try:
        e_machine=struct.unpack_from(endian+"H", b, 18)[0]
        md["machine"]=ELF_MACHINE_MAP.get(e_machine, hex(e_machine))
        e_entry = struct.unpack_from(endian+("I" if elf_class==1 else "Q"), b, 0x18)[0]
        md["entry_point"]=e_entry
        e_phoff = struct.unpack_from(endian+("I" if elf_class==1 else "Q"), b, 0x1C if elf_class==1 else 0x20)[0]
        e_shoff = struct.unpack_from(endian+("I" if elf_class==1 else "Q"), b, 0x20 if elf_class==1 else 0x28)[0]
        e_phentsize = struct.unpack_from(endian+"H", b, 0x2A if elf_class==1 else 0x36)[0]
        e_phnum = struct.unpack_from(endian+"H", b, 0x2C if elf_class==1 else 0x38)[0]
        e_shentsize = struct.unpack_from(endian+"H", b, 0x2E if elf_class==1 else 0x3A)[0]
        e_shnum = struct.unpack_from(endian+"H", b, 0x30 if elf_class==1 else 0x3C)[0]
        # Program headers
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if elf_class==1:
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack_from(endian+"8I", b, off)
            else:
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack(endian+"II6Q", b, off)
            md["program_headers"].append({"type": p_type, "flags": p_flags, "offset": p_offset, "vaddr": p_vaddr, "filesz": p_filesz, "memsz": p_memsz})
        # Sections
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            if elf_class==1:
                name_idx, s_type, flags, addr, offset, size, link, info, addralign, entsize = struct.unpack_from(endian+"10I", b, off)
            else:
                name_idx, s_type, flags, addr, offset, size, link, info, addralign, entsize = struct.unpack_from(endian+"II6QII", b, off)
            sec_bytes = b[offset:offset + size] if offset + size <= len(b) else b""
            md["sections"].append({"type": s_type, "flags": flags, "addr": addr, "offset": offset, "size": size, "entropy": round(shannon_entropy(sec_bytes), 3) if sec_bytes else None})
    except:
        pass
    return md

def parse_macho_metadata(b: bytes) -> Dict[str, Any]:
    md={"is_macho":False,"cpu_type":None,"entry_point":None,"dylibs":[], "segments":[]}
    if not is_macho(b): return md
    md["is_macho"]=True
    magic = b[0:4]
    is64 = magic in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
    endian = "<" if magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf") else ">"
    header_size = 32 if is64 else 28
    if len(b) < header_size: return md
    cpu_type = struct.unpack_from(endian+"I", b, 4)[0]
    md["cpu_type"] = MACHO_MACHINE_MAP.get(cpu_type, hex(cpu_type))
    ncmds = struct.unpack_from(endian+"I", b, 16 if is64 else 12)[0]
    sizeofcmds = struct.unpack_from(endian+"I", b, 20 if is64 else 16)[0]
    cursor = header_size
    text_fileoff = 0
    for _ in range(ncmds):
        if cursor + 8 > len(b): break
        cmd, cmdsize = struct.unpack_from(endian+"II", b, cursor)
        if cmd == 0x1c:  # LC_LOAD_DYLIB
            offset = struct.unpack_from(endian+"I", b, cursor + 8)[0]
            name_off = cursor + offset
            name = b[name_off:name_off + cmdsize - offset].rstrip(b"\x00").decode('utf-8', 'ignore')
            md["dylibs"].append(name)
        elif cmd in (0x1, 0x19):  # LC_SEGMENT or LC_SEGMENT_64
            segname = b[cursor+8:cursor+24].rstrip(b"\x00").decode('ascii', 'ignore')
            vmaddr = struct.unpack_from(endian+"Q" if is64 else "I", b, cursor+24 if is64 else cursor+16)[0]
            vmsize = struct.unpack_from(endian+"Q" if is64 else "I", b, cursor+32 if is64 else cursor+20)[0]
            fileoff = struct.unpack_from(endian+"Q" if is64 else "I", b, cursor+40 if is64 else cursor+24)[0]
            filesz = struct.unpack_from(endian+"Q" if is64 else "I", b, cursor+48 if is64 else cursor+28)[0]
            seg_bytes = b[fileoff:fileoff + filesz] if fileoff + filesz <= len(b) else b""
            md["segments"].append({"name": segname, "vmaddr": vmaddr, "vmsize": vmsize, "fileoff": fileoff, "filesz": filesz, "entropy": round(shannon_entropy(seg_bytes), 3) if seg_bytes else None})
            if segname == "__TEXT":
                text_fileoff = fileoff
        elif cmd == 0x80000028:  # LC_MAIN
            entry_off = struct.unpack_from(endian+"Q", b, cursor + 8)[0]
            md["entry_point"] = entry_off
            md["entry_point_offset"] = text_fileoff + entry_off if text_fileoff else None
        cursor += cmdsize
    return md

def parse_pe_headers(b: bytes) -> Dict[str, Any]:
    if not is_pe(b): return {}
    pe_off = struct.unpack_from("<I", b, 0x3C)[0]
    coff_off = pe_off + 4
    machine, num_sections, tds, _, _, size_opt = struct.unpack_from("<HHIIIH", b, coff_off)
    opt_off = coff_off + 20
    magic = struct.unpack_from("<H", b, opt_off)[0]
    is_pe32_plus = (magic == 0x20b)
    if is_pe32_plus:
        image_base = struct.unpack_from("<Q", b, opt_off + 24)[0]
        aep = struct.unpack_from("<I", b, opt_off + 16)[0]
        data_dir_off = opt_off + 112
    else:
        image_base = struct.unpack_from("<I", b, opt_off + 28)[0]
        aep = struct.unpack_from("<I", b, opt_off + 16)[0]
        data_dir_off = opt_off + 96
    # Data directories
    dirs=[]
    for i in range(16):
        off = data_dir_off + i*8
        if off + 8 > len(b): break
        rva, sz = struct.unpack_from("<II", b, off)
        dirs.append((rva, sz))
    # Sections
    sec_off = opt_off + size_opt
    sections=[]
    for i in range(num_sections):
        sh=sec_off+i*40
        if sh+40>len(b): break
        name=b[sh:sh+8].rstrip(b"\x00").decode("ascii","replace")
        vsize,vaddr,rsize,rptr=struct.unpack_from("<IIII", b, sh+8)
        chars=struct.unpack_from("<I", b, sh+36)[0]
        sections.append({"name":name,"vsize":vsize,"vaddr":vaddr,"rsize":rsize,"rptr":rptr,"chars":chars})
    return {"is_pe32_plus":is_pe32_plus,"entry_point_rva":aep,"image_base":image_base,"dirs":dirs,"sections":sections}

def rva_to_offset(sections, rva):
    for s in sections:
        start = s["vaddr"]; end = start + max(s["vsize"], s["rsize"])
        if start <= rva < end:
            return s["rptr"] + (rva - start) if s["rptr"] != 0 else None
    return None

def read_cstr_rva(b: bytes, peh, rva: int) -> str:
    off = rva_to_offset(peh["sections"], rva)
    if off is None or off >= len(b): return ""
    out=bytearray(); i=off
    while i < len(b) and b[i] != 0:
        out.append(b[i]); i+=1
    return out.decode('ascii','ignore')

def parse_imports(b: bytes, peh) -> List[Dict[str,str]]:
    imports = []
    if len(peh["dirs"]) < 2: return imports
    imp_rva, imp_size = peh["dirs"][1]
    if not (imp_rva and imp_size): return imports
    off = rva_to_offset(peh["sections"], imp_rva)
    if off is None: return imports
    is64 = peh["is_pe32_plus"]; thunk_size = 8 if is64 else 4
    ioff = off
    while ioff + 20 <= len(b):
        orig_first_thunk, time_stamp, fwd_chain, name_rva, first_thunk = struct.unpack_from("<IIIII", b, ioff)
        if orig_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
            break
        dll_name = read_cstr_rva(b, peh, name_rva)
        thunk_rva = orig_first_thunk if orig_first_thunk != 0 else first_thunk
        troff = rva_to_offset(peh["sections"], thunk_rva) if thunk_rva else None
        if troff is not None:
            j = troff
            while j + thunk_size <= len(b):
                thunk = struct.unpack_from("<Q" if is64 else "<I", b, j)[0]
                if thunk == 0: break
                if (not is64 and (thunk & 0x80000000)) or (is64 and (thunk & 0x8000000000000000)):
                    ordinal = thunk & 0xFFFF
                    imports.append({"module": dll_name, "symbol": f"Ord{ordinal}"})
                else:
                    name_off = rva_to_offset(peh["sections"], thunk)
                    if name_off and name_off + 2 < len(b):
                        hint = struct.unpack_from("<H", b, name_off)[0]
                        sym = bytearray(); k = name_off + 2
                        while k < len(b) and b[k] != 0:
                            sym.append(b[k]); k += 1
                        imports.append({"module": dll_name, "symbol": sym.decode('ascii','ignore')})
                j += thunk_size
        ioff += 20
    return imports

def compute_imphash(imports: List[Dict[str, str]]) -> str | None:
    if not imports: return None
    parts = []
    for imp in imports:
        mod = imp["module"].lower().rstrip('.dll')
        sym = imp["symbol"].lower().replace('ord', 'ordinal') if imp["symbol"].startswith('Ord') else imp["symbol"].lower()
        parts.append(f"{mod}.{sym}")
    data = ','.join(parts).encode()
    return hashlib.md5(data).hexdigest()

def parse_exports(b: bytes, peh):
    rva, sz = peh["dirs"][0] if len(peh["dirs"])>0 else (0,0)
    if not (rva and sz): return []
    off = rva_to_offset(peh["sections"], rva)
    if off is None or off + 40 > len(b): return []
    vals = struct.unpack_from("<IIIIIIIIIII", b, off)
    Name, Base, NumberOfFunctions, NumberOfNames, AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals = vals[4], vals[5], vals[6], vals[7], vals[8], vals[9], vals[10]
    dll_name = read_cstr_rva(b, peh, Name)
    aof_off = rva_to_offset(peh["sections"], AddressOfFunctions) if AddressOfFunctions else None
    aon_off = rva_to_offset(peh["sections"], AddressOfNames) if AddressOfNames else None
    aoo_off = rva_to_offset(peh["sections"], AddressOfNameOrdinals) if AddressOfNameOrdinals else None
    out=[]
    if aon_off and aoo_off and aof_off:
        for i in range(NumberOfNames):
            if aon_off + i*4 + 4 > len(b): break
            name_rva = struct.unpack_from("<I", b, aon_off + i*4)[0]
            func_name = read_cstr_rva(b, peh, name_rva)
            if aoo_off + i*2 + 2 <= len(b):
                ord_index = struct.unpack_from("<H", b, aoo_off + i*2)[0]
                if aof_off + ord_index*4 + 4 <= len(b):
                    func_rva = struct.unpack_from("<I", b, aof_off + ord_index*4)[0]
                    out.append({"dll_name": dll_name, "name": func_name, "ordinal": Base + ord_index, "func_rva": hex(func_rva)})
    return out

def parse_debug_presence(peh):
    rva, sz = peh["dirs"][6] if len(peh["dirs"])>6 else (0,0)
    return bool(rva and sz), sz

def parse_tls_callbacks(b: bytes, peh):
    rva, sz = peh["dirs"][9] if len(peh["dirs"])>9 else (0,0)
    if not (rva and sz): return {"present": False}
    off = rva_to_offset(peh["sections"], rva)
    if off is None: return {"present": True, "note": "TLS directory RVA not mapped"}
    is64 = peh["is_pe32_plus"]
    try:
        if is64:
            StartRaw, EndRaw, AddrIndex, AddrCallbacks, SizeZero, Charac = struct.unpack_from("<QQQQII", b, off)
        else:
            StartRaw, EndRaw, AddrIndex, AddrCallbacks, SizeZero, Charac = struct.unpack_from("<IIIIII", b, off)
    except Exception as e:
        return {"present": True, "note": f"TLS parse error: {e}"}
    image_base = peh["image_base"]
    callbacks=[]
    if AddrCallbacks and AddrCallbacks >= image_base:
        cb_rva = AddrCallbacks - image_base
        cb_off = rva_to_offset(peh["sections"], cb_rva)
        if cb_off is not None:
            ptr_size = 8 if is64 else 4
            i = cb_off
            while i + ptr_size <= len(b):
                va = struct.unpack_from("<Q" if is64 else "<I", b, i)[0]
                if va == 0: break
                callbacks.append(hex(va))
                i += ptr_size
    out = {"present": True}
    if callbacks: out["callbacks_va"] = callbacks
    return out

def parse_base_relocs(b: bytes, peh, max_blocks=6):
    rva, sz = peh["dirs"][5] if len(peh["dirs"])>5 else (0,0)
    if not (rva and sz and sz >= 8): return []
    off = rva_to_offset(peh["sections"], rva)
    if off is None: return []
    out = []; end = off + sz; cursor = off; idx = 0
    while cursor + 8 <= end and idx < max_blocks:
        page_rva, block_size = struct.unpack_from("<II", b, cursor)
        if block_size < 8 or cursor + block_size > end:
            break
        entry_count = (block_size - 8) // 2
        out.append({"page_rva": hex(page_rva), "block_size": block_size, "entry_count": entry_count})
        cursor += block_size; idx += 1
    return out

def parse_resources_summary(b: bytes, peh: Dict[str, Any]) -> Dict[str, Any]:
    rva, sz = peh["dirs"][2] if len(peh["dirs"]) > 2 else (0, 0)
    if not (rva and sz): return {"count": 0}
    res_base_off = rva_to_offset(peh["sections"], rva)
    if res_base_off is None: return {"count": 0, "note": "Resource RVA not mapped"}

    def recurse(curr_off: int, level: int) -> int:
        if curr_off + 16 > len(b): return 0
        _, _, _, _, num_named, num_id = struct.unpack_from("<IIIIHH", b, curr_off)
        count = 0
        entry_off = curr_off + 16
        for _ in range(num_named + num_id):
            if entry_off + 8 > len(b): break
            name_id, offset = struct.unpack_from("<II", b, entry_off)
            sub_rva = offset & 0x7FFFFFFF if offset & 0x80000000 else offset
            sub_off = rva_to_offset(peh["sections"], rva + sub_rva)
            if sub_off is None: 
                entry_off += 8
                continue
            if offset & 0x80000000:
                # subdirectory
                count += recurse(sub_off, level + 1)
            else:
                # data entry
                count += 1
            entry_off += 8
        return count

    total_count = recurse(res_base_off, 0)
    return {"count": total_count}

def section_flags_info(chars):
    EXEC = 0x20000000; READ = 0x40000000; WRIT = 0x80000000
    return (bool(chars & EXEC), bool(chars & READ), bool(chars & WRIT))

def elf_dt_needed(b: bytes) -> List[str]:
    if not is_elf(b): return []
    ei_class=b[4]; ei_data=b[5]; endian = "<" if ei_data==1 else ">"
    if ei_class==1:
        e_phoff = struct.unpack_from(endian+"I", b, 28)[0]
        e_phentsize = struct.unpack_from(endian+"H", b, 42)[0]
        e_phnum = struct.unpack_from(endian+"H", b, 44)[0]
    else:
        e_phoff = struct.unpack_from(endian+"Q", b, 32)[0]
        e_phentsize = struct.unpack_from(endian+"H", b, 54)[0]
        e_phnum = struct.unpack_from(endian+"H", b, 56)[0]
    PT_LOAD=1; PT_DYNAMIC=2
    phs = []; loads = []
    for i in range(e_phnum):
        off=e_phoff+i*e_phentsize
        if ei_class==1:
            p_type,p_offset,p_vaddr,p_paddr,p_filesz,p_memsz,p_flags,p_align = struct.unpack_from(endian+"IIIIIIII", b, off)
        else:
            p_type,p_flags,p_offset,p_vaddr,p_paddr,p_filesz,p_memsz,p_align = struct.unpack_from(endian+"IIQQQQQQ", b, off)
        phs.append((p_type,p_offset,p_vaddr,p_filesz))
        if p_type==PT_LOAD: loads.append((p_vaddr,p_offset,p_filesz))
    def vaddr_to_off(v):
        for vv,oo,sz in loads:
            if vv <= v < vv+sz: return oo + (v - vv)
        return None
    dyn = None
    for pt,poff,pva,pfs in phs:
        if pt==PT_DYNAMIC: dyn=(poff,pva,pfs); break
    if not dyn: return []
    dyn_off, dyn_vaddr, dyn_sz = dyn
    entsize = 8 if ei_class==1 else 16
    DT_NEEDED = 1; DT_STRTAB = 5
    strtab_vaddr = None; needed_offsets = []
    i = dyn_off if dyn_off != 0 else vaddr_to_off(dyn_vaddr)
    if i is None: return []
    end = i + dyn_sz
    while i + entsize <= end:
        if ei_class==1:
            d_tag,d_val = struct.unpack_from(endian+"II", b, i)
        else:
            d_tag,d_val = struct.unpack_from(endian+"QQ", b, i)
        if d_tag==0: break
        if d_tag==DT_NEEDED: needed_offsets.append(d_val)
        elif d_tag==DT_STRTAB: strtab_vaddr = d_val
        i += entsize
    strtab_off = vaddr_to_off(strtab_vaddr) if strtab_vaddr else None
    out = []
    if strtab_off is not None:
        for noff in needed_offsets:
            so_off = strtab_off + noff
            s = bytearray(); j = so_off
            while j < len(b) and b[j] != 0:
                s.append(b[j]); j += 1
            out.append(s.decode("ascii","ignore"))
    return out

def elf_vaddr_to_off(b: bytes, vaddr: int) -> int | None:
    ei_class = b[4]; ei_data = b[5]; endian = "<" if ei_data==1 else ">"
    if ei_class==1:
        e_phoff = struct.unpack_from(endian+"I", b, 28)[0]
        e_phentsize = struct.unpack_from(endian+"H", b, 42)[0]
        e_phnum = struct.unpack_from(endian+"H", b, 44)[0]
    else:
        e_phoff = struct.unpack_from(endian+"Q", b, 32)[0]
        e_phentsize = struct.unpack_from(endian+"H", b, 54)[0]
        e_phnum = struct.unpack_from(endian+"H", b, 56)[0]
    loads = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if ei_class==1:
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack_from(endian+"8I", b, off)
        else:
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(endian+"II6Q", b, off)
        if p_type == 1:  # PT_LOAD
            loads.append((p_vaddr, p_offset, p_filesz))
    for vv, oo, sz in loads:
        if vv <= vaddr < vv + sz: return oo + (vaddr - vv)
    return None

# --------------------- Indicators ---------------------
PACKER_MARKERS = ["VMProtect","VMProtectSDK","VMP","Themida","Oreans","WinLicense","ProtectionID","HWID","Trial","Serial Number","License Key","Anti-Debug","IsDebuggerPresent","CheckRemoteDebuggerPresent","NtQueryInformationProcess","OutputDebugStringA","TLS Callback","VirtualProtect","ZwSetInformationThread","RDTSC","IsWow64Process","CreateToolhelp32Snapshot","PECompact","ASPack","UPX","Code Virtualizer","Virtualizer","FSG","ASProtect","Enigma","Obsidium"]
API_CANDS = ["VirtualProtect","VirtualAlloc","LoadLibrary","GetProcAddress","CreateProcess","OpenProcess","WriteProcessMemory","ReadProcessMemory","CreateRemoteThread","NtQueryInformationProcess","ZwProtectVirtualMemory","DeviceIoControl","GetModuleHandle","GetTickCount","QueryPerformanceCounter","IsDebuggerPresent","CheckRemoteDebuggerPresent","NtSetInformationThread","SetUnhandledExceptionFilter","UnhandledExceptionFilter","AddVectoredExceptionHandler"]
HINT_KEYWORDS = {
    "debug_api": ["IsDebuggerPresent","CheckRemoteDebuggerPresent","OutputDebugString","NtQueryInformationProcess","NtSetInformationThread","ZwSetInformationThread","SetUnhandledExceptionFilter","AddVectoredExceptionHandler","DbgBreakPoint","DbgUiRemoteBreakin"],
    "time_anti": ["QueryPerformanceCounter","GetTickCount","RDTSC","rdtsc","timeGetTime","GetSystemTimeAsFileTime"],
    "vm_markers": ["VBox","VirtualBox","VMware","KVM","QEMU","Hyper-V","VBOX","VMX","Parallels","Xen","Bochs","VirtualPC"],
    "tools_names": ["ollydbg","ida","idag","idaw","idau","windbg","x64dbg","x32dbg","scylla","wireshark","fiddler","procmon","procexp","immunity","ghidra","radare2"],
    "sandbox": ["Sandboxie","Cuckoo","Any.Run","AnyRun","Thug","Detonator","cwsandbox","joe sandbox","joesandbox","anubis","fortisandbox"],
    "wine": ["wine","WINEDEBUG","wine_get_unix_file_name"],
}

def cluster_hints(strings: List[str]) -> Dict[str,List[str]]:
    hits = defaultdict(set)
    for s in strings:
        for cat, words in HINT_KEYWORDS.items():
            for w in words:
                if w in s:
                    hits[cat].add(w)
    return {k: sorted(list(v)) for k,v in hits.items()}

# --------------------- Analyzer ---------------------
def analyze_path(path: str, recurse: bool) -> List[str]:
    targets = []
    if os.path.isdir(path):
        for root, _, files in os.walk(path) if recurse else ((path, [], os.listdir(path)),):
            for f in files:
                full = os.path.join(root, f)
                if os.path.isfile(full):
                    targets.append(full)
    else:
        if os.path.isfile(path):
            targets.append(path)
    return targets

def guess_binary(file: str) -> bool:
    try:
        with open(file, "rb") as f:
            hdr = f.read(4)
        return hdr[:2] == b"MZ" or hdr[:4] == b"\x7fELF" or hdr in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
    except Exception:
        return False

def analyze_file(path: str) -> Dict[str, Any]:
    with open(path, "rb") as f: data = f.read()
    size = len(data); hashes = compute_hashes(data); ent = shannon_entropy(data)
    ascii_strs = extract_ascii_strings(data, 5, 10000)
    utf16_strs = extract_utf16le(data, 5, 50000)
    strs = ascii_strs + utf16_strs
    ft = "PE (Windows)" if is_pe(data) else "ELF (Unix)" if is_elf(data) else "Mach-O (macOS)" if is_macho(data) else "Unknown"
    pe = parse_pe_metadata(data) if is_pe(data) else None
    elf = parse_elf_metadata(data) if is_elf(data) else None
    macho = parse_macho_metadata(data) if is_macho(data) else None
    markers_found = sorted(set(m for m in PACKER_MARKERS if any(m in s for s in strs)))[:30]
    apis_found = sorted(set(api for api in API_CANDS if any(api in s for s in strs)))
    sections = pe["sections"] if pe else elf["sections"] if elf else macho["segments"] if macho else []
    packer = detect_packer(pe or elf or macho or {}, ent, markers_found, sections)
    result = {
        "path": path, "size_bytes": size, **hashes, "file_type": ft,
        "overall_entropy": round(ent,3), "pe_meta": pe, "elf_meta": elf, "macho_meta": macho,
        "packers_markers_found": markers_found, "apis_found": apis_found, "detected_packers": packer,
    }
    # Extended
    ext = {
        "pe_directories": [], "pe_sections": [], "pe_imports": [], "pe_exports": [],
        "pe_debug_present": False, "pe_tls": {}, "pe_relocs": [], "elf_needed": [], "hint_clusters": cluster_hints(strs),
        "pe_resources": {}
    }
    ep_bytes_hex = None
    if pe:
        peh = parse_pe_headers(data)
        for i, (rva, sz) in enumerate(peh["dirs"]):
            ext["pe_directories"].append({"dir_index": i, "directory": DIR_NAMES[i] if i < len(DIR_NAMES) else str(i), "rva": hex(rva), "size": sz, "present": bool(rva and sz)})
        # Combine sections with flags and entropy
        for s in pe["sections"]:
            ex, rd, wr = section_flags_info(s["chars"])
            ext["pe_sections"].append({"section": s["name"], "vaddr": hex(s["virtual_address"]), "vsize": s["virtual_size"], "rptr": s["raw_ptr"], "rsize": s["raw_size"], "exec": ex, "read": rd, "write": wr, "entropy": s["entropy"]})
        ext["pe_imports"] = parse_imports(data, peh)
        ext["pe_exports"] = parse_exports(data, peh)
        dbg, dbg_sz = parse_debug_presence(peh); ext["pe_debug_present"] = dbg
        ext["pe_tls"] = parse_tls_callbacks(data, peh)
        ext["pe_relocs"] = parse_base_relocs(data, peh)
        ext["pe_resources"] = parse_resources_summary(data, peh)
        # Imphash
        if ext["pe_imports"]:
            result["imphash"] = compute_imphash(ext["pe_imports"])
        # Overlay
        if pe["sections"]:
            last_end = max(s["raw_ptr"] + s["raw_size"] for s in pe["sections"])
            pe["overlay_size"] = max(0, size - last_end)
        # EP section
        ep_rva = pe["entry_point_rva"]
        for s in pe["sections"]:
            if s["virtual_address"] <= ep_rva < s["virtual_address"] + s["virtual_size"]:
                pe["ep_section"] = s["name"]
                break
        # EP bytes
        ep_off = rva_to_offset(peh["sections"], ep_rva)
        if ep_off is not None:
            ep_bytes_hex = data[ep_off:ep_off + 32].hex()
    if elf:
        ext["elf_needed"] = elf_dt_needed(data)
        # EP bytes
        ep_off = elf_vaddr_to_off(data, elf["entry_point"])
        if ep_off is not None:
            ep_bytes_hex = data[ep_off:ep_off + 32].hex()
    if macho:
        ext["macho_dylibs"] = macho.get("dylibs", [])
        # EP bytes
        ep_off = macho.get("entry_point_offset")
        if ep_off is not None:
            ep_bytes_hex = data[ep_off:ep_off + 32].hex()
    if ep_bytes_hex:
        result["ep_bytes_hex"] = ep_bytes_hex
    result["_extended"] = ext
    return result

# --------------------- Unpacking Guidance ---------------------
def unpack_guidance(packers: List[str]) -> str:
    guidance = []
    if "UPX" in packers:
        guidance.append("For UPX, try 'upx -d <file>' to unpack. Ensure UPX is installed.")
    if "VMProtect" in packers:
        guidance.append("VMProtect: Use dynamic analysis tools like x64dbg with anti-anti-debug plugins.")
    if "Themida" in packers:
        guidance.append("Themida: Consider tools like Themida Unpacker or manual unpacking in a debugger.")
    if "ASPack" in packers:
        guidance.append("ASPack: Use ASPackDie or similar unpackers.")
    if guidance:
        return "\n".join(guidance)
    return "No specific unpacking guidance available for detected packers. Use general reverse engineering techniques."

# --------------------- HTML rendering ---------------------
CSS = """
:root{--bg:#0f1115;--panel:#171a21;--ink:#e6e6e6;--muted:#a8b3cf;--accent:#7aa2f7;--good:#78dba9;--warn:#ffbe55;--bad:#ff6b6b;--card:#12141a;--chip:#1f2430;--code:#0b0d12}
* {box-sizing:border-box}html,body{background:var(--bg);color:var(--ink);font:14px/1.6 system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,'Helvetica Neue',Arial,'Noto Sans','Apple Color Emoji','Segoe UI Emoji';margin:0}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.wrapper{max-width:1200px;margin:0 auto;padding:28px 18px 80px}
.header{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:20px}
.brand{display:flex;align-items:center;gap:14px}.brand .logo{width:42px;height:42px;border-radius:12px;background:linear-gradient(135deg,var(--accent),#9b8cff);box-shadow:0 6px 18px rgba(122,162,247,.25)}.brand h1{font-size:20px;margin:0}.meta{color:var(--muted);font-size:12px}
.nav{display:flex;gap:10px;flex-wrap:wrap}.nav a{background:var(--chip);color:var(--ink);padding:8px 12px;border-radius:999px;border:1px solid #272d3d}
.section{background:var(--panel);border:1px solid #22273a;border-radius:16px;padding:18px;margin-top:18px;box-shadow:0 6px 20px rgba(0,0,0,.25)}.section h2{margin:0 0 10px 0;font-size:18px}
.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px}.card{background:var(--card);border:1px solid #1f2436;border-radius:14px;padding:14px}
.kv{display:flex;justify-content:space-between;margin:8px 0;border-bottom:1px dashed #23283a;padding-bottom:6px}.kv:last-child{border-bottom:none}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;border:1px solid #303a56;background:var(--chip);color:var(--muted)}.badge.warn{background:rgba(255,190,85,.08);color:var(--warn);border-color:rgba(255,190,85,.35)}.badge.good{background:rgba(120,219,169,.08);color:var(--good);border-color:rgba(120,219,169,.35)}
.figure{margin:8px 0 0 0;text-align:center;background:var(--card);border-radius:12px;padding:12px;border:1px solid #1f2436}.figure img{max-width:100%;border-radius:10px}.figure .cap{color:var(--muted);font-size:12px;margin-top:6px}
.table{width:100%;border-collapse:collapse;border-spacing:0}.table th,.table td{padding:8px 10px;border-bottom:1px solid #22273a;vertical-align:top}.table thead th{text-align:left;font-weight:600;color:var(--muted);border-bottom:1px solid #2a3150;cursor:pointer}.table tr:hover td{background:rgba(122,162,247,.06)}
.small{font-size:12px;color:var(--muted)}.code{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono','Courier New',monospace;background:var(--code);padding:2px 6px;border-radius:6px;border:1px solid #20263a}
hr.sep{border:0;border-top:1px dashed #2a2f43;margin:14px 0}
"""

JS_SORT = """
<script>
function sortTable(table, col, reverse = false) {
  const tb = table.tBodies[0]; const tr = Array.from(tb.rows);
  tr.sort((a, b) => {
    const A = a.cells[col].textContent.trim(); const B = b.cells[col].textContent.trim();
    return /^[0-9.]+$/.test(A) ? (parseFloat(A) - parseFloat(B)) : A.localeCompare(B);
  });
  if (reverse) tr.reverse();
  tr.forEach(row => tb.appendChild(row));
}
document.querySelectorAll('.table thead th').forEach((th, col) => {
  th.addEventListener('click', () => {
    const table = th.closest('table'); const reverse = table.dataset.sortCol == col && table.dataset.sortDir == 'asc';
    sortTable(table, col, reverse);
    table.dataset.sortCol = col; table.dataset.sortDir = reverse ? 'desc' : 'asc';
  });
});
</script>
"""

def badge_entropy(e: float) -> str:
    if e is None: return '<span class="badge">n/a</span>'
    if e >= 7.2: return '<span class="badge warn">high</span>'
    if e >= 6.0: return '<span class="badge">elevated</span>'
    return '<span class="badge good">normal</span>'

def html_escape(s: Any) -> str:
    return ("" if s is None else str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;"))

def table(headers: List[str], rows: List[List[Any]]) -> str:
    thead = "<thead><tr>" + "".join(f"<th>{html_escape(h)}</th>" for h in headers) + "</tr></thead>"
    body = []
    for r in rows:
        tds = "".join(f"<td>{c if isinstance(c, str) and c.startswith('<') else html_escape(c)}</td>" for c in r)
        body.append(f"<tr>{tds}</tr>")
    tbody = "<tbody>" + "".join(body) + "</tbody>"
    return f'<table class="table">{thead}{tbody}</table>'

def b64_png_from_fig() -> str:
    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format="png", bbox_inches="tight")
    plt.close()
    buf.seek(0)
    return "data:image/png;base64," + base64.b64encode(buf.read()).decode("ascii")

def render_html(results: List[Dict[str,Any]], title: str) -> str:
    now = datetime.datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    # Summary rows
    sum_rows = []
    for r in results:
        meta = r.get("pe_meta") or r.get("elf_meta") or r.get("macho_meta") or {}
        arch = meta.get("arch") or meta.get("machine") or meta.get("cpu_type") or ""
        compile_time = meta.get("compile_time_utc") or ""
        num_sections = meta.get("num_sections") or len(meta.get("sections", []))
        imphash = r.get("imphash", "")
        sum_rows.append([
            os.path.basename(r["path"]), r["file_type"], arch,
            f"{r['size_bytes']/1_000_000:.2f} MB",
            f"{r['overall_entropy']:.3f} {badge_entropy(r['overall_entropy'])}",
            r["md5"], r["sha256"],
            compile_time, num_sections,
            ", ".join(r.get("packers_markers_found", [])[:6]),
            ", ".join(r.get("apis_found", [])[:6]),
            ", ".join(r.get("detected_packers", [])),
            imphash,
        ])
    files_table = table(
        ["File","Type","Arch","Size","Entropy","MD5","SHA-256","Compile Time","Sections","Markers","APIs","Detected Packers","ImpHash"],
        sum_rows
    )

    # Charts
    charts_html = ""
    if HAS_MPL and results:
        files = [os.path.basename(r["path"]) for r in results]
        ents = [r["overall_entropy"] for r in results]
        try:
            plt.figure(figsize=(8,4.5))
            plt.bar(files, ents, color='skyblue')
            plt.xlabel("File"); plt.ylabel("Shannon Entropy")
            plt.title("Overall File Entropy")
            plt.xticks(rotation=45, ha="right")
            charts_html += f'<div class="figure"><img src="{b64_png_from_fig()}" alt="Overall Entropy"/><div class="cap">Overall file entropy; ≥7.2 flagged as high.</div></div>'
        except Exception:
            pass
        # Section entropies
        for r in results:
            meta = r.get("pe_meta") or r.get("elf_meta") or r.get("macho_meta") or {}
            pairs = [(s.get("name", hex(s.get("addr") or s.get("vmaddr") or s.get("virtual_address") or 0)), s.get("entropy")) for s in meta.get("sections", []) if s.get("entropy") is not None]
            if not pairs: continue
            pairs = sorted(pairs, key=lambda t: t[1], reverse=True)[:20]
            secs = [p[0] for p in pairs]; es = [p[1] for p in pairs]
            try:
                plt.figure(figsize=(9,5))
                plt.bar(secs, es, color='lightgreen')
                plt.xlabel("Section/Segment"); plt.ylabel("Entropy")
                plt.title(f"Top Entropy Sections — {os.path.basename(r['path'])}")
                plt.xticks(rotation=45, ha="right")
                charts_html += f'<div class="figure"><img src="{b64_png_from_fig()}" alt="Section Entropy"/><div class="cap">Top entropy sections for {html_escape(os.path.basename(r["path"]))}</div></div>'
            except Exception:
                pass
    elif not HAS_MPL:
        charts_html = '<div class="small">Matplotlib not available; charts disabled. Install matplotlib to enable.</div>'

    # Aggregated extended tables
    dir_rows = []; sec_rows = []; tls_rows = []; dbg_rows = []; imp_rows = []; exp_rows = []; reloc_rows = []; elf_rows = []; hint_rows = []; macho_rows = []; res_rows = []; ep_rows = []; overlay_rows = []
    for r in results:
        ext = r.get("_extended", {})
        # PE directories
        for d in ext.get("pe_directories", []):
            dir_rows.append([os.path.basename(r["path"]), d["dir_index"], d["directory"], d["rva"], d["size"], "yes" if d["present"] else ""])
        # Sections
        for s in ext.get("pe_sections", []):
            sec_rows.append([os.path.basename(r["path"]), "PE", s["section"], s["vaddr"], s["vsize"], s["rptr"], s["rsize"], s["exec"], s["read"], s["write"], s["entropy"] if s["entropy"] is not None else "n/a"])
        # TLS
        tls = ext.get("pe_tls", {})
        if tls:
            tls_rows.append([os.path.basename(r["path"]), "yes" if tls.get("present") else "", ", ".join(tls.get("callbacks_va", []))])
        # Debug
        if ext.get("pe_debug_present"):
            dbg_rows.append([os.path.basename(r["path"]), "present"])
        # Imports
        for imp in ext.get("pe_imports", []):
            imp_rows.append([os.path.basename(r["path"]), imp["module"], imp["symbol"]])
        # Exports
        for ex in ext.get("pe_exports", []):
            exp_rows.append([os.path.basename(r["path"]), ex["dll_name"], ex["name"], ex["ordinal"], ex["func_rva"]])
        # Relocs
        for bl in ext.get("pe_relocs", []):
            reloc_rows.append([os.path.basename(r["path"]), bl["page_rva"], bl["block_size"], bl["entry_count"]])
        # ELF needed
        for so in ext.get("elf_needed", []):
            elf_rows.append([os.path.basename(r["path"]), so])
        # Mach-O dylibs
        for dy in ext.get("macho_dylibs", []):
            macho_rows.append([os.path.basename(r["path"]), dy])
        # Hints
        for cat, words in ext.get("hint_clusters", {}).items():
            hint_rows.append([os.path.basename(r["path"]), cat, ", ".join(words)])
        # Add ELF/Mach-O sections to sec_rows
        if r.get("elf_meta"):
            for s in r["elf_meta"].get("sections", []):
                sec_rows.append([os.path.basename(r["path"]), "ELF", hex(s["type"]), hex(s["addr"]), s["size"], s["offset"], s["size"], "", "", "", s["entropy"] if s["entropy"] is not None else "n/a"])
        if r.get("macho_meta"):
            for s in r["macho_meta"].get("segments", []):
                sec_rows.append([os.path.basename(r["path"]), "Mach-O", s["name"], hex(s["vmaddr"]), s["vmsize"], s["fileoff"], s["filesz"], "", "", "", s["entropy"] if s["entropy"] is not None else "n/a"])
        # Resources
        res = ext.get("pe_resources", {})
        if res.get("count", 0) > 0:
            res_rows.append([os.path.basename(r["path"]), res["count"]])
        # EP bytes
        if "ep_bytes_hex" in r:
            ep_rows.append([os.path.basename(r["path"]), r["ep_bytes_hex"]])
        # Overlay
        if r.get("pe_meta") and "overlay_size" in r["pe_meta"]:
            overlay_rows.append([os.path.basename(r["path"]), r["pe_meta"]["overlay_size"]])

    dirs_table = table(["File","Index","Directory","RVA","Size","Present"], dir_rows) if dir_rows else "<div class='small'>No PE directories parsed.</div>"
    secs_table = table(["File","Type","Name","Vaddr","Vsize","Rptr","Rsize","Exec","Read","Write","Entropy"], sec_rows) if sec_rows else "<div class='small'>No sections parsed.</div>"
    tls_table = table(["File","TLS Present","Callbacks (VA)"], tls_rows) if tls_rows else "<div class='small'>No TLS directory parsed.</div>"
    dbg_table = table(["File","Debug Directory"], dbg_rows) if dbg_rows else "<div class='small'>No debug directory entries.</div>"
    imp_table = table(["File","Module","Symbol"], imp_rows) if imp_rows else "<div class='small'>No imports parsed.</div>"
    exp_table = table(["File","DLL","Name","Ordinal","Func RVA"], exp_rows) if exp_rows else "<div class='small'>No exports found.</div>"
    reloc_table = table(["File","Page RVA","Block Size","Entry Count"], reloc_rows) if reloc_rows else "<div class='small'>No base relocation blocks parsed.</div>"
    elf_table = table(["File","DT_NEEDED"], elf_rows) if elf_rows else "<div class='small'>No DT_NEEDED entries resolved.</div>"
    macho_table = table(["File","Dylib"], macho_rows) if macho_rows else "<div class='small'>No Mach-O dylibs found.</div>"
    hint_table = table(["File","Category","Hits"], hint_rows) if hint_rows else "<div class='small'>No anti-debug/VM hint strings detected.</div>"
    res_table = table(["File","Resource Count"], res_rows) if res_rows else "<div class='small'>No resources parsed.</div>"
    ep_table = table(["File","EP Bytes Hex"], ep_rows) if ep_rows else "<div class='small'>No entry point bytes extracted.</div>"
    overlay_table = table(["File","Overlay Size"], overlay_rows) if overlay_rows else "<div class='small'>No overlay detected.</div>"

    nav_html = "".join([f'<a href="#{sid}">{label}</a>' for sid,label in [
        ("overview","Overview"),("files","Files Summary"),("entropy","Entropy Charts"),("dirs","PE Directories"),
        ("sections","Sections & Flags"),("tls","TLS & Debug"),("imports","Imports / Exports"),
        ("relocs","Base Relocations"),("resources","Resources"),("ep","Entry Point"),("overlay","Overlay"),
        ("elf","ELF DT_NEEDED"),("macho","Mach-O Dylibs"),("hints","Anti-Debug / VM Hints")
    ]])

    html = f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{title}</title>
<style>{CSS}</style>
{JS_SORT}
</head>
<body>
<div class="wrapper">
  <div class="header">
    <div class="brand"><div class="logo"></div><div><h1>{title}</h1><div class="meta">Generated {now}</div></div></div>
    <div class="nav">{nav_html}</div>
  </div>

  <div id="overview" class="section">
    <h2>Overview</h2>
    <div class="card">
      This report consolidates advanced static metadata for the analyzed binaries. Packer detection and basic unpacking guidance included.
      <hr class="sep">
      <div class="small">Note: Timestamps and layouts may be manipulated. Treat as indicative.</div>
    </div>
  </div>

  <div id="files" class="section"><h2>Files Summary</h2>
    <div class="card">{files_table}</div>
  </div>

  <div id="entropy" class="section"><h2>Entropy Charts</h2>
    {charts_html or '<div class="small">No charts available.</div>'}
  </div>

  <div id="dirs" class="section"><h2>PE Directories</h2><div class="card">{dirs_table}</div></div>
  <div id="sections" class="section"><h2>Sections & Flags</h2><div class="card">{secs_table}</div></div>
  <div id="tls" class="section"><h2>TLS & Debug</h2><div class="card"><h3>TLS</h3>{tls_table}<hr class="sep"><h3>Debug</h3>{dbg_table}</div></div>

  <div id="imports" class="section"><h2>Imports / Exports</h2>
    <div class="card"><h3>Imports</h3>{imp_table}<hr class="sep"><h3>Exports</h3>{exp_table}</div>
  </div>

  <div id="relocs" class="section"><h2>Base Relocations</h2><div class="card">{reloc_table}</div></div>
  <div id="resources" class="section"><h2>PE Resources Summary</h2><div class="card">{res_table}</div></div>
  <div id="ep" class="section"><h2>Entry Point Bytes (First 32)</h2><div class="card">{ep_table}</div></div>
  <div id="overlay" class="section"><h2>PE Overlay Size</h2><div class="card">{overlay_table}</div></div>
  <div id="elf" class="section"><h2>ELF DT_NEEDED</h2><div class="card">{elf_table}</div></div>
  <div id="macho" class="section"><h2>Mach-O Dylibs</h2><div class="card">{macho_table}</div></div>
  <div id="hints" class="section"><h2>Anti-Debug / VM Hint Clusters</h2><div class="card">{hint_table}</div></div>
</div>
</body></html>"""
    return html

# --------------------- Main ---------------------
def main():
    ap = argparse.ArgumentParser(description="Generate an advanced HTML static-analysis report for PE/ELF/Mach-O binaries.")
    ap.add_argument("paths", nargs="+", help="Files or directories to analyze")
    ap.add_argument("--recurse", action="store_true", help="Recurse into directories")
    ap.add_argument("--out", default="binary_report.html", help="Output HTML file path")
    ap.add_argument("--title", default="Binary Analysis Report", help="Report title")
    ap.add_argument("--json", action="store_true", help="Also write JSON outputs")
    ap.add_argument("--max-files", type=int, default=0, help="Limit number of binaries (0 = no limit)")
    args = ap.parse_args()

    # Gather targets
    candidates = []
    for p in args.paths:
        candidates += analyze_path(p, args.recurse)
    targets = [c for c in candidates if guess_binary(c)]
    if args.max_files and len(targets) > args.max_files:
        targets = targets[:args.max_files]

    if not targets:
        print("No binaries found.", file=sys.stderr)
        sys.exit(2)

    results = []
    for t in targets:
        try:
            result = analyze_file(t)
            if result["detected_packers"]:
                print(f"[!] Detected packers in {t}: {', '.join(result['detected_packers'])}")
                print(unpack_guidance(result["detected_packers"]))
            results.append(result)
        except Exception as e:
            sys.stderr.write(f"[!] Failed to analyze {t}: {e}\n")

    # Write HTML
    html = render_html(results, args.title)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] HTML report written to: {os.path.abspath(args.out)}")

    # Optional JSON
    if args.json:
        base = os.path.splitext(os.path.abspath(args.out))[0]
        static_path = base + "_static.json"
        extended_path = base + "_extended.json"
        static_list = [{k: v for k, v in r.items() if k != "_extended"} for r in results]
        extended_bundle = {"files": [{"path": r["path"], **r.get("_extended", {})} for r in results]}
        with open(static_path, "w") as f: json.dump(static_list, f, indent=2)
        with open(extended_path, "w") as f: json.dump(extended_bundle, f, indent=2)
        print(f"[+] JSON written to: {static_path} and {extended_path}")

if __name__ == "__main__":
    main()
