#!/usr/bin/env python3
"""
Apply fixes patches to known Manalink 1.3 binaries.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import struct

import pe_patcher


XOR_EAX_EAX_RET = b"\x31\xC0\xC3"
MOV_EAX_1_RET = b"\xB8\x01\x00\x00\x00\xC3"
AI_TIMER_DIV_10X = b"\x1D\x02\x00\x00"
SCRATCH_SECTION_CHARS = 0xC0000040
ROOT = Path(__file__).with_name("in")
SPECS_PATH = Path(__file__).with_name("specs.json")
OUT_DIR = Path(__file__).with_name("patched")
IN_PLACE = False


SPECS = pe_patcher.load_specs(SPECS_PATH)


@dataclass
class LoadedBinary:
    src: Path
    dst: Path
    spec: pe_patcher.BinarySpec
    image: bytearray
    pe: pe_patcher.PeInfo


LOADED: dict[str, LoadedBinary] = {}


def _load_binary(filename: str) -> LoadedBinary:
    key = filename.lower()
    if key not in SPECS:
        raise ValueError(f"{filename} is not present in specs")
    if key in LOADED:
        return LOADED[key]

    spec = SPECS[key]
    src = ROOT / spec.filename
    image = bytearray(src.read_bytes())
    if len(image) != spec.expected_size:
        raise ValueError(
            f"size mismatch for {spec.filename}: expected {spec.expected_size}, got {len(image)}"
        )
    if spec.expected_md5:
        actual_md5 = pe_patcher.md5_hex(image)
        if actual_md5 != spec.expected_md5:
            raise ValueError(
                f"md5 mismatch for {spec.filename}: expected {spec.expected_md5}, got {actual_md5}"
            )

    if IN_PLACE:
        dst = src
    else:
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        dst = OUT_DIR / spec.filename

    loaded = LoadedBinary(
        src=src,
        dst=dst,
        spec=spec,
        image=image,
        pe=pe_patcher.parse_pe_info(image),
    )
    LOADED[key] = loaded
    return loaded


def patch(filename: str, va: int, blob: bytes) -> None:
    loaded = _load_binary(filename)
    file_off = pe_patcher.patch_bytes_at_va(loaded.image, loaded.pe, va, blob)
    print(
        f"{loaded.spec.filename}: patched VA 0x{va:X} -> file offset 0x{file_off:X} "
        f"with {blob.hex(' ')}"
    )


def replace_all_u32(filename: str, old_value: int, new_value: int, expected_count: int) -> None:
    loaded = _load_binary(filename)
    old_bytes = _u32(old_value)
    new_bytes = _u32(new_value)
    offsets: list[int] = []
    start = 0

    while True:
        idx = loaded.image.find(old_bytes, start)
        if idx < 0:
            break
        offsets.append(idx)
        start = idx + 1

    if len(offsets) != expected_count:
        raise ValueError(
            f"{filename}: expected {expected_count} occurrences of 0x{old_value:08X}, "
            f"found {len(offsets)}"
        )

    for idx in offsets:
        loaded.image[idx : idx + 4] = new_bytes

    off_text = ", ".join(f"0x{off:X}" for off in offsets)
    print(
        f"{loaded.spec.filename}: rewrote {len(offsets)} occurrences of 0x{old_value:08X} "
        f"to 0x{new_value:08X} at {off_text}"
    )


def _u32(value: int) -> bytes:
    return struct.pack("<I", value)


def _rel32(from_va: int, to_va: int, instr_len: int) -> bytes:
    return struct.pack("<i", to_va - (from_va + instr_len))


def build_frame_limiter_mod_3c(clock_iat_va: int) -> bytes:
    """
    Build a no-state frame limiter helper for 32-bit x86.

    Pseudocode:

        void frame_limiter(void)
        {
            clock_t now;
            clock_t target;

            now = clock();
            target = now + (0x3c - (now % 0x3c));
            if ((target - now) == 0x3c) {
                return;
            }

            do {
                now = clock();
            } while (now < target);
        }

    This snaps to the next absolute 0x3c-clock boundary and does not rely on
    any persistent local or global state.

    Returns raw machine code. Current size: 55 bytes.
    """

    return b"".join(
        [
            b"\x55",                  # push ebp
            b"\x8B\xEC",              # mov ebp, esp
            b"\x83\xEC\x04",          # sub esp, 4
            b"\xFF\x15",
            _u32(clock_iat_va),       # call dword ptr [clock]
            b"\x89\x45\xFC",          # mov [ebp-4], eax
            b"\x99",                  # cdq
            b"\xB9\x3C\x00\x00\x00",  # mov ecx, 0x3c
            b"\xF7\xF9",              # idiv ecx
            b"\x85\xD2",              # test edx, edx
            b"\x74\x18",              # je done
            b"\xB8\x3C\x00\x00\x00",  # mov eax, 0x3c
            b"\x2B\xC2",              # sub eax, edx
            b"\x03\x45\xFC",          # add eax, [ebp-4]
            b"\x89\x45\xFC",          # mov [ebp-4], eax
            b"\xFF\x15",
            _u32(clock_iat_va),       # wait_loop: call dword ptr [clock]
            b"\x3B\x45\xFC",          # cmp eax, [ebp-4]
            b"\x7C\xF5",              # jl wait_loop
            b"\x8B\xE5",              # done: mov esp, ebp
            b"\x5D",                  # pop ebp
            b"\xC3",                  # ret
        ]
    )

def pad_with_nops(data: bytes, size: int) -> bytes:
    if len(data) > size:
        raise ValueError("input is larger than target size")
    return data + b"\x90" * (size - len(data))

def build_call_stub(from_va: int, to_va: int, total_len: int) -> bytes:
    if total_len < 5:
        raise ValueError("call stub needs at least 5 bytes")
    return b"\xE8" + _rel32(from_va, to_va, 5) + (b"\x90" * (total_len - 5))

def patch_shandalar_frame_limiter() -> None:
    # code cave for the new limiter function (too long to directly patch)
    # this is a seemingly uncalled function very close to the caller
    cave_va = 0x0055E13A
    cave_size = 120
    # original code block to replace
    site_va = 0x0055E08A
    site_size = 32
    # IAT address for the clock() function
    clock_iat_va = 0x009879F4

    helper = build_frame_limiter_mod_3c(clock_iat_va)
    if len(helper) > cave_size:
        raise ValueError(
            f"frame limiter helper is {len(helper)} bytes but cave only has {cave_size}"
        )

    stub = build_call_stub(site_va, cave_va, site_size)

    patch("shandalar.exe", cave_va, pad_with_nops(helper, cave_size))
    patch("shandalar.exe", site_va, stub)


def patch_large_decode_scratch() -> None:
    # 10x the original sizes, works for 4k but idk how to calculate the optimal size
    haar_size = 0x7A800 * 10
    catalog_size = 0x3CC00 * 10
    total_size = pe_patcher.align_up(haar_size, 0x10) + catalog_size

    targets = [
        ("cardartlib.dll", 0x10032C98, 4, 0x100AD498, 2),
        ("drawcardlib.dll", 0x1003AB68, 4, 0x100B5368, 2),
        #("shandalar.exe", 0x0067ad80, 4, 0x006f5580, 2)
    ]

    for filename, old_haar_va, haar_ref_count, old_catalog_va, catalog_ref_count in targets:
        loaded = _load_binary(filename)

        # No easy way to resize a section so we just add a new one and abandon the old buffer
        section = pe_patcher.add_section(
            loaded.image,
            loaded.pe,
            ".mdfix",
            total_size,
            0x200,
            SCRATCH_SECTION_CHARS,
        )
        loaded.pe = pe_patcher.parse_pe_info(loaded.image)

        new_haar_va = loaded.pe.image_base + section.virtual_address
        new_catalog_va = new_haar_va + pe_patcher.align_up(haar_size, 0x10)

        replace_all_u32(filename, old_haar_va, new_haar_va, haar_ref_count)
        replace_all_u32(filename, old_catalog_va, new_catalog_va, catalog_ref_count)
        print(
            f"{filename}: new scratch section at RVA 0x{section.virtual_address:X}, "
            f"haar=0x{new_haar_va:08X}, catalog=0x{new_catalog_va:08X}"
        )


def write_outputs() -> None:
    for loaded in LOADED.values():
        loaded.dst.write_bytes(loaded.image)
        print(f"{loaded.spec.filename}: wrote {loaded.dst}")


def main() -> int:
    # Disable broken DRM functions which rely on Windows95/98 product IDs in registry
    patch("deckdll.dll", 0x1000DEB9, XOR_EAX_EAX_RET)
    patch("deckdll.dll", 0x100271E3, MOV_EAX_1_RET)

    patch("magic.exe", 0x0043D29B, XOR_EAX_EAX_RET)
    patch("magic.exe", 0x00497A09, MOV_EAX_1_RET)

    patch("shandalar.exe", 0x00441BF9, XOR_EAX_EAX_RET)
    patch("shandalar.exe", 0x00468498, MOV_EAX_1_RET)

    # Allocate new bigger buffers in cardartlib/drawcardlib/shandalar
    patch_large_decode_scratch()

    # Fix invalid CreateFileMappingA param
    patch("magic.exe", 0x4944EE, b"\x68\x02\x00\x00\x00")
    patch("shandalar.exe", 0x464f89, b"\x68\x02\x00\x00\x00")

    # Fix swapped params to GetCurrentDirectoryA trying to write to 0x100 (innocuous)
    # patch("facemaker.exe", 0x40560B, pad_with_nops(b"\x68\x24\xb0\x41\x00\x68\x00\x01\x00\x00", 13))
    
    # Avoid crashing if resolution is too high (changes resolution check from hrez == 1024 to >= 1024)
    patch("facemaker.exe", 0x4058CA, b"\x8D")
    patch("shandalar.exe", 0x4CE2CE, b"\x8D")

    # Patch FUN_00406650 to use calculated res rather than running GetDeviceCaps()
    patch("facemaker.exe", 0x004066af, pad_with_nops(b"\xA1\x10\xD1\x41\x00\xA3\x6C\x65\x42\x00\x89\x46\x20\xA1\x14\xD1\x41\x00", 25))

    # Replace the broken shandalar.exe frame limiter
    patch_shandalar_frame_limiter()

    # Cut AI thinking time by 90%
    patch("magic.exe", 0x004A7CF3, AI_TIMER_DIV_10X)
    patch("shandalar.exe", 0x00559E76, AI_TIMER_DIV_10X)

    # Write accumulated patches to output directory
    write_outputs()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
