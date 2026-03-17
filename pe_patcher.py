#!/usr/bin/env python3
"""Library helpers for PE parsing, file-size specs, and VA-based patching."""

from __future__ import annotations

import json
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class BinarySpec:
    filename: str
    expected_size: int
    expected_md5: str | None = None


@dataclass(frozen=True)
class Section:
    virtual_address: int
    raw_size: int
    virtual_size: int
    pointer_to_raw_data: int


@dataclass(frozen=True)
class PeInfo:
    e_lfanew: int
    file_header_offset: int
    optional_header_offset: int
    section_table_offset: int
    number_of_sections: int
    number_of_sections_offset: int
    image_base: int
    size_of_headers: int
    section_alignment: int
    file_alignment: int
    size_of_image: int
    size_of_image_offset: int
    sections: list[Section]


def read_u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise ValueError(f"u16 read out of range at 0x{offset:X}")
    return int.from_bytes(data[offset : offset + 2], "little", signed=False)


def read_u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise ValueError(f"u32 read out of range at 0x{offset:X}")
    return int.from_bytes(data[offset : offset + 4], "little", signed=False)


def read_u64(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 8 > len(data):
        raise ValueError(f"u64 read out of range at 0x{offset:X}")
    return int.from_bytes(data[offset : offset + 8], "little", signed=False)


def write_u16(data: bytearray, offset: int, value: int) -> None:
    if offset < 0 or offset + 2 > len(data):
        raise ValueError(f"u16 write out of range at 0x{offset:X}")
    data[offset : offset + 2] = int(value).to_bytes(2, "little", signed=False)


def write_u32(data: bytearray, offset: int, value: int) -> None:
    if offset < 0 or offset + 4 > len(data):
        raise ValueError(f"u32 write out of range at 0x{offset:X}")
    data[offset : offset + 4] = int(value).to_bytes(4, "little", signed=False)


def align_up(value: int, alignment: int) -> int:
    if alignment <= 0:
        raise ValueError("alignment must be positive")
    return (value + alignment - 1) // alignment * alignment


def parse_pe_info(image: bytes) -> PeInfo:
    if len(image) < 0x40:
        raise ValueError("file too small for DOS header")
    if image[0:2] != b"MZ":
        raise ValueError("missing MZ signature")

    e_lfanew = read_u32(image, 0x3C)
    if e_lfanew + 24 > len(image):
        raise ValueError("invalid e_lfanew")
    if image[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("missing PE signature")

    file_header_off = e_lfanew + 4
    number_of_sections = read_u16(image, file_header_off + 2)
    size_of_optional_header = read_u16(image, file_header_off + 16)
    optional_header_off = file_header_off + 20
    optional_end = optional_header_off + size_of_optional_header
    if optional_end > len(image):
        raise ValueError("optional header exceeds file size")

    magic = read_u16(image, optional_header_off)
    if magic == 0x10B:
        image_base = read_u32(image, optional_header_off + 28)
    elif magic == 0x20B:
        image_base = read_u64(image, optional_header_off + 24)
    else:
        raise ValueError(f"unsupported optional header magic 0x{magic:X}")

    section_alignment = read_u32(image, optional_header_off + 32)
    file_alignment = read_u32(image, optional_header_off + 36)
    size_of_headers = read_u32(image, optional_header_off + 60)
    size_of_image = read_u32(image, optional_header_off + 56)

    section_table_off = optional_end
    sections: list[Section] = []
    for idx in range(number_of_sections):
        sec_off = section_table_off + idx * 40
        if sec_off + 40 > len(image):
            raise ValueError("section table exceeds file size")
        virtual_size = read_u32(image, sec_off + 8)
        virtual_address = read_u32(image, sec_off + 12)
        raw_size = read_u32(image, sec_off + 16)
        pointer_to_raw_data = read_u32(image, sec_off + 20)
        sections.append(
            Section(
                virtual_address=virtual_address,
                raw_size=raw_size,
                virtual_size=virtual_size,
                pointer_to_raw_data=pointer_to_raw_data,
            )
        )

    return PeInfo(
        e_lfanew=e_lfanew,
        file_header_offset=file_header_off,
        optional_header_offset=optional_header_off,
        section_table_offset=section_table_off,
        number_of_sections=number_of_sections,
        number_of_sections_offset=file_header_off + 2,
        image_base=image_base,
        size_of_headers=size_of_headers,
        section_alignment=section_alignment,
        file_alignment=file_alignment,
        size_of_image=size_of_image,
        size_of_image_offset=optional_header_off + 56,
        sections=sections,
    )


def rva_to_file_offset(pe: PeInfo, image_size: int, rva: int) -> int | None:
    # Match the logic used by carddata_dump's rva_to_file_offset().
    if rva < pe.size_of_headers:
        return rva if rva < image_size else None

    for sec in pe.sections:
        span = max(sec.raw_size, sec.virtual_size)
        if sec.virtual_address <= rva < sec.virtual_address + span:
            delta = rva - sec.virtual_address
            file_off = sec.pointer_to_raw_data + delta
            if delta >= sec.raw_size:
                return None
            if file_off >= image_size:
                return None
            return file_off

    return None


def va_to_file_offset(pe: PeInfo, image_size: int, va: int, image_base: int) -> int | None:
    if va < image_base:
        return None
    rva = va - image_base
    return rva_to_file_offset(pe, image_size, rva)


def patch_bytes_at_va(image: bytearray, pe: PeInfo, va: int, blob: bytes) -> int:
    file_off = va_to_file_offset(pe, len(image), va, pe.image_base)
    if file_off is None:
        raise ValueError(f"VA 0x{va:X} is not mappable to a raw file offset")
    end_off = file_off + len(blob)
    if end_off > len(image):
        raise ValueError(
            f"patch at VA 0x{va:X} overflows file (off=0x{file_off:X}, len={len(blob)})"
        )
    image[file_off:end_off] = blob
    return file_off


def add_section(
    image: bytearray,
    pe: PeInfo,
    name: str,
    virtual_size: int,
    raw_size: int,
    characteristics: int,
) -> Section:
    if not name or len(name) > 8:
        raise ValueError("section name must be 1-8 ASCII bytes")
    if virtual_size <= 0:
        raise ValueError("virtual_size must be positive")
    if not pe.sections:
        raise ValueError("PE image has no sections")

    new_section_off = pe.section_table_offset + pe.number_of_sections * 40
    if new_section_off + 40 > pe.size_of_headers:
        raise ValueError("no room for another section header")

    last = pe.sections[-1]
    last_span = max(last.virtual_size, last.raw_size)
    virtual_address = align_up(last.virtual_address + last_span, pe.section_alignment)

    raw_size_aligned = align_up(raw_size, pe.file_alignment) if raw_size else 0
    if raw_size_aligned:
        pointer_to_raw_data = align_up(len(image), pe.file_alignment)
        if len(image) < pointer_to_raw_data:
            image.extend(b"\x00" * (pointer_to_raw_data - len(image)))
        image.extend(b"\x00" * raw_size_aligned)
    else:
        pointer_to_raw_data = 0

    header = bytearray(40)
    header[0:8] = name.encode("ascii").ljust(8, b"\x00")
    header[8:12] = int(virtual_size).to_bytes(4, "little", signed=False)
    header[12:16] = int(virtual_address).to_bytes(4, "little", signed=False)
    header[16:20] = int(raw_size_aligned).to_bytes(4, "little", signed=False)
    header[20:24] = int(pointer_to_raw_data).to_bytes(4, "little", signed=False)
    header[36:40] = int(characteristics).to_bytes(4, "little", signed=False)
    image[new_section_off : new_section_off + 40] = header

    write_u16(image, pe.number_of_sections_offset, pe.number_of_sections + 1)
    write_u32(
        image,
        pe.size_of_image_offset,
        align_up(virtual_address + virtual_size, pe.section_alignment),
    )

    return Section(
        virtual_address=virtual_address,
        raw_size=raw_size_aligned,
        virtual_size=virtual_size,
        pointer_to_raw_data=pointer_to_raw_data,
    )


def load_specs(path: Path) -> dict[str, BinarySpec]:
    raw: Any = json.loads(path.read_text(encoding="utf-8"))
    rows: list[dict[str, Any]]

    if isinstance(raw, dict) and isinstance(raw.get("binaries"), list):
        rows = raw["binaries"]
    elif isinstance(raw, list):
        rows = raw
    else:
        raise ValueError("spec file must be a list or an object with 'binaries'")

    out: dict[str, BinarySpec] = {}
    for row in rows:
        filename = str(row["filename"])
        expected_size = int(row["expected_size"])
        expected_md5 = row.get("expected_md5")
        if expected_md5 is not None:
            expected_md5 = str(expected_md5).lower()
        out[filename.lower()] = BinarySpec(
            filename=filename,
            expected_size=expected_size,
            expected_md5=expected_md5,
        )
    return out


def collect_specs(root: Path) -> list[BinarySpec]:
    specs: list[BinarySpec] = []
    for path in sorted(root.iterdir(), key=lambda p: p.name.lower()):
        if path.suffix.lower() not in {".exe", ".dll"} or not path.is_file():
            continue
        specs.append(
            BinarySpec(
                filename=path.name,
                expected_size=path.stat().st_size,
            )
        )
    return specs

def write_specs(path: Path, specs: list[BinarySpec]) -> None:
    payload = {
        "binaries": [
            {
                "filename": spec.filename,
                "expected_size": spec.expected_size,
                **({"expected_md5": spec.expected_md5} if spec.expected_md5 else {}),
            }
            for spec in specs
        ]
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def md5_hex(data: bytes | bytearray) -> str:
    h = hashlib.md5()
    h.update(data)
    return h.hexdigest()
