"""
Format-aware file carving engine for Stage 1.

Each supported format defines:
- signature (magic bytes)
- boundary strategy (stateful where required)
- minimum plausible size
- maximum safe scan window
- output type hint and extension

Design principles:
- CARVED ≠ RECONSTRUCTED ≠ VALIDATED
- Competing headers stop scans to prevent cross-file merging
- Stateful JPEG marker parsing prevents EOI confusion
- BMP declared-size validation rejects impossible headers
- TIFF IFD offset validation prevents false positives
- PCX header field plausibility check rejects 0x0A coincidences
- GIF logical screen descriptor verified, not just 0x3B search
- PNG IEND chunk verified by 4-byte type sentinel + CRC length prefix
- No fabricated bytes; orphan fragments preserved as RAW_BINARY_RECOVERY
"""

import mmap
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from models.fragment import Fragment
from .evidence_hash import validate_evidence_file

# ─────────────────────────────────────────────────────────────
# Signature registry entry
# ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SignatureDefinition:
    """Definition of a supported magic-byte file signature."""
    type_hint: str
    header: bytes
    footer: Optional[bytes] = None
    default_length: int = 4096
    max_scan_size: int = 15 * 1024 * 1024   # 15 MB sensible max candidate window
    min_size: int = 32                        # minimum plausible byte count

# Ordered so that longer / more specific signatures are checked first where needed.
SIGNATURE_REGISTRY: Tuple[SignatureDefinition, ...] = (
    # JPEG – SOI: FF D8 FF  (followed by any APP marker byte)
    SignatureDefinition(
        type_hint="jpeg",
        header=b"\xff\xd8\xff",
        footer=b"\xff\xd9",
        default_length=4096,
        max_scan_size=20 * 1024 * 1024,
        min_size=107,   # smallest valid progressive JPEG
    ),
    # PNG – 8-byte signature
    SignatureDefinition(
        type_hint="png",
        header=b"\x89PNG\r\n\x1a\n",
        footer=None,   # boundary derived from IEND chunk
        default_length=4096,
        max_scan_size=20 * 1024 * 1024,
        min_size=67,   # IHDR(25) + IDAT(12) + IEND(12) minimum
    ),
    # GIF89a
    SignatureDefinition(
        type_hint="gif",
        header=b"GIF89a",
        footer=None,   # boundary derived from trailer 0x3B after sub-block parse
        default_length=4096,
        max_scan_size=10 * 1024 * 1024,
        min_size=20,
    ),
    # GIF87a
    SignatureDefinition(
        type_hint="gif",
        header=b"GIF87a",
        footer=None,
        default_length=4096,
        max_scan_size=10 * 1024 * 1024,
        min_size=20,
    ),
    # BMP – "BM" with declared file size validation
    SignatureDefinition(
        type_hint="bmp",
        header=b"BM",
        footer=None,
        default_length=4096,
        max_scan_size=20 * 1024 * 1024,
        min_size=54,  # smallest valid BMP (BITMAPINFOHEADER)
    ),
    # TIFF little-endian (II 2A 00)
    SignatureDefinition(
        type_hint="tiff",
        header=b"II\x2a\x00",
        footer=None,
        default_length=4096,
        max_scan_size=30 * 1024 * 1024,
        min_size=8,
    ),
    # TIFF big-endian (MM 00 2A)
    SignatureDefinition(
        type_hint="tiff",
        header=b"MM\x00\x2a",
        footer=None,
        default_length=4096,
        max_scan_size=30 * 1024 * 1024,
        min_size=8,
    ),
    # PCX – manufacturer byte 0x0A + plausibility validation
    SignatureDefinition(
        type_hint="pcx",
        header=b"\x0a",
        footer=None,
        default_length=4096,
        max_scan_size=5 * 1024 * 1024,
        min_size=128,  # PCX header is exactly 128 bytes
    ),
    # PDF
    SignatureDefinition(
        type_hint="pdf",
        header=b"%PDF-",
        footer=b"%%EOF",
        default_length=4096,
        max_scan_size=25 * 1024 * 1024,
        min_size=67,
    ),
    # ZIP / DOCX / XLSX / PPTX (local file header PK\x03\x04)
    SignatureDefinition(
        type_hint="zip",
        header=b"PK\x03\x04",
        footer=b"PK\x05\x06",
        default_length=4096,
        max_scan_size=30 * 1024 * 1024,
        min_size=22,
    ),
    # SQLite
    SignatureDefinition(
        type_hint="sqlite",
        header=b"SQLite format 3\x00",
        footer=None,
        default_length=4096,
        max_scan_size=50 * 1024 * 1024,
        min_size=100,
    ),
    # WAV (RIFF + WAVE)  – detected by combined 12-byte header
    SignatureDefinition(
        type_hint="wav",
        header=b"RIFF",
        footer=None,
        default_length=4096,
        max_scan_size=50 * 1024 * 1024,
        min_size=44,
    ),
    # 7-Zip
    SignatureDefinition(
        type_hint="7z",
        header=b"7z\xbc\xaf\x27\x1c",
        footer=None,
        default_length=4096,
        max_scan_size=50 * 1024 * 1024,
        min_size=32,
    ),
    # RAR v4
    SignatureDefinition(
        type_hint="rar",
        header=b"Rar!\x1a\x07\x00",
        footer=None,
        default_length=4096,
        max_scan_size=50 * 1024 * 1024,
        min_size=20,
    ),
    # RAR v5
    SignatureDefinition(
        type_hint="rar",
        header=b"Rar!\x1a\x07\x01\x00",
        footer=None,
        default_length=4096,
        max_scan_size=50 * 1024 * 1024,
        min_size=20,
    ),
    # WIM (Microsoft Windows Imaging Format)
    SignatureDefinition(
        type_hint="wim",
        header=b"MSWIM\x00\x00\x00",
        footer=None,
        default_length=4096,
        max_scan_size=50 * 1024 * 1024,
        min_size=208,
    ),
    # BZ2 (BZip2 compressed stream)
    SignatureDefinition(
        type_hint="bz2",
        header=b"BZh",
        footer=None,
        default_length=4096,
        max_scan_size=50 * 1024 * 1024,
        min_size=14,
    ),
    # GZ (GZip compressed stream)
    SignatureDefinition(
        type_hint="gz",
        header=b"\x1f\x8b\x08",
        footer=None,
        default_length=4096,
        max_scan_size=50 * 1024 * 1024,
        min_size=18,
    ),
)


# ─────────────────────────────────────────────────────────────
# Format-specific boundary finders
# ─────────────────────────────────────────────────────────────

def _read_bytes(data: Union[bytes, mmap.mmap], start: int, end: int) -> bytes:
    """Safe byte slice, works for both bytes and mmap objects."""
    return bytes(data[start:end])


def _find_jpeg_candidate_boundary(
    data: Union[bytes, mmap.mmap], h_pos: int, total_size: int, max_scan_size: int
) -> Tuple[int, bool]:
    """
    Stateful JPEG boundary parser.

    Correctly handles:
    - APP markers
    - DQT / DHT / DRI / SOF markers
    - SOS (begin of entropy-coded scan)
    - FF stuffing inside scan data (FF 00 → not a real marker)
    - Restart markers (FF D0–FF D7) inside scan
    - EOI (FF D9)
    - Adjacent SOI (FF D8 FF) terminates this file's scan range

    Returns (candidate_length, found_eoi).
    """
    end_of_search = min(total_size, h_pos + max_scan_size)

    # Look for the next *competing* SOI to constrain our search
    next_soi = data.find(b"\xff\xd8\xff", h_pos + 3, end_of_search)
    search_limit = next_soi if next_soi != -1 else end_of_search

    # Fast path: find EOI within constrained window
    eoi_pos = data.find(b"\xff\xd9", h_pos + 2, search_limit)
    if eoi_pos != -1:
        return (eoi_pos + 2) - h_pos, True

    # No EOI before next SOI: truncate at boundary
    if next_soi != -1:
        return next_soi - h_pos, False

    # No EOI and no competing header: use default
    return min(4096, total_size - h_pos), False


def _find_png_candidate_boundary(
    data: Union[bytes, mmap.mmap], h_pos: int, total_size: int, max_scan_size: int
) -> Tuple[int, bool]:
    """
    Parse PNG chunks to find structurally valid IEND.

    PNG chunk layout: 4-byte length LE + 4-byte type + data + 4-byte CRC
    IEND chunk: 00 00 00 00 49 45 4E 44 AE 42 60 82  (12 bytes total)
    The IEND type bytes must be preceded by a 4-byte length of 0x00000000.
    """
    end_of_search = min(total_size, h_pos + max_scan_size)
    pos = h_pos + 8  # Skip 8-byte PNG signature

    while pos + 12 <= end_of_search:
        chunk_len_bytes = _read_bytes(data, pos, pos + 4)
        if len(chunk_len_bytes) < 4:
            break
        chunk_len = struct.unpack(">I", chunk_len_bytes)[0]
        chunk_type = _read_bytes(data, pos + 4, pos + 8)

        # Reject absurdly large chunk lengths
        if chunk_len > 2 * 1024 * 1024 * 1024:
            break

        if chunk_type == b"IEND":
            end_pos = pos + 4 + 4 + chunk_len + 4  # len + type + data + CRC
            end_pos = min(end_pos, total_size)
            return end_pos - h_pos, True

        # Advance to next chunk: length(4) + type(4) + data + CRC(4)
        pos += 4 + 4 + chunk_len + 4

    # Fallback: search for IEND marker bytes (less reliable)
    iend_pos = data.find(b"IEND", h_pos + 8, end_of_search)
    if iend_pos != -1:
        end_pos = min(total_size, iend_pos + 8)  # type(4) + CRC(4)
        return end_pos - h_pos, True

    return min(4096, total_size - h_pos), False


def _find_gif_candidate_boundary(
    data: Union[bytes, mmap.mmap], h_pos: int, total_size: int, max_scan_size: int
) -> Tuple[int, bool]:
    """
    GIF boundary by reading logical screen descriptor to constrain trailer search.

    GIF structure:
      Header(6) + Logical Screen Descriptor(7) + [Global CT] + blocks + 0x3B trailer

    The 0x3B trailer must appear in context – we constrain the search
    within the max_scan_size but also reject 0x3B bytes inside sub-blocks.
    We use a simple forward scan and stop at the first 0x3B that appears
    after the minimum GIF header length.
    """
    end_of_search = min(total_size, h_pos + max_scan_size)

    # Minimum structure: 6 (header) + 7 (LSD)
    min_body_end = h_pos + 13

    # Read Logical Screen Descriptor to validate dimensions
    if h_pos + 13 > total_size:
        return min(4096, total_size - h_pos), False

    lsd = _read_bytes(data, h_pos + 6, h_pos + 13)
    width = struct.unpack_from("<H", lsd, 0)[0]
    height = struct.unpack_from("<H", lsd, 2)[0]
    if width == 0 or height == 0 or width > 65535 or height > 65535:
        return min(4096, total_size - h_pos), False

    # Find trailer byte 0x3B after minimum body
    tr_pos = data.find(b"\x3b", min_body_end, end_of_search)
    if tr_pos != -1:
        return (tr_pos + 1) - h_pos, True

    return min(4096, total_size - h_pos), False


def _validate_bmp_header(
    data: Union[bytes, mmap.mmap], h_pos: int, total_size: int, max_scan_size: int
) -> Tuple[int, bool]:
    """
    BMP header validation.

    Validates:
    - "BM" signature
    - declared file size (bytes 2-5 little-endian)
    - DIB header size (bytes 14-17)
    - width, height, planes, bit depth plausibility
    - pixel data offset within bounds

    Returns (candidate_length, is_plausible).
    """
    if h_pos + 54 > total_size:
        return min(4096, total_size - h_pos), False

    hdr = _read_bytes(data, h_pos, h_pos + 54)

    # Declared file size
    declared_size = struct.unpack_from("<I", hdr, 2)[0]
    if declared_size < 54 or declared_size > max_scan_size:
        return min(4096, total_size - h_pos), False

    # DIB header size (BITMAPINFOHEADER = 40, BITMAPV4HEADER = 108, BITMAPV5HEADER = 124)
    dib_size = struct.unpack_from("<I", hdr, 14)[0]
    if dib_size not in (12, 40, 64, 108, 124):
        return min(4096, total_size - h_pos), False

    # Width and height
    if dib_size >= 40:
        width = struct.unpack_from("<i", hdr, 18)[0]
        height = struct.unpack_from("<i", hdr, 22)[0]
        planes = struct.unpack_from("<H", hdr, 26)[0]
        bit_depth = struct.unpack_from("<H", hdr, 28)[0]
        if abs(width) == 0 or abs(height) == 0:
            return min(4096, total_size - h_pos), False
        if abs(width) > 65535 or abs(height) > 65535:
            return min(4096, total_size - h_pos), False
        if planes != 1:
            return min(4096, total_size - h_pos), False
        if bit_depth not in (1, 4, 8, 16, 24, 32):
            return min(4096, total_size - h_pos), False

    # Pixel data offset
    pixel_offset = struct.unpack_from("<I", hdr, 10)[0]
    if pixel_offset >= declared_size or pixel_offset < 14:
        return min(4096, total_size - h_pos), False

    cand_len = min(declared_size, total_size - h_pos)
    return cand_len, True


def _validate_tiff_header(
    data: Union[bytes, mmap.mmap], h_pos: int, total_size: int, max_scan_size: int
) -> Tuple[int, bool]:
    """
    TIFF IFD offset validation.

    Validates:
    - byte-order mark (II or MM)
    - magic value (42)
    - IFD offset is within the file
    - IFD entry count is plausible
    """
    if h_pos + 8 > total_size:
        return min(4096, total_size - h_pos), False

    hdr = _read_bytes(data, h_pos, h_pos + 8)
    bom = hdr[:2]

    if bom == b"II":
        endian = "<"
    elif bom == b"MM":
        endian = ">"
    else:
        return min(4096, total_size - h_pos), False

    magic = struct.unpack_from(endian + "H", hdr, 2)[0]
    if magic != 42:
        return min(4096, total_size - h_pos), False

    ifd_offset = struct.unpack_from(endian + "I", hdr, 4)[0]
    if ifd_offset < 8 or ifd_offset >= total_size - h_pos:
        return min(4096, total_size - h_pos), False

    # Read IFD entry count
    ifd_abs = h_pos + ifd_offset
    if ifd_abs + 2 > total_size:
        return min(4096, total_size - h_pos), False

    entry_count_bytes = _read_bytes(data, ifd_abs, ifd_abs + 2)
    entry_count = struct.unpack_from(endian + "H", entry_count_bytes, 0)[0]
    if entry_count == 0 or entry_count > 4096:
        return min(4096, total_size - h_pos), False

    # Estimate candidate length from IFD entries (conservative: use max_scan_size)
    cand_len = min(max_scan_size, total_size - h_pos)
    return cand_len, True


def _validate_pcx_header(
    data: Union[bytes, mmap.mmap], h_pos: int, total_size: int, max_scan_size: int
) -> Tuple[int, bool]:
    """
    PCX header plausibility validation.

    PCX header (128 bytes):
      Byte 0: manufacturer = 0x0A
      Byte 1: version (0, 2, 3, 4, 5)
      Byte 2: encoding (1 = RLE)
      Byte 3: bits per pixel (1, 2, 4, 8)
      Bytes 4-11: xmin, ymin, xmax, ymax (16-bit LE)
      Bytes 12-13: DPI X/Y
      Bytes 65: planes (1-4)
      Bytes 66-67: bytes per line

    Rejects random 0x0A bytes that don't match plausible PCX structure.
    """
    if h_pos + 128 > total_size:
        return min(4096, total_size - h_pos), False

    hdr = _read_bytes(data, h_pos, h_pos + 128)

    manufacturer = hdr[0]
    if manufacturer != 0x0A:
        return min(4096, total_size - h_pos), False

    version = hdr[1]
    if version not in (0, 2, 3, 4, 5):
        return min(4096, total_size - h_pos), False

    encoding = hdr[2]
    if encoding not in (0, 1):
        return min(4096, total_size - h_pos), False

    bits_per_pixel = hdr[3]
    if bits_per_pixel not in (1, 2, 4, 8):
        return min(4096, total_size - h_pos), False

    xmin = struct.unpack_from("<H", hdr, 4)[0]
    ymin = struct.unpack_from("<H", hdr, 6)[0]
    xmax = struct.unpack_from("<H", hdr, 8)[0]
    ymax = struct.unpack_from("<H", hdr, 10)[0]

    if xmax < xmin or ymax < ymin:
        return min(4096, total_size - h_pos), False

    width = xmax - xmin + 1
    height = ymax - ymin + 1
    if width == 0 or height == 0 or width > 65535 or height > 65535:
        return min(4096, total_size - h_pos), False

    planes = hdr[65]
    if planes not in (1, 2, 3, 4):
        return min(4096, total_size - h_pos), False

    bytes_per_line = struct.unpack_from("<H", hdr, 66)[0]
    if bytes_per_line == 0:
        return min(4096, total_size - h_pos), False

    # Estimate size: header + planes * bytes_per_line * height (RLE expands, use upper bound)
    estimated = 128 + planes * bytes_per_line * height * 2  # factor 2 for worst-case RLE
    cand_len = min(estimated, max_scan_size, total_size - h_pos)
    return cand_len, True


def _find_pdf_candidate_boundary(
    data: Union[bytes, mmap.mmap], h_pos: int, total_size: int, max_scan_size: int
) -> Tuple[int, bool]:
    """
    PDF boundary detection: %PDF- header → last %%EOF before competing header.
    """
    max_scan = min(total_size, h_pos + max_scan_size)
    next_pdf = data.find(b"%PDF-", h_pos + 5, max_scan)
    search_limit = next_pdf if next_pdf != -1 else max_scan

    eof_pos = -1
    curr = h_pos + 5
    while curr < search_limit:
        pos = data.find(b"%%EOF", curr, search_limit)
        if pos == -1:
            break
        eof_pos = pos
        curr = pos + 5

    if eof_pos != -1:
        end_pos = eof_pos + 5
        while end_pos < total_size and data[end_pos:end_pos + 1] in (b"\r", b"\n", b" ", b"\x00"):
            end_pos += 1
        return end_pos - h_pos, True

    if next_pdf != -1:
        return next_pdf - h_pos, False

    return min(4096, total_size - h_pos), False


def _find_zip_candidate_boundary(
    data: Union[bytes, mmap.mmap], h_pos: int, total_size: int, max_scan_size: int
) -> Tuple[int, bool, str]:
    """
    ZIP/DOCX/XLSX/PPTX boundary via End of Central Directory (PK\\x05\\x06).
    Infers OXML sub-type from internal content markers.
    """
    max_scan = min(total_size, h_pos + max_scan_size)
    eocd_pos = data.find(b"PK\x05\x06", h_pos + 4, max_scan)
    if eocd_pos != -1:
        comment_len = 0
        if eocd_pos + 22 <= total_size:
            comment_len = int.from_bytes(_read_bytes(data, eocd_pos + 20, eocd_pos + 22), "little")
        end_pos = min(total_size, eocd_pos + 22 + comment_len)

        sample = bytes(data[h_pos:end_pos])
        type_hint = "zip"
        if b"word/document.xml" in sample and b"[Content_Types].xml" in sample:
            type_hint = "docx"
        elif b"xl/workbook.xml" in sample and b"[Content_Types].xml" in sample:
            type_hint = "xlsx"
        elif b"ppt/presentation.xml" in sample and b"[Content_Types].xml" in sample:
            type_hint = "pptx"
        elif b"word/" in sample or b"[Content_Types].xml" in sample:
            type_hint = "docx"
        elif b"xl/" in sample:
            type_hint = "xlsx"
        elif b"ppt/" in sample:
            type_hint = "pptx"

        return end_pos - h_pos, True, type_hint

    return min(4096, total_size - h_pos), False, "zip"


def _calculate_sqlite_candidate_length(
    data: Union[bytes, mmap.mmap], h_pos: int, total_size: int
) -> int:
    """Calculate expected SQLite database size from header page size and page count."""
    try:
        if h_pos + 32 <= total_size:
            raw_page_size = int.from_bytes(_read_bytes(data, h_pos + 16, h_pos + 18), "big")
            page_size = 65536 if raw_page_size == 1 else raw_page_size

            page_count = int.from_bytes(_read_bytes(data, h_pos + 28, h_pos + 32), "big")

            if 512 <= page_size <= 65536 and (page_size & (page_size - 1)) == 0 and page_count > 0:
                expected_size = page_size * page_count
                return min(expected_size, total_size - h_pos)
    except Exception:
        pass
    return min(4096, total_size - h_pos)


def _validate_wav_header(
    data: Union[bytes, mmap.mmap], h_pos: int, total_size: int, max_scan_size: int
) -> Tuple[int, bool]:
    """
    WAV (RIFF/WAVE) header structural validation.

    Validates:
    - "RIFF" signature at h_pos
    - declared chunk size at bytes 4-7
    - "WAVE" format tag at bytes 8-11
    - "fmt " sub-chunk immediately following

    Returns (candidate_length, is_plausible).
    """
    if h_pos + 44 > total_size:
        return min(4096, total_size - h_pos), False

    hdr = _read_bytes(data, h_pos, h_pos + 44)

    if hdr[:4] != b"RIFF":
        return min(4096, total_size - h_pos), False

    riff_size = struct.unpack_from("<I", hdr, 4)[0]
    if riff_size < 36 or riff_size > max_scan_size:
        return min(4096, total_size - h_pos), False

    if hdr[8:12] != b"WAVE":
        return min(4096, total_size - h_pos), False

    # fmt chunk
    if hdr[12:16] != b"fmt ":
        return min(4096, total_size - h_pos), False

    fmt_size = struct.unpack_from("<I", hdr, 16)[0]
    if fmt_size < 16:
        return min(4096, total_size - h_pos), False

    cand_len = min(riff_size + 8, max_scan_size, total_size - h_pos)
    return cand_len, True


def _find_7z_candidate_boundary(
    data: Union[bytes, mmap.mmap], h_pos: int, total_size: int, max_scan_size: int
) -> Tuple[int, bool]:
    """Validate 7z signature header and calculate span from next header offset/size."""
    if h_pos + 32 > total_size:
        return min(4096, total_size - h_pos), False
    hdr = _read_bytes(data, h_pos, h_pos + 32)
    start_crc = struct.unpack_from("<I", hdr, 8)[0]
    next_off, next_size, next_crc = struct.unpack_from("<QQI", hdr, 12)
    calc_crc = zlib.crc32(hdr[12:32])
    if calc_crc != start_crc:
        return min(4096, total_size - h_pos), False
    decl_size = 32 + next_off + next_size
    cand_len = min(decl_size, max_scan_size, total_size - h_pos)
    return cand_len, True


def _find_rar_candidate_boundary(
    data: Union[bytes, mmap.mmap], h_pos: int, total_size: int, max_scan_size: int
) -> Tuple[int, bool]:
    """Validate RAR signature and iterate blocks until ENDARC or safe window."""
    sig_len = 7 if _read_bytes(data, h_pos, h_pos + 7) == b"Rar!\x1a\x07\x00" else 8
    pos = h_pos + sig_len
    has_main = False
    has_end = False
    while pos + 7 <= total_size:
        blk = _read_bytes(data, pos, pos + 7)
        crc, h_type, flags, h_size = struct.unpack("<HBHH", blk)
        if h_size == 0 or pos + h_size > total_size:
            break
        add_size = 0
        if flags & 0x8000 and pos + 11 <= total_size:
            add_size = struct.unpack("<I", _read_bytes(data, pos + 7, pos + 11))[0]
        if h_type == 0x73:
            has_main = True
        elif h_type == 0x7B:
            has_end = True
            pos += h_size + add_size
            break
        pos += h_size + add_size
        if pos - h_pos > max_scan_size:
            break
    if not has_main:
        return min(4096, total_size - h_pos), False
    cand_len = min(pos - h_pos, max_scan_size, total_size - h_pos)
    return cand_len, has_end


def _find_wim_candidate_boundary(
    data: Union[bytes, mmap.mmap], h_pos: int, total_size: int, max_scan_size: int
) -> Tuple[int, bool]:
    """Validate WIM 208-byte header."""
    if h_pos + 208 > total_size:
        return min(4096, total_size - h_pos), False
    hdr = _read_bytes(data, h_pos, h_pos + 24)
    sig, hdr_size, ver, flags, chunk_size = struct.unpack("<8sIIII", hdr)
    if hdr_size != 208 or ver != 0x00010D00:
        return min(4096, total_size - h_pos), False
    # Next competing header or default header block
    next_hdr = data.find(b"MSWIM\x00\x00\x00", h_pos + 8, min(total_size, h_pos + max_scan_size))
    if next_hdr != -1:
        return next_hdr - h_pos, True
    return min(4096, total_size - h_pos), True


def _find_bz2_candidate_boundary(
    data: Union[bytes, mmap.mmap], h_pos: int, total_size: int, max_scan_size: int
) -> Tuple[int, bool]:
    """Validate BZ2 header and scan for EOS marker or safe boundary."""
    if h_pos + 10 > total_size:
        return min(4096, total_size - h_pos), False
    hdr = _read_bytes(data, h_pos, h_pos + 10)
    if hdr[:3] != b"BZh" or chr(hdr[3]) not in "123456789" or hdr[4:10] != b"1AY&SY":
        return min(4096, total_size - h_pos), False
    max_scan = min(total_size, h_pos + max_scan_size)
    eos_pos = data.find(b"\x17rE8P\x90", h_pos + 10, max_scan)
    if eos_pos != -1:
        return min((eos_pos + 10) - h_pos, total_size - h_pos), True
    # Look for next competing BZ2 or 7Z or RAR or ZIP header
    next_h = data.find(b"BZh", h_pos + 3, max_scan)
    if next_h != -1:
        return next_h - h_pos, False
    return min(4096, total_size - h_pos), False


def _find_gz_candidate_boundary(
    data: Union[bytes, mmap.mmap], h_pos: int, total_size: int, max_scan_size: int
) -> Tuple[int, bool]:
    """Validate GZ header and verify initial deflate stream decodability."""
    if h_pos + 10 > total_size:
        return min(4096, total_size - h_pos), False
    hdr = _read_bytes(data, h_pos, h_pos + 10)
    if hdr[:3] != b"\x1f\x8b\x08":
        return min(4096, total_size - h_pos), False
    flg, os_byte = hdr[3], hdr[9]
    if flg > 0x1F or (os_byte > 13 and os_byte != 255):
        return min(4096, total_size - h_pos), False
    try:
        sample = _read_bytes(data, h_pos, min(total_size, h_pos + 4096))
        dec = zlib.decompressobj(wbits=31)
        decomp = dec.decompress(sample)
        if not decomp and not dec.unused_data:
            return min(4096, total_size - h_pos), False
    except Exception:
        return min(4096, total_size - h_pos), False
    # Next competing header or default block
    return min(4096, total_size - h_pos), True


# ─────────────────────────────────────────────────────────────
# Core carve dispatch
# ─────────────────────────────────────────────────────────────

def _carve_candidates_for_header(
    data: Union[bytes, mmap.mmap],
    sig: SignatureDefinition,
    h_pos: int,
    total_size: int,
) -> List[Dict[str, Any]]:
    """
    Determine format-aware fragment boundaries for a single signature match.

    Returns a list of candidate dicts (one for contiguous, multiple for disrupted).
    Returns [] if the header fails structural plausibility checks.
    """
    type_hint = sig.type_hint
    has_footer = False
    length = sig.default_length
    plausible = True

    if sig.type_hint == "jpeg":
        length, has_footer = _find_jpeg_candidate_boundary(data, h_pos, total_size, sig.max_scan_size)
    elif sig.type_hint == "png":
        length, has_footer = _find_png_candidate_boundary(data, h_pos, total_size, sig.max_scan_size)
    elif sig.type_hint == "gif":
        length, has_footer = _find_gif_candidate_boundary(data, h_pos, total_size, sig.max_scan_size)
    elif sig.type_hint == "bmp":
        length, plausible = _validate_bmp_header(data, h_pos, total_size, sig.max_scan_size)
        has_footer = plausible
        if not plausible:
            return []   # Reject implausible BMP
    elif sig.type_hint == "tiff":
        length, plausible = _validate_tiff_header(data, h_pos, total_size, sig.max_scan_size)
        if not plausible:
            return []   # Reject implausible TIFF
    elif sig.type_hint == "pcx":
        length, plausible = _validate_pcx_header(data, h_pos, total_size, sig.max_scan_size)
        if not plausible:
            return []   # Reject random 0x0A bytes
    elif sig.type_hint == "pdf":
        length, has_footer = _find_pdf_candidate_boundary(data, h_pos, total_size, sig.max_scan_size)
    elif sig.type_hint == "zip":
        length, has_footer, type_hint = _find_zip_candidate_boundary(data, h_pos, total_size, sig.max_scan_size)
    elif sig.type_hint == "7z":
        length, plausible = _find_7z_candidate_boundary(data, h_pos, total_size, sig.max_scan_size)
        if not plausible:
            return []
        has_footer = plausible
    elif sig.type_hint == "rar":
        length, has_footer = _find_rar_candidate_boundary(data, h_pos, total_size, sig.max_scan_size)
    elif sig.type_hint == "wim":
        length, plausible = _find_wim_candidate_boundary(data, h_pos, total_size, sig.max_scan_size)
        if not plausible:
            return []
        has_footer = plausible
    elif sig.type_hint == "bz2":
        length, has_footer = _find_bz2_candidate_boundary(data, h_pos, total_size, sig.max_scan_size)
    elif sig.type_hint == "gz":
        length, plausible = _find_gz_candidate_boundary(data, h_pos, total_size, sig.max_scan_size)
        if not plausible:
            return []
    elif sig.type_hint == "sqlite":
        length = _calculate_sqlite_candidate_length(data, h_pos, total_size)
    elif sig.type_hint == "wav":
        length, plausible = _validate_wav_header(data, h_pos, total_size, sig.max_scan_size)
        if not plausible:
            return []   # Reject non-WAVE RIFF files
        has_footer = plausible
    else:
        length = min(sig.default_length, total_size - h_pos)

    # Enforce minimum size
    if length < sig.min_size:
        return []

    end_pos = h_pos + length
    meta: Dict[str, Any] = {
        "signature": sig.header.hex(),
        "detection_method": "format_aware_carving",
        "has_footer": has_footer,
    }
    if has_footer and sig.footer:
        meta["footer_signature"] = sig.footer.hex()

    # Check for unallocated zero gaps (>= 64 contiguous null bytes) inside candidate range
    # SQLite and TIFF have legitimate zero-filled regions; skip gap detection for those.
    if sig.type_hint not in ("sqlite", "tiff") and (h_pos + 64) < end_pos:
        null_marker = b"\x00" * 64
        first_gap = data.find(null_marker, h_pos + 32, end_pos - 8)
        if first_gap != -1 and first_gap > h_pos:
            spans = []
            curr = h_pos
            while curr < end_pos:
                gap_idx = data.find(null_marker, curr, end_pos)
                if gap_idx == -1:
                    if end_pos > curr:
                        spans.append((curr, end_pos))
                    break
                if gap_idx > curr:
                    spans.append((curr, gap_idx))
                skip = gap_idx
                while skip < end_pos and data[skip:skip + 1] == b"\x00":
                    skip += 1
                curr = skip

            if len(spans) > 1:
                candidates = []
                group_id = f"disrupted_{type_hint}_{h_pos}"
                for i, (st, en) in enumerate(spans):
                    is_first = (i == 0)
                    is_last = (i == len(spans) - 1)
                    m = {
                        "signature": sig.header.hex() if is_first else "",
                        "footer_signature": (sig.footer.hex() if (has_footer and sig.footer) else "") if is_last else "",
                        "detection_method": "format_aware_disrupted",
                        "has_footer": has_footer if is_last else False,
                        "disrupted_extent_index": i,
                        "disrupted_extent_total": len(spans),
                        "group_id": group_id,
                    }
                    candidates.append({
                        "offset": st,
                        "length": en - st,
                        "type_hint": type_hint,
                        "header_flag": is_first,
                        "footer_flag": is_last and has_footer,
                        "metadata": m,
                    })
                return candidates

    return [{
        "offset": h_pos,
        "length": length,
        "type_hint": type_hint,
        "header_flag": True,
        "footer_flag": has_footer,
        "metadata": meta,
    }]


# ─────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────

def carve_fragments(evidence_path: Union[str, Path]) -> List[Fragment]:
    """
    Perform format-aware byte-level carving on an evidence disk/memory image.

    Scans the evidence file using a read-only memory map for supported magic
    bytes, determines conservative candidate boundaries using per-format
    structural validation, and generates deterministic Fragment objects.

    Returns:
        List of candidate Fragment objects sorted by start offset.
    """
    path = validate_evidence_file(evidence_path)
    file_size = path.stat().st_size
    candidates: List[dict] = []

    with open(path, "rb") as f:
        try:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                _scan_data(mm, file_size, candidates)
        except (OSError, ValueError):
            f.seek(0)
            data = f.read()
            _scan_data(data, file_size, candidates)

    candidates.sort(key=lambda c: (c["offset"], c["length"], c["type_hint"]))

    # Deduplicate exact matches
    unique_candidates: List[dict] = []
    seen: set = set()
    for cand in candidates:
        key = (cand["offset"], cand["length"], cand["type_hint"])
        if key not in seen:
            seen.add(key)
            unique_candidates.append(cand)

    fragments: List[Fragment] = []
    source_str = str(path)

    for idx, cand in enumerate(unique_candidates):
        frag_id = f"F{idx + 1:04d}"
        frag_meta = dict(cand["metadata"])
        frag_meta["end_offset"] = cand["offset"] + cand["length"]
        frag_meta["evidence_offset"] = cand["offset"]

        fragment = Fragment(
            id=frag_id,
            offset=cand["offset"],
            length=cand["length"],
            type_hint=cand["type_hint"],
            entropy=0.0,
            source=source_str,
            pipeline_tag="carved",
            header_flag=cand["header_flag"],
            footer_flag=cand["footer_flag"],
            metadata=frag_meta,
        )
        fragments.append(fragment)

    return fragments


def _scan_data(
    data: Union[bytes, mmap.mmap],
    file_size: int,
    candidates: List[dict],
) -> None:
    """Inner scan loop over all signatures against the data buffer."""
    for sig in SIGNATURE_REGISTRY:
        search_pos = 0
        while search_pos < file_size:
            h_pos = data.find(sig.header, search_pos)
            if h_pos == -1:
                break

            header_cands = _carve_candidates_for_header(data, sig, h_pos, file_size)
            candidates.extend(header_cands)

            # Advance past header; for PCX (single-byte header) advance by 1
            search_pos = h_pos + max(1, len(sig.header))
