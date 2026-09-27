"""
Archive Format Adapter Layer for RECOV.

Provides deterministic structural inspection, parsing, validation,
and metadata extraction for archive families:
- ZIP (Container)
- TAR (Container)
- 7Z (Container)
- RAR (Container)
- WIM (Container)
- GZ (Compressed Stream)
- BZ2 (Compressed Stream)

Design principles:
- Deterministic, byte-level structural reasoning
- Independent of LLM or external forensic binaries
- Supports complete and partial/member-level recovery states
"""

import abc
import bz2
import gzip
import io
import math
import struct
import tarfile
import zipfile
import zlib
from typing import Any, Dict, List, Optional, Tuple, Union


class ArchiveRecoveryState:
    COMPLETE_ARCHIVE = "COMPLETE_ARCHIVE"
    PARTIAL_ARCHIVE = "PARTIAL_ARCHIVE"
    VALID_MEMBER_ONLY = "VALID_MEMBER_ONLY"
    STRUCTURALLY_VALID = "STRUCTURALLY_VALID"
    STRUCTURALLY_INVALID = "STRUCTURALLY_INVALID"
    PAYLOAD_VALID = "PAYLOAD_VALID"
    METADATA_ONLY = "METADATA_ONLY"


class ArchiveFormatAdapter(abc.ABC):
    """Abstract base class for deterministic archive format adapters."""

    @abc.abstractmethod
    def get_format_name(self) -> str:
        """Return standardized format name (e.g., 'zip', 'tar', '7z', 'rar', 'wim', 'gz', 'bz2')."""
        pass

    @abc.abstractmethod
    def is_container(self) -> bool:
        """Return True if format is a multi-file container, False if compressed stream."""
        pass

    @abc.abstractmethod
    def detect(self, data: bytes, offset: int = 0) -> bool:
        """Check if magic signature matches at given offset."""
        pass

    @abc.abstractmethod
    def inspect_structure(self, data: bytes, offset: int = 0) -> Dict[str, Any]:
        """Extract detailed structural metadata from header at offset."""
        pass

    @abc.abstractmethod
    def validate_candidate(self, candidate_bytes: bytes) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validate reconstructed candidate bytes using real format rules/parsers.
        Returns: (is_valid, message, metadata_dict)
        """
        pass

    @abc.abstractmethod
    def calculate_completeness(self, candidate_bytes: bytes, metadata: Optional[Dict[str, Any]] = None) -> float:
        """Calculate ratio of recovered bytes / declared logical container size."""
        pass


# ─────────────────────────────────────────────────────────────
# ZIP Adapter
# ─────────────────────────────────────────────────────────────

class ZipArchiveAdapter(ArchiveFormatAdapter):
    """Deterministic adapter for ZIP container format."""

    def get_format_name(self) -> str:
        return "zip"

    def is_container(self) -> bool:
        return True

    def detect(self, data: bytes, offset: int = 0) -> bool:
        if len(data) < offset + 4:
            return False
        return data[offset:offset+4] == b"PK\x03\x04"

    def inspect_structure(self, data: bytes, offset: int = 0) -> Dict[str, Any]:
        meta: Dict[str, Any] = {
            "format": "zip",
            "offset": offset,
            "has_local_header": False,
            "has_eocd": False,
            "members": [],
            "declared_compressed_size": 0,
            "declared_uncompressed_size": 0,
        }
        if len(data) < offset + 30 or data[offset:offset+4] != b"PK\x03\x04":
            return meta

        meta["has_local_header"] = True
        try:
            (
                sig, ver, flags, comp, mod_t, mod_d,
                crc, comp_s, uncomp_s, fn_len, ef_len
            ) = struct.unpack("<4sHHHHHIIIHH", data[offset:offset+30])

            fn = data[offset+30:offset+30+fn_len].decode("utf-8", errors="replace")
            meta["members"].append({
                "filename": fn,
                "compression_method": comp,
                "crc32": crc,
                "compressed_size": comp_s,
                "uncompressed_size": uncomp_s,
                "flags": flags,
                "header_size": 30 + fn_len + ef_len,
            })
            meta["declared_compressed_size"] = comp_s
            meta["declared_uncompressed_size"] = uncomp_s
            meta["expected_span"] = 30 + fn_len + ef_len + comp_s

            # Look for EOCD
            eocd_pos = data.find(b"PK\x05\x06", offset)
            if eocd_pos != -1 and eocd_pos + 22 <= len(data):
                meta["has_eocd"] = True
                meta["eocd_offset"] = eocd_pos
                disk_entries, total_entries, cd_size, cd_offset = struct.unpack(
                    "<HHHH", data[eocd_pos+8:eocd_pos+16]
                )
                meta["total_entries"] = total_entries
                meta["cd_size"] = cd_size
                meta["cd_offset"] = cd_offset
        except Exception as e:
            meta["error"] = str(e)

        return meta

    def validate_candidate(self, candidate_bytes: bytes) -> Tuple[bool, str, Dict[str, Any]]:
        if not candidate_bytes or not candidate_bytes.startswith(b"PK\x03\x04"):
            return False, "Missing ZIP local file header (PK\x03\x04)", {"state": ArchiveRecoveryState.STRUCTURALLY_INVALID}

        # Attempt 1: Standard zipfile verification
        try:
            with zipfile.ZipFile(io.BytesIO(candidate_bytes)) as zf:
                bad_crc = zf.testzip()
                if bad_crc is not None:
                    return False, f"ZIP member CRC-32 check failed on: {bad_crc}", {
                        "state": ArchiveRecoveryState.STRUCTURALLY_INVALID,
                        "failed_member": bad_crc,
                    }
                members = zf.namelist()
                infolist = zf.infolist()
                total_uncomp = sum(i.file_size for i in infolist)
                return True, f"Valid complete ZIP archive ({len(members)} member(s): {', '.join(members[:3])})", {
                    "state": ArchiveRecoveryState.COMPLETE_ARCHIVE,
                    "members": members,
                    "member_count": len(members),
                    "uncompressed_bytes": total_uncomp,
                }
        except Exception:
            pass

        # Attempt 2: Partial recovery via surviving Local File Headers
        surviving_members = []
        pos = 0
        while pos + 30 <= len(candidate_bytes):
            if candidate_bytes[pos:pos+4] == b"PK\x03\x04":
                try:
                    (
                        sig, ver, flags, comp, mod_t, mod_d,
                        crc, comp_s, uncomp_s, fn_len, ef_len
                    ) = struct.unpack("<4sHHHHHIIIHH", candidate_bytes[pos:pos+30])
                    fn = candidate_bytes[pos+30:pos+30+fn_len].decode("utf-8", errors="replace")
                    payload_start = pos + 30 + fn_len + ef_len
                    payload_end = payload_start + comp_s
                    if payload_end <= len(candidate_bytes):
                        payload_data = candidate_bytes[payload_start:payload_end]
                        # Verify member decompression and CRC
                        decompressed = None
                        if comp == 0:  # Stored
                            decompressed = payload_data
                        elif comp == 8:  # Deflate
                            try:
                                decompressed = zlib.decompress(payload_data, -15)
                            except Exception:
                                decompressed = None

                        if decompressed is not None and zlib.crc32(decompressed) == crc:
                            surviving_members.append({
                                "filename": fn,
                                "uncompressed_size": uncomp_s,
                                "decompressed_bytes": len(decompressed),
                                "crc_verified": True,
                            })
                    pos = max(pos + 4, payload_end)
                    continue
                except Exception:
                    pass
            pos += 1

        if surviving_members:
            return True, f"Valid partial ZIP archive ({len(surviving_members)} validated member(s))", {
                "state": ArchiveRecoveryState.VALID_MEMBER_ONLY if len(surviving_members) == 1 else ArchiveRecoveryState.PARTIAL_ARCHIVE,
                "surviving_members": surviving_members,
                "member_count": len(surviving_members),
            }

        return False, "ZIP validation failed: damaged central directory and no valid uncorrupted members recovered", {
            "state": ArchiveRecoveryState.STRUCTURALLY_INVALID
        }

    def calculate_completeness(self, candidate_bytes: bytes, metadata: Optional[Dict[str, Any]] = None) -> float:
        if not candidate_bytes:
            return 0.0
        meta = metadata or self.inspect_structure(candidate_bytes)
        expected_span = meta.get("expected_span", 0)
        if expected_span > 0:
            return min(1.0, round(len(candidate_bytes) / expected_span, 4))
        return 1.0 if len(candidate_bytes) >= 30 else 0.0


# ─────────────────────────────────────────────────────────────
# TAR Adapter
# ─────────────────────────────────────────────────────────────

class TarArchiveAdapter(ArchiveFormatAdapter):
    """Deterministic adapter for POSIX/GNU TAR 512-byte block format."""

    def get_format_name(self) -> str:
        return "tar"

    def is_container(self) -> bool:
        return True

    def detect(self, data: bytes, offset: int = 0) -> bool:
        if len(data) < offset + 512:
            return False
        block = data[offset:offset+512]
        # Check ustar magic at offset 257 (posix: b"ustar\x0000", gnu: b"ustar  \x00")
        if b"ustar" in block[257:265]:
            return True
        # Check checksum validity for non-empty block
        if any(block):
            return self._verify_tar_checksum(block)
        return False

    def _verify_tar_checksum(self, block: bytes) -> bool:
        if len(block) < 512:
            return False
        chk_bytes = block[148:156]
        try:
            chk_str = chk_bytes.rstrip(b"\x00 ").decode("ascii", errors="ignore")
            if not chk_str:
                return False
            expected_chk = int(chk_str, 8)
        except Exception:
            return False

        # Checksum is computed with bytes 148..156 replaced with 8 spaces (0x20)
        modified = bytearray(block)
        modified[148:156] = b" " * 8
        calc_unsigned = sum(modified)
        calc_signed = sum(struct.unpack("512b", modified))
        return expected_chk in (calc_unsigned, calc_signed)

    def inspect_structure(self, data: bytes, offset: int = 0) -> Dict[str, Any]:
        meta: Dict[str, Any] = {
            "format": "tar",
            "offset": offset,
            "members": [],
            "total_size": 0,
        }
        pos = offset
        while pos + 512 <= len(data):
            block = data[pos:pos+512]
            if not any(block):
                # Double zero block is TAR EOF
                next_block = data[pos+512:pos+1024] if pos + 1024 <= len(data) else b""
                if not any(next_block):
                    meta["has_eof"] = True
                    meta["eof_offset"] = pos
                break

            if not self._verify_tar_checksum(block):
                break

            name = block[:100].rstrip(b"\x00").decode("utf-8", errors="replace")
            size_str = block[124:136].rstrip(b"\x00 ").decode("ascii", errors="ignore")
            try:
                member_size = int(size_str, 8) if size_str else 0
            except Exception:
                member_size = 0

            typeflag = chr(block[156]) if block[156] else "0"
            payload_blocks = math.ceil(member_size / 512)
            meta["members"].append({
                "filename": name,
                "size": member_size,
                "typeflag": typeflag,
                "header_offset": pos,
            })
            pos += 512 + (payload_blocks * 512)

        meta["total_size"] = pos - offset
        return meta

    def validate_candidate(self, candidate_bytes: bytes) -> Tuple[bool, str, Dict[str, Any]]:
        if not candidate_bytes or len(candidate_bytes) < 512:
            return False, "Candidate too small for TAR 512-byte block", {"state": ArchiveRecoveryState.STRUCTURALLY_INVALID}

        # Phase 1: Python standard tarfile
        try:
            with tarfile.open(fileobj=io.BytesIO(candidate_bytes), mode="r:*") as tf:
                members = tf.getmembers()
                if members:
                    names = [m.name for m in members]
                    return True, f"Valid TAR archive ({len(members)} member(s): {', '.join(names[:3])})", {
                        "state": ArchiveRecoveryState.COMPLETE_ARCHIVE,
                        "members": names,
                        "member_count": len(members),
                    }
        except Exception:
            pass

        # Phase 2: Structural block-level check
        meta = self.inspect_structure(candidate_bytes)
        if meta.get("members"):
            names = [m["filename"] for m in meta["members"]]
            return True, f"Structurally valid TAR archive ({len(names)} member(s): {', '.join(names[:3])})", {
                "state": ArchiveRecoveryState.PARTIAL_ARCHIVE if not meta.get("has_eof") else ArchiveRecoveryState.COMPLETE_ARCHIVE,
                "members": names,
                "member_count": len(names),
            }

        return False, "TAR validation failed: no valid 512-byte block headers with verified checksums", {
            "state": ArchiveRecoveryState.STRUCTURALLY_INVALID
        }

    def calculate_completeness(self, candidate_bytes: bytes, metadata: Optional[Dict[str, Any]] = None) -> float:
        if not candidate_bytes:
            return 0.0
        meta = metadata or self.inspect_structure(candidate_bytes)
        tot = meta.get("total_size", len(candidate_bytes))
        return 1.0 if len(candidate_bytes) >= tot else round(len(candidate_bytes) / max(1, tot), 4)


# ─────────────────────────────────────────────────────────────
# 7Z Adapter
# ─────────────────────────────────────────────────────────────

class SevenZipArchiveAdapter(ArchiveFormatAdapter):
    """Deterministic adapter for 7-Zip container format."""

    def get_format_name(self) -> str:
        return "7z"

    def is_container(self) -> bool:
        return True

    def detect(self, data: bytes, offset: int = 0) -> bool:
        if len(data) < offset + 6:
            return False
        return data[offset:offset+6] == b"7z\xbc\xaf\x27\x1c"

    def inspect_structure(self, data: bytes, offset: int = 0) -> Dict[str, Any]:
        meta: Dict[str, Any] = {
            "format": "7z",
            "offset": offset,
            "has_valid_signature_header": False,
            "next_header_offset": 0,
            "next_header_size": 0,
            "declared_file_size": 0,
            "end_header_crc_valid": False,
        }
        if len(data) < offset + 32 or data[offset:offset+6] != b"7z\xbc\xaf\x27\x1c":
            return meta

        ver_maj, ver_min = data[offset+6], data[offset+7]
        start_crc = struct.unpack("<I", data[offset+8:offset+12])[0]
        next_off, next_size, next_crc = struct.unpack("<QQI", data[offset+12:offset+32])

        calc_start_crc = zlib.crc32(data[offset+12:offset+32])
        if calc_start_crc != start_crc:
            meta["error"] = "StartHeaderCRC mismatch"
            return meta

        meta["has_valid_signature_header"] = True
        meta["version"] = f"{ver_maj}.{ver_min}"
        meta["next_header_offset"] = next_off
        meta["next_header_size"] = next_size
        meta["next_header_crc"] = next_crc
        meta["declared_file_size"] = 32 + next_off + next_size

        end_hdr_start = offset + 32 + next_off
        end_hdr_end = end_hdr_start + next_size
        if end_hdr_end <= len(data) and next_size > 0:
            calc_end_crc = zlib.crc32(data[end_hdr_start:end_hdr_end])
            meta["end_header_crc_valid"] = (calc_end_crc == next_crc)

        return meta

    def validate_candidate(self, candidate_bytes: bytes) -> Tuple[bool, str, Dict[str, Any]]:
        if not candidate_bytes or len(candidate_bytes) < 32:
            return False, "Candidate too small for 7Z 32-byte signature header", {"state": ArchiveRecoveryState.STRUCTURALLY_INVALID}
        if candidate_bytes[:6] != b"7z\xbc\xaf\x27\x1c":
            return False, "Missing 7Z signature (7z\\xBC\\xAF\\x27\\x1C)", {"state": ArchiveRecoveryState.STRUCTURALLY_INVALID}

        meta = self.inspect_structure(candidate_bytes)
        if not meta.get("has_valid_signature_header"):
            return False, f"7Z StartHeader CRC validation failed: {meta.get('error', 'invalid')}", {
                "state": ArchiveRecoveryState.STRUCTURALLY_INVALID
            }

        declared_size = meta["declared_file_size"]
        if meta.get("end_header_crc_valid"):
            return True, f"Valid complete 7Z archive (v{meta.get('version', '0.3')}, size: {declared_size} bytes, EndHeader CRC verified)", {
                "state": ArchiveRecoveryState.COMPLETE_ARCHIVE,
                "declared_size": declared_size,
                "version": meta.get("version"),
            }

        if len(candidate_bytes) >= declared_size:
            return False, "7Z EndHeader CRC-32 mismatch at declared offset", {"state": ArchiveRecoveryState.STRUCTURALLY_INVALID}

        # Partial 7Z
        ratio = round(len(candidate_bytes) / max(1, declared_size), 4)
        return True, f"Partial 7Z archive ({len(candidate_bytes)}/{declared_size} bytes, {ratio*100:.1f}%)", {
            "state": ArchiveRecoveryState.PARTIAL_ARCHIVE,
            "declared_size": declared_size,
            "recovered_bytes": len(candidate_bytes),
        }

    def calculate_completeness(self, candidate_bytes: bytes, metadata: Optional[Dict[str, Any]] = None) -> float:
        if not candidate_bytes:
            return 0.0
        meta = metadata or self.inspect_structure(candidate_bytes)
        decl = meta.get("declared_file_size", 0)
        if decl > 0:
            return min(1.0, round(len(candidate_bytes) / decl, 4))
        return 1.0 if len(candidate_bytes) >= 32 else 0.0


# ─────────────────────────────────────────────────────────────
# RAR Adapter
# ─────────────────────────────────────────────────────────────

class RarArchiveAdapter(ArchiveFormatAdapter):
    """Deterministic adapter for RAR v4 (v2.9+) and RAR v5 container format."""

    def get_format_name(self) -> str:
        return "rar"

    def is_container(self) -> bool:
        return True

    def detect(self, data: bytes, offset: int = 0) -> bool:
        if len(data) >= offset + 7 and data[offset:offset+7] == b"Rar!\x1a\x07\x00":
            return True
        if len(data) >= offset + 8 and data[offset:offset+8] == b"Rar!\x1a\x07\x01\x00":
            return True
        return False

    def inspect_structure(self, data: bytes, offset: int = 0) -> Dict[str, Any]:
        meta: Dict[str, Any] = {
            "format": "rar",
            "offset": offset,
            "version": 4 if data[offset:offset+7] == b"Rar!\x1a\x07\x00" else 5,
            "blocks": [],
            "members": [],
            "has_main_header": False,
            "has_endarc": False,
            "total_span": 0,
        }
        sig_len = 7 if meta["version"] == 4 else 8
        pos = offset + sig_len
        while pos + 7 <= len(data):
            crc, h_type, flags, h_size = struct.unpack("<HBHH", data[pos:pos+7])
            if h_size == 0 or pos + h_size > len(data):
                break
            add_size = 0
            if flags & 0x8000 and len(data) >= pos + 11:
                add_size = struct.unpack("<I", data[pos+7:pos+11])[0]

            block_info = {
                "type": h_type,
                "size": h_size,
                "add_size": add_size,
                "total_block_size": h_size + add_size,
                "offset": pos,
            }
            meta["blocks"].append(block_info)

            if h_type == 0x73:  # MAIN_HEAD
                meta["has_main_header"] = True
            elif h_type == 0x74:  # FILE_HEAD
                if len(data) >= pos + 32:
                    unp_size = struct.unpack("<I", data[pos+11:pos+15])[0]
                    file_crc = struct.unpack("<I", data[pos+19:pos+23])[0]
                    name_size = struct.unpack("<H", data[pos+26:pos+28])[0]
                    fname = data[pos+32:pos+32+name_size].decode("latin-1", errors="replace")
                    meta["members"].append({
                        "filename": fname,
                        "uncompressed_size": unp_size,
                        "packed_size": add_size,
                        "crc32": file_crc,
                    })
            elif h_type == 0x7B:  # ENDARC
                meta["has_endarc"] = True
                pos += h_size + add_size
                break

            pos += h_size + add_size
            if pos - offset > 50 * 1024 * 1024:
                break

        meta["total_span"] = pos - offset
        return meta

    def validate_candidate(self, candidate_bytes: bytes) -> Tuple[bool, str, Dict[str, Any]]:
        if not candidate_bytes or len(candidate_bytes) < 7:
            return False, "Candidate too small for RAR signature", {"state": ArchiveRecoveryState.STRUCTURALLY_INVALID}
        if not self.detect(candidate_bytes, 0):
            return False, "Missing RAR signature", {"state": ArchiveRecoveryState.STRUCTURALLY_INVALID}

        meta = self.inspect_structure(candidate_bytes)
        if not meta.get("has_main_header"):
            return False, "RAR missing valid MAIN_HEAD (0x73) record", {"state": ArchiveRecoveryState.STRUCTURALLY_INVALID}

        members = meta.get("members", [])
        if meta.get("has_endarc") and members:
            names = [m["filename"] for m in members]
            return True, f"Valid complete RAR archive (v{meta['version']}, {len(members)} member(s): {', '.join(names[:3])})", {
                "state": ArchiveRecoveryState.COMPLETE_ARCHIVE,
                "version": meta["version"],
                "members": names,
                "member_count": len(members),
            }

        if members:
            names = [m["filename"] for m in members]
            return True, f"Valid partial RAR archive ({len(members)} member record(s): {', '.join(names[:3])})", {
                "state": ArchiveRecoveryState.PARTIAL_ARCHIVE,
                "version": meta["version"],
                "members": names,
                "member_count": len(members),
            }

        return True, "Structurally valid RAR archive header container", {
            "state": ArchiveRecoveryState.METADATA_ONLY,
            "version": meta["version"],
        }

    def calculate_completeness(self, candidate_bytes: bytes, metadata: Optional[Dict[str, Any]] = None) -> float:
        if not candidate_bytes:
            return 0.0
        meta = metadata or self.inspect_structure(candidate_bytes)
        tot = meta.get("total_span", len(candidate_bytes))
        return 1.0 if len(candidate_bytes) >= tot else round(len(candidate_bytes) / max(1, tot), 4)


# ─────────────────────────────────────────────────────────────
# WIM Adapter
# ─────────────────────────────────────────────────────────────

class WimArchiveAdapter(ArchiveFormatAdapter):
    """Deterministic adapter for Microsoft Windows Imaging Format (WIM)."""

    def get_format_name(self) -> str:
        return "wim"

    def is_container(self) -> bool:
        return True

    def detect(self, data: bytes, offset: int = 0) -> bool:
        if len(data) < offset + 8:
            return False
        return data[offset:offset+8] == b"MSWIM\x00\x00\x00"

    def inspect_structure(self, data: bytes, offset: int = 0) -> Dict[str, Any]:
        meta: Dict[str, Any] = {
            "format": "wim",
            "offset": offset,
            "has_valid_header": False,
        }
        if len(data) < offset + 208 or data[offset:offset+8] != b"MSWIM\x00\x00\x00":
            return meta

        try:
            sig, hdr_size, ver, flags, chunk_size = struct.unpack("<8sIIII", data[offset:offset+24])
            guid = data[offset+24:offset+40].hex()
            part_num, total_parts, img_count = struct.unpack("<HHH", data[offset+40:offset+46])

            if hdr_size == 208 and ver == 0x00010D00:
                meta["has_valid_header"] = True
                meta["version"] = f"0x{ver:08X}"
                meta["flags"] = flags
                meta["chunk_size"] = chunk_size
                meta["guid"] = guid
                meta["part_number"] = part_num
                meta["total_parts"] = total_parts
                meta["image_count"] = img_count
        except Exception as e:
            meta["error"] = str(e)

        return meta

    def validate_candidate(self, candidate_bytes: bytes) -> Tuple[bool, str, Dict[str, Any]]:
        if not candidate_bytes or len(candidate_bytes) < 208:
            return False, "Candidate too small for WIM 208-byte header", {"state": ArchiveRecoveryState.STRUCTURALLY_INVALID}
        if candidate_bytes[:8] != b"MSWIM\x00\x00\x00":
            return False, "Missing MSWIM signature", {"state": ArchiveRecoveryState.STRUCTURALLY_INVALID}

        meta = self.inspect_structure(candidate_bytes)
        if not meta.get("has_valid_header"):
            return False, "WIM header fields invalid (header size != 208 or version mismatch)", {
                "state": ArchiveRecoveryState.STRUCTURALLY_INVALID
            }

        return True, f"Structurally valid WIM archive header (GUID: {meta.get('guid', '')[:8]}..., parts: {meta.get('part_number', 1)}/{meta.get('total_parts', 1)}, images: {meta.get('image_count', 1)})", {
            "state": ArchiveRecoveryState.STRUCTURALLY_VALID,
            "guid": meta.get("guid"),
            "image_count": meta.get("image_count"),
        }

    def calculate_completeness(self, candidate_bytes: bytes, metadata: Optional[Dict[str, Any]] = None) -> float:
        if not candidate_bytes:
            return 0.0
        return 1.0 if len(candidate_bytes) >= 208 else round(len(candidate_bytes) / 208.0, 4)


# ─────────────────────────────────────────────────────────────
# GZ Adapter (Compressed Stream)
# ─────────────────────────────────────────────────────────────

class GzArchiveAdapter(ArchiveFormatAdapter):
    """Deterministic adapter for GZIP compressed stream."""

    def get_format_name(self) -> str:
        return "gz"

    def is_container(self) -> bool:
        return False

    def detect(self, data: bytes, offset: int = 0) -> bool:
        if len(data) < offset + 2:
            return False
        return data[offset:offset+2] == b"\x1f\x8b"

    def inspect_structure(self, data: bytes, offset: int = 0) -> Dict[str, Any]:
        meta: Dict[str, Any] = {
            "format": "gz",
            "offset": offset,
            "has_valid_header": False,
        }
        if len(data) < offset + 10 or data[offset:offset+2] != b"\x1f\x8b":
            return meta

        cm, flg = data[offset+2], data[offset+3]
        if cm == 8:  # Deflate
            meta["has_valid_header"] = True
            meta["compression_method"] = "deflate"
            meta["flags"] = flg

        return meta

    def validate_candidate(self, candidate_bytes: bytes) -> Tuple[bool, str, Dict[str, Any]]:
        if not candidate_bytes or len(candidate_bytes) < 10:
            return False, "Candidate too small for GZIP header", {"state": ArchiveRecoveryState.STRUCTURALLY_INVALID}
        if candidate_bytes[:2] != b"\x1f\x8b":
            return False, "Missing GZIP magic (0x1F8B)", {"state": ArchiveRecoveryState.STRUCTURALLY_INVALID}

        # Attempt standard gzip decompression
        try:
            decomp = gzip.decompress(candidate_bytes)
            return True, f"Valid complete GZIP stream (decompressed: {len(decomp)} bytes)", {
                "state": ArchiveRecoveryState.COMPLETE_ARCHIVE,
                "decompressed_bytes": len(decomp),
            }
        except Exception as e:
            # Check for partial stream
            try:
                dec = zlib.decompressobj(wbits=31)
                part = dec.decompress(candidate_bytes)
                if len(part) > 0:
                    return True, f"Valid partial GZIP stream ({len(part)} uncompressed bytes recovered)", {
                        "state": ArchiveRecoveryState.PARTIAL_ARCHIVE,
                        "decompressed_bytes": len(part),
                    }
            except Exception:
                pass
            return False, f"GZIP stream decompression failed: {str(e)}", {"state": ArchiveRecoveryState.STRUCTURALLY_INVALID}

    def calculate_completeness(self, candidate_bytes: bytes, metadata: Optional[Dict[str, Any]] = None) -> float:
        if not candidate_bytes:
            return 0.0
        return 1.0 if len(candidate_bytes) >= 10 else 0.0


# ─────────────────────────────────────────────────────────────
# BZ2 Adapter (Compressed Stream)
# ─────────────────────────────────────────────────────────────

class Bz2ArchiveAdapter(ArchiveFormatAdapter):
    """Deterministic adapter for BZIP2 compressed stream."""

    def get_format_name(self) -> str:
        return "bz2"

    def is_container(self) -> bool:
        return False

    def detect(self, data: bytes, offset: int = 0) -> bool:
        if len(data) < offset + 10:
            return False
        return data[offset:offset+3] == b"BZh" and data[offset+4:offset+10] == b"1AY&SY"

    def inspect_structure(self, data: bytes, offset: int = 0) -> Dict[str, Any]:
        meta: Dict[str, Any] = {
            "format": "bz2",
            "offset": offset,
            "has_valid_header": False,
        }
        if len(data) < offset + 10 or data[offset:offset+3] != b"BZh":
            return meta

        level = chr(data[offset+3])
        if level in "123456789" and data[offset+4:offset+10] == b"1AY&SY":
            meta["has_valid_header"] = True
            meta["block_size_level"] = int(level)

        return meta

    def validate_candidate(self, candidate_bytes: bytes) -> Tuple[bool, str, Dict[str, Any]]:
        if not candidate_bytes or len(candidate_bytes) < 10:
            return False, "Candidate too small for BZ2 header", {"state": ArchiveRecoveryState.STRUCTURALLY_INVALID}
        if candidate_bytes[:3] != b"BZh":
            return False, "Missing BZ2 signature (BZh)", {"state": ArchiveRecoveryState.STRUCTURALLY_INVALID}

        # Attempt full decompression
        try:
            decomp = bz2.decompress(candidate_bytes)
            return True, f"Valid complete BZ2 stream (decompressed: {len(decomp)} bytes)", {
                "state": ArchiveRecoveryState.COMPLETE_ARCHIVE,
                "decompressed_bytes": len(decomp),
            }
        except Exception:
            # Attempt incremental / partial stream decompression
            try:
                dec = bz2.BZ2Decompressor()
                out = dec.decompress(candidate_bytes)
                if len(out) > 0:
                    return True, f"Valid partial BZ2 stream ({len(out)} uncompressed bytes recovered)", {
                        "state": ArchiveRecoveryState.PARTIAL_ARCHIVE,
                        "decompressed_bytes": len(out),
                    }
            except Exception as e:
                return False, f"BZ2 decompression failed: {str(e)}", {"state": ArchiveRecoveryState.STRUCTURALLY_INVALID}

        return False, "BZ2 stream decompression failed", {"state": ArchiveRecoveryState.STRUCTURALLY_INVALID}

    def calculate_completeness(self, candidate_bytes: bytes, metadata: Optional[Dict[str, Any]] = None) -> float:
        if not candidate_bytes:
            return 0.0
        return 1.0 if len(candidate_bytes) >= 10 else 0.0


# ─────────────────────────────────────────────────────────────
# Adapter Registry & Dispatcher
# ─────────────────────────────────────────────────────────────

ARCHIVE_ADAPTERS: Dict[str, ArchiveFormatAdapter] = {
    "zip": ZipArchiveAdapter(),
    "tar": TarArchiveAdapter(),
    "7z": SevenZipArchiveAdapter(),
    "rar": RarArchiveAdapter(),
    "wim": WimArchiveAdapter(),
    "gz": GzArchiveAdapter(),
    "bz2": Bz2ArchiveAdapter(),
}


def get_archive_adapter(format_name: str) -> Optional[ArchiveFormatAdapter]:
    """Retrieve adapter by format name."""
    fmt = (format_name or "").lower().strip().lstrip(".")
    return ARCHIVE_ADAPTERS.get(fmt)


def detect_archive_format(data: bytes, offset: int = 0) -> Optional[str]:
    """Detect archive format at given offset across all registered adapters."""
    for name, adapter in ARCHIVE_ADAPTERS.items():
        if adapter.detect(data, offset):
            return name
    return None
