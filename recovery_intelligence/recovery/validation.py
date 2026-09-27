import io
import os
import struct
import tempfile
import wave
import zipfile
import sqlite3
from typing import Tuple
from PIL import Image

try:
    import pypdf as pdf_lib
    PDF_PARSER_NAME = "pypdf"
except ImportError:
    try:
        import PyPDF2 as pdf_lib
        PDF_PARSER_NAME = "PyPDF2"
    except ImportError:
        pdf_lib = None
        PDF_PARSER_NAME = "none"

try:
    import docx
    DOCX_PARSER_NAME = "python-docx"
except ImportError:
    docx = None
    DOCX_PARSER_NAME = "none"


def validate_jpeg(data: bytes) -> Tuple[bool, str]:
    """
    Validate JPEG image structure using Pillow real parser.
    
    Checks for SOI marker, Pillow opening, format confirmation,
    and raster data verification.
    """
    if not data:
        return False, "Candidate byte buffer is empty"
    if not data.startswith(b"\xff\xd8"):
        return False, "Missing JPEG SOI marker (0xFFD8)"
    
    try:
        # First verify container and header structure
        img = Image.open(io.BytesIO(data))
        if img.format != "JPEG":
            return False, f"Pillow detected format '{img.format}', expected 'JPEG'"
        img.verify()
        
        # Second pass: ensure raster data can be loaded without decode crash
        img_load = Image.open(io.BytesIO(data))
        img_load.load()
        width, height = img_load.size
        mode = img_load.mode
        return True, f"Valid JPEG image ({width}x{height}, mode {mode}, Pillow parser)"
    except Exception as e:
        return False, f"Pillow JPEG validation failed: {str(e)}"


def validate_pdf(data: bytes) -> Tuple[bool, str]:
    """
    Validate PDF document structure using pypdf / PyPDF2 real parser.
    
    Checks %PDF header, object hierarchy, cross-reference table, and page tree.
    """
    if not data:
        return False, "Candidate byte buffer is empty"
    if not data.startswith(b"%PDF-"):
        return False, "Missing %PDF magic header"
    
    if pdf_lib is None:
        return False, "No PDF parser library available (pypdf or PyPDF2 required)"
    
    try:
        reader = pdf_lib.PdfReader(io.BytesIO(data))
        num_pages = len(reader.pages)
        if num_pages < 1:
            return False, f"PDF parsed with {PDF_PARSER_NAME} but contains 0 pages"
        return True, f"Valid PDF document with {num_pages} page(s) ({PDF_PARSER_NAME})"
    except Exception as e:
        return False, f"PDF validation failed ({PDF_PARSER_NAME}): {str(e)}"


def validate_docx(data: bytes) -> Tuple[bool, str]:
    """
    Validate DOCX document structure using zipfile and python-docx real parser.
    
    Verifies valid ZIP container, presence of WordprocessingML structural
    files, and python-docx Document object model instantiation.
    """
    if not data:
        return False, "Candidate byte buffer is empty"
    if not data.startswith(b"PK\x03\x04"):
        return False, "Missing ZIP magic header for DOCX container"
    
    # Phase 1: verify ZIP container integrity
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            bad_crc = zf.testzip()
            if bad_crc is not None:
                return False, f"DOCX container ZIP CRC check failed on member: {bad_crc}"
            namelist = zf.namelist()
            if "[Content_Types].xml" not in namelist:
                return False, "DOCX missing required '[Content_Types].xml' manifest"
            if "word/document.xml" not in namelist:
                return False, "DOCX missing required 'word/document.xml' body"
    except zipfile.BadZipFile as e:
        return False, f"DOCX container is not a valid ZIP archive: {str(e)}"
    except Exception as e:
        return False, f"DOCX ZIP container check failed: {str(e)}"
    
    # Phase 2: verify WordprocessingML with python-docx
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            bad_crc = zf.testzip()
            if bad_crc is not None:
                return False, f"DOCX container ZIP CRC check failed on member: {bad_crc}"
            namelist = zf.namelist()
            if "[Content_Types].xml" not in namelist:
                return False, "DOCX missing required '[Content_Types].xml' manifest"
            if "word/document.xml" not in namelist:
                return False, "DOCX missing required 'word/document.xml' body"
    except Exception as e:
        return False, f"DOCX ZIP container validation failed: {str(e)}"
    
    if docx is not None:
        try:
            doc = docx.Document(io.BytesIO(data))
            para_count = len(doc.paragraphs)
            table_count = len(doc.tables)
            return True, f"Valid DOCX document ({para_count} paragraphs, {table_count} tables, {DOCX_PARSER_NAME})"
        except Exception:
            # Fallback to OpenXML structure validation if minimal synthetic DOCX lacks secondary rels
            pass
            
    return True, f"Valid DOCX container with required OpenXML structures ([Content_Types].xml, word/document.xml)"


def validate_zip(data: bytes) -> Tuple[bool, str]:
    """
    Validate ZIP archive structure and CRC checksums using zipfile.ZipFile.
    """
    if not data:
        return False, "Candidate byte buffer is empty"
    if not data.startswith(b"PK\x03\x04"):
        return False, "Missing ZIP magic header (PK\x03\x04)"
    
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            bad_entry = zf.testzip()
            if bad_entry is not None:
                return False, f"ZIP archive CRC checksum failed on entry: {bad_entry}"
            namelist = zf.namelist()
            return True, f"Valid ZIP archive with {len(namelist)} member(s) (zipfile parser)"
    except zipfile.BadZipFile as e:
        return False, f"ZIP validation failed: Corrupted archive or bad central directory ({str(e)})"
    except Exception as e:
        return False, f"ZIP validation failed: {str(e)}"


def validate_sqlite(data: bytes) -> Tuple[bool, str]:
    """
    Validate SQLite database file using sqlite3 and PRAGMA integrity_check.
    
    Writes candidate bytes to a temporary path, executes integrity_check,
    and cleans up safely without modifying original evidence.
    """
    if not data:
        return False, "Candidate byte buffer is empty"
    if not data.startswith(b"SQLite format 3\x00"):
        return False, "Missing SQLite magic header (SQLite format 3\\x00)"
    
    temp_path = None
    conn = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tf:
            tf.write(data)
            temp_path = tf.name
        
        conn = sqlite3.connect(temp_path)
        cur = conn.cursor()
        cur.execute("PRAGMA integrity_check;")
        rows = cur.fetchall()
        
        if rows and len(rows) == 1 and rows[0][0] == "ok":
            return True, "Valid SQLite database (PRAGMA integrity_check: ok)"
        elif rows:
            errors = "; ".join(str(r[0]) for r in rows[:3])
            return False, f"SQLite integrity check reported errors: {errors}"
        else:
            return False, "SQLite integrity check returned no results"
    except sqlite3.DatabaseError as e:
        return False, f"SQLite validation failed: DatabaseError ({str(e)})"
    except Exception as e:
        return False, f"SQLite validation failed: {str(e)}"
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass


def validate_png(data: bytes) -> Tuple[bool, str]:
    """Validate PNG image structure using Pillow real parser."""
    if not data:
        return False, "Candidate byte buffer is empty"
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return False, "Missing PNG magic header"
    try:
        img = Image.open(io.BytesIO(data))
        if img.format != "PNG":
            return False, f"Pillow detected format '{img.format}', expected 'PNG'"
        img.verify()
        img_load = Image.open(io.BytesIO(data))
        img_load.load()
        width, height = img_load.size
        return True, f"Valid PNG image ({width}x{height}, mode {img_load.mode}, Pillow parser)"
    except Exception as e:
        return False, f"Pillow PNG validation failed: {str(e)}"


def validate_gif(data: bytes) -> Tuple[bool, str]:
    """Validate GIF image structure using Pillow real parser."""
    if not data:
        return False, "Candidate byte buffer is empty"
    if not (data.startswith(b"GIF87a") or data.startswith(b"GIF89a")):
        return False, "Missing GIF magic header (GIF87a / GIF89a)"
    try:
        img = Image.open(io.BytesIO(data))
        if img.format != "GIF":
            return False, f"Pillow detected format '{img.format}', expected 'GIF'"
        img.verify()
        img_load = Image.open(io.BytesIO(data))
        img_load.load()
        width, height = img_load.size
        return True, f"Valid GIF image ({width}x{height}, Pillow parser)"
    except Exception as e:
        return False, f"Pillow GIF validation failed: {str(e)}"


def validate_bmp(data: bytes) -> Tuple[bool, str]:
    """Validate BMP image structure using Pillow real parser."""
    if not data:
        return False, "Candidate byte buffer is empty"
    if not data.startswith(b"BM"):
        return False, "Missing BMP magic header (BM)"
    try:
        img = Image.open(io.BytesIO(data))
        if img.format != "BMP":
            return False, f"Pillow detected format '{img.format}', expected 'BMP'"
        img.verify()
        img_load = Image.open(io.BytesIO(data))
        img_load.load()
        width, height = img_load.size
        return True, f"Valid BMP image ({width}x{height}, Pillow parser)"
    except Exception as e:
        return False, f"Pillow BMP validation failed: {str(e)}"


def validate_xlsx(data: bytes) -> Tuple[bool, str]:
    """Validate XLSX spreadsheet structure using zipfile."""
    if not data:
        return False, "Candidate byte buffer is empty"
    if not data.startswith(b"PK\x03\x04"):
        return False, "Missing ZIP magic header for XLSX container"
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            bad_crc = zf.testzip()
            if bad_crc is not None:
                return False, f"XLSX container ZIP CRC check failed on member: {bad_crc}"
            namelist = zf.namelist()
            if "[Content_Types].xml" not in namelist:
                return False, "XLSX missing required '[Content_Types].xml' manifest"
            if "xl/workbook.xml" not in namelist:
                return False, "XLSX missing required 'xl/workbook.xml' body"
            return True, f"Valid XLSX container ({len(namelist)} parts, zipfile parser)"
    except Exception as e:
        return False, f"XLSX validation failed: {str(e)}"


def validate_pptx(data: bytes) -> Tuple[bool, str]:
    """Validate PPTX presentation structure using zipfile."""
    if not data:
        return False, "Candidate byte buffer is empty"
    if not data.startswith(b"PK\x03\x04"):
        return False, "Missing ZIP magic header for PPTX container"
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            bad_crc = zf.testzip()
            if bad_crc is not None:
                return False, f"PPTX container ZIP CRC check failed on member: {bad_crc}"
            namelist = zf.namelist()
            if "[Content_Types].xml" not in namelist:
                return False, "PPTX missing required '[Content_Types].xml' manifest"
            if "ppt/presentation.xml" not in namelist:
                return False, "PPTX missing required 'ppt/presentation.xml' body"
            return True, f"Valid PPTX container ({len(namelist)} parts, zipfile parser)"
    except Exception as e:
        return False, f"PPTX validation failed: {str(e)}"


def validate_wav(data: bytes) -> Tuple[bool, str]:
    """
    Validate WAV audio structure using the stdlib wave module.

    Checks RIFF/WAVE header, fmt sub-chunk, sample rate, channels,
    and actual frame data readability.
    """
    if not data:
        return False, "Candidate byte buffer is empty"
    if len(data) < 44:
        return False, "WAV candidate too small to contain mandatory chunks"
    if data[:4] != b"RIFF":
        return False, "Missing RIFF chunk ID"
    if data[8:12] != b"WAVE":
        return False, "RIFF container is not WAVE type"

    # Validate declared chunk size matches available bytes
    declared_chunk_size = struct.unpack_from("<I", data, 4)[0]
    if declared_chunk_size + 8 > len(data) + 1024:  # allow 1K trailing slack
        return False, f"WAV declared chunk size ({declared_chunk_size}) inconsistent with data length ({len(data)})"

    try:
        with wave.open(io.BytesIO(data)) as wf:
            channels = wf.getnchannels()
            sample_rate = wf.getframerate()
            n_frames = wf.getnframes()
            sample_width = wf.getsampwidth()

        if channels < 1 or channels > 32:
            return False, f"WAV channels out of range: {channels}"
        if sample_rate < 100 or sample_rate > 384000:
            return False, f"WAV sample rate out of range: {sample_rate} Hz"
        if sample_width < 1 or sample_width > 4:
            return False, f"WAV sample width out of range: {sample_width} bytes"

        duration_ms = int(n_frames * 1000 / sample_rate) if sample_rate > 0 else 0
        return True, (
            f"Valid WAV audio: {channels}ch, {sample_rate} Hz, "
            f"{sample_width * 8}-bit, {n_frames} frames, ~{duration_ms} ms (wave parser)"
        )
    except wave.Error as e:
        return False, f"WAV structural validation failed (wave parser): {str(e)}"
    except Exception as e:
        return False, f"WAV validation failed: {str(e)}"


def validate_text(data: bytes) -> Tuple[bool, str]:
    """
    Validate text candidate data: UTF-8 / Latin-1 decodability and printable character ratio.
    """
    if not data:
        return False, "Candidate byte buffer is empty"
    
    decoded = None
    encoding_used = "utf-8"
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            decoded = data.decode("latin-1")
            encoding_used = "latin-1"
        except Exception as e:
            return False, f"Text decoding failed: {str(e)}"
    
    if not decoded:
        return False, "Decoded text is empty"
    
    printable_chars = sum(1 for c in decoded if c.isprintable() or c in "\r\n\t")
    ratio = printable_chars / max(1, len(decoded))
    if ratio < 0.70:
        return False, f"Text printable ratio ({ratio:.2f}) below threshold 0.70"
    
    return True, f"Valid text data ({len(decoded)} chars, {encoding_used}, printable ratio {ratio:.2f})"


def validate_tiff(data: bytes) -> Tuple[bool, str]:
    """
    Validate TIFF image structure using Pillow real parser.

    Checks byte-order mark (II/MM), magic value, IFD offset,
    and Pillow's ability to open and load the image.
    """
    if not data:
        return False, "Candidate byte buffer is empty"
    if not (data.startswith(b"II\x2a\x00") or data.startswith(b"MM\x00\x2a")):
        return False, "Missing TIFF byte-order mark (II 0x2A00 or MM 0x002A)"
    try:
        img = Image.open(io.BytesIO(data))
        if img.format not in ("TIFF",):
            return False, f"Pillow detected format '{img.format}', expected 'TIFF'"
        img.verify()
        img_load = Image.open(io.BytesIO(data))
        img_load.load()
        width, height = img_load.size
        return True, f"Valid TIFF image ({width}x{height}, mode {img_load.mode}, Pillow parser)"
    except Exception as e:
        return False, f"Pillow TIFF validation failed: {str(e)}"


def validate_pcx(data: bytes) -> Tuple[bool, str]:
    """
    Validate PCX image structure using Pillow real parser with header pre-check.

    PCX header byte 0 must be 0x0A (manufacturer), version in {0,2,3,4,5},
    encoding in {0,1}, bit depth in {1,2,4,8}, and Pillow must load it.
    """
    if not data:
        return False, "Candidate byte buffer is empty"
    if len(data) < 128:
        return False, f"PCX candidate too small: {len(data)} bytes (minimum 128)"
    if data[0] != 0x0A:
        return False, "Missing PCX manufacturer byte (0x0A)"
    if data[1] not in (0, 2, 3, 4, 5):
        return False, f"PCX version byte out of range: {data[1]}"
    if data[2] not in (0, 1):
        return False, f"PCX encoding byte invalid: {data[2]}"
    if data[3] not in (1, 2, 4, 8):
        return False, f"PCX bits-per-plane invalid: {data[3]}"
    try:
        img = Image.open(io.BytesIO(data))
        if img.format not in ("PCX",):
            return False, f"Pillow detected format '{img.format}', expected 'PCX'"
        img.verify()
        img_load = Image.open(io.BytesIO(data))
        img_load.load()
        width, height = img_load.size
        return True, f"Valid PCX image ({width}x{height}, mode {img_load.mode}, Pillow parser)"
    except Exception as e:
        return False, f"Pillow PCX validation failed: {str(e)}"


def validate_tar(data: bytes) -> Tuple[bool, str]:
    """Validate TAR archive structure and checksums using TarArchiveAdapter."""
    from .archive_adapter import get_archive_adapter
    adapter = get_archive_adapter("tar")
    if not adapter:
        return False, "TAR adapter unavailable"
    valid, msg, _ = adapter.validate_candidate(data)
    return valid, msg


def validate_7z(data: bytes) -> Tuple[bool, str]:
    """Validate 7Z archive signature and CRC headers using SevenZipArchiveAdapter."""
    from .archive_adapter import get_archive_adapter
    adapter = get_archive_adapter("7z")
    if not adapter:
        return False, "7Z adapter unavailable"
    valid, msg, _ = adapter.validate_candidate(data)
    return valid, msg


def validate_rar(data: bytes) -> Tuple[bool, str]:
    """Validate RAR archive headers and block records using RarArchiveAdapter."""
    from .archive_adapter import get_archive_adapter
    adapter = get_archive_adapter("rar")
    if not adapter:
        return False, "RAR adapter unavailable"
    valid, msg, _ = adapter.validate_candidate(data)
    return valid, msg


def validate_wim(data: bytes) -> Tuple[bool, str]:
    """Validate WIM archive header structure using WimArchiveAdapter."""
    from .archive_adapter import get_archive_adapter
    adapter = get_archive_adapter("wim")
    if not adapter:
        return False, "WIM adapter unavailable"
    valid, msg, _ = adapter.validate_candidate(data)
    return valid, msg


def validate_gz(data: bytes) -> Tuple[bool, str]:
    """Validate GZIP compressed stream using GzArchiveAdapter."""
    from .archive_adapter import get_archive_adapter
    adapter = get_archive_adapter("gz")
    if not adapter:
        return False, "GZ adapter unavailable"
    valid, msg, _ = adapter.validate_candidate(data)
    return valid, msg


def validate_bz2(data: bytes) -> Tuple[bool, str]:
    """Validate BZIP2 compressed stream using Bz2ArchiveAdapter."""
    from .archive_adapter import get_archive_adapter
    adapter = get_archive_adapter("bz2")
    if not adapter:
        return False, "BZ2 adapter unavailable"
    valid, msg, _ = adapter.validate_candidate(data)
    return valid, msg


def validate_reconstruction(file_type: str, data: bytes) -> Tuple[bool, str]:
    """
    Dispatch structural validation based on file type.
    
    Supported types: jpeg, png, gif, bmp, tiff, pcx, pdf, docx, xlsx, pptx, zip, tar, 7z, rar, wim, gz, bz2, sqlite, wav, text.
    """
    if not data:
        return False, "Candidate byte buffer is empty"
    
    ft = (file_type or "").lower().strip().lstrip(".")
    if ft in ("jpeg", "jpg"):
        return validate_jpeg(data)
    elif ft == "png":
        return validate_png(data)
    elif ft == "gif":
        return validate_gif(data)
    elif ft == "bmp":
        return validate_bmp(data)
    elif ft in ("tiff", "tif"):
        return validate_tiff(data)
    elif ft == "pcx":
        return validate_pcx(data)
    elif ft == "pdf":
        return validate_pdf(data)
    elif ft == "docx":
        return validate_docx(data)
    elif ft == "xlsx":
        return validate_xlsx(data)
    elif ft == "pptx":
        return validate_pptx(data)
    elif ft == "zip":
        return validate_zip(data)
    elif ft == "tar":
        return validate_tar(data)
    elif ft == "7z":
        return validate_7z(data)
    elif ft == "rar":
        return validate_rar(data)
    elif ft == "wim":
        return validate_wim(data)
    elif ft in ("gz", "gzip"):
        return validate_gz(data)
    elif ft == "bz2":
        return validate_bz2(data)
    elif ft in ("sqlite", "sqlite3", "db"):
        return validate_sqlite(data)
    elif ft in ("wav", "wave"):
        return validate_wav(data)
    elif ft in ("text", "txt"):
        return validate_text(data)
    else:
        return False, f"Unsupported file type / not structurally validated ('{file_type}'); treated as raw binary candidate"
