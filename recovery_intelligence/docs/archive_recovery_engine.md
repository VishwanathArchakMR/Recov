# RECOV Archive Recovery Engine — Technical Documentation

## 1. Architecture & Design Principles

The RECOV Archive Recovery Engine adds format-aware, evidence-grounded structural recovery for compressed streams and multi-file container archives. It extends RECOV's 8-stage deterministic pipeline without altering any existing data structures or non-archive formats.

```
Evidence Disk Image (.dd / .raw)
          ↓
SHA-256 Hashing & Ingestion (Stage 1)
          ↓
Format-Aware Carving (Stage 1)
          ↓
Entropy & Characterization (Stage 2)
          ↓
Fingerprinting & Feature Vectors (Stage 3)
          ↓
Relationship Graph with Archive Constraints (Stage 4)
          ↓
DBSCAN Clustering & Provenance Grouping (Stage 4)
          ↓
Archive Reconstruction Engine (L1/L2/L4/L5) (Stage 5)
          ↓
Structural Parser Validation (Stage 5)
          ↓
Decomposed 4-Signal Integrity Scoring (Stage 6)
          ↓
Real Recoverability Assessment (Stage 7)
          ↓
Sensitivity Classification & Priority Ranking (Stage 8)
```

### Core Tenets
1. **Evidence-Grounded**: All candidate offsets, member boundaries, and logical layouts are extracted strictly from disk bytes. Ground truth files are never imported into production recovery logic.
2. **Deterministic Search**: Non-sequential and interleaved recovery use bounded beam search with hard structural pruning (no uncontrolled brute-force or factorial permutation searches).
3. **Honest Validation**: Real format parsers (`zipfile`, `tarfile`, `gzip`, `bz2`, and structural header validators for `7z`, `rar`, `wim`) determine recovery states (`COMPLETE_ARCHIVE`, `PARTIAL_ARCHIVE`, `VALID_MEMBER_ONLY`, `STRUCTURALLY_INVALID`).

---

## 2. Supported Archive Formats

| Format | Category | Magic Signature | Validation Mechanism | Supported Recovery States |
| :--- | :--- | :--- | :--- | :--- |
| **ZIP** | Multi-File Container | `PK\x03\x04` | `zipfile.ZipFile.testzip()`, per-member CRC-32 & DEFLATE stream verification | `COMPLETE_ARCHIVE`, `PARTIAL_ARCHIVE`, `VALID_MEMBER_ONLY`, `STRUCTURALLY_INVALID` |
| **TAR** | Multi-File Container | `ustar\x0000`, `ustar  \x00` | 512-byte header block checksum verification (8-space sum), `tarfile` verification | `COMPLETE_ARCHIVE`, `PARTIAL_ARCHIVE`, `STRUCTURALLY_INVALID` |
| **7Z** | Multi-File Container | `7z\xbc\xaf\x27\x1c` | 32-byte header `StartHeaderCRC` verification, `NextHeaderOffset` / `NextHeaderSize` / `NextHeaderCRC` checks | `COMPLETE_ARCHIVE`, `PARTIAL_ARCHIVE`, `STRUCTURALLY_INVALID` |
| **RAR** | Multi-File Container | `Rar!\x1a\x07\x00` (v4), `Rar!\x1a\x07\x01\x00` (v5) | Block header CRC16 verification, `MAIN_HEAD` (0x73) and `FILE_HEAD` (0x74) chain continuity | `COMPLETE_ARCHIVE`, `PARTIAL_ARCHIVE`, `METADATA_ONLY`, `STRUCTURALLY_INVALID` |
| **WIM** | Image Container | `MSWIM\x00\x00\x00` | 208-byte header validation, version `0x00010D00`, descriptor plausibility checks | `STRUCTURALLY_VALID`, `STRUCTURALLY_INVALID` |
| **GZ** | Compressed Stream | `\x1f\x8b\x08` | `gzip.decompress()` / `zlib.decompressobj(wbits=31)` stream decompression & CRC trailer | `COMPLETE_ARCHIVE`, `PARTIAL_ARCHIVE`, `STRUCTURALLY_INVALID` |
| **BZ2** | Compressed Stream | `BZh` + `1AY&SY` | `bz2.BZ2Decompressor` / `bz2.decompress()` stream decompression & EOS marker checks | `COMPLETE_ARCHIVE`, `PARTIAL_ARCHIVE`, `STRUCTURALLY_INVALID` |

---

## 3. Fragmentation Level Handling

### L1 — Sequential Fragmentation
Reconstructs contiguous archive blocks across physical cluster sequences, validating declared spans and trailers.

### L2 — Non-Sequential Fragmentation
When physical ordering does not yield a valid archive, deterministic beam search (beam width ≤ 8, search depth ≤ 12) explores block combinations constrained by format-specific header fields, member CRCs, and decompressor progress.

### L4 — Nested Fragmentation
Identifies outer container boundaries, reconstructs container archives, scans for inner embedded archive headers on 512-byte boundaries, and records provenance links (`parent_candidate_id`, `offset_in_parent`).

### L5 — Braided / Interleaved Fragmentation
Separates interleaved multi-archive candidate streams using the relationship graph with typed constraints (`MUST_FOLLOW`, `SAME_ARCHIVE`, `SAME_MEMBER`) and hard parser validation pruning.

---

## 4. Running Tests and Benchmarks

### Running the Test Suite
```bash
python -m pytest tests/test_archive_recovery.py -v
python -m pytest -v
```

### Running Offline Archive Analysis
```bash
python tools/analyze_archives.py
```

### Running Full Archive Benchmark
```bash
python evaluation/archive_benchmark.py
```

---

## 5. Limitations
- Encrypted/password-protected archives without known keys cannot be fully decompressed; structural metadata and headers are extracted and marked `METADATA_ONLY` or `PARTIAL_ARCHIVE`.
- Missing compressed stream blocks that destroy decompression dictionary state are reported honestly as `PARTIAL_ARCHIVE` with exact recovered byte counts rather than fabricating missing data.
