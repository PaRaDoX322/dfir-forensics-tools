#!/usr/bin/env python3
"""
disk_entropy_scanner.py — Disk Image Entropy Scanner for Ransomware Analysis
=============================================================================
Scans disk images sector-by-sector to detect encrypted regions using Shannon
entropy analysis. Identifies partial encryption boundaries, plaintext islands
within encrypted volumes, and generates visual entropy maps for forensic
documentation.

Primary use case: ransomware recovery forensics — determining which sectors
contain recoverable plaintext data and locating the precise encryption boundary
in interrupted deployments.

Companion tool to:
  "Enterprise Ransomware Recovery: A Structured Forensic Methodology for
   System Restoration Without Ransom Payment" — D. Kharkovets, 2024

Usage:
  python disk_entropy_scanner.py image.dd
  python disk_entropy_scanner.py image.dd --block-size 4096 --threshold 7.5
  python disk_entropy_scanner.py image.dd --out report.csv --map entropy_map.txt
  python disk_entropy_scanner.py image.dd --find-boundary --verbose

Author:  Dmitrii Kharkovets
License: MIT
Version: 1.0.0
"""

import argparse
import csv
import math
import os
import struct
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_BLOCK_SIZE    = 4096    # bytes per analysis block
DEFAULT_ENC_THRESHOLD = 7.5     # bits/byte — above this = likely encrypted
DEFAULT_PLAINTEXT_THR = 4.0     # bits/byte — below this = likely plaintext/zero
SECTOR_SIZE           = 512     # standard logical sector size

# Entropy signatures for common data types
ENTROPY_SIGNATURES = {
    "zero_fill":    (0.0, 0.5),    # all-zero blocks
    "plaintext":    (3.0, 6.5),    # typical text, executables, databases
    "compressed":   (7.0, 8.0),    # already-compressed data (images, archives)
    "encrypted":    (7.5, 8.0),    # encrypted data (AES-CBC/CTR output)
    "random":       (7.9, 8.0),    # true random / key material
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclass
class BlockRecord:
    offset: int          # byte offset from start of image
    lba: int             # logical sector address (offset // 512)
    entropy: float       # Shannon entropy (0.0–8.0)
    classification: str  # zero_fill / plaintext / compressed / encrypted / mixed
    size: int            # block size in bytes
    first_bytes: bytes   # first 8 bytes for signature matching


@dataclass
class EntropyReport:
    total_blocks: int = 0
    total_bytes: int = 0
    encrypted_blocks: int = 0
    plaintext_blocks: int = 0
    zero_blocks: int = 0
    mixed_blocks: int = 0
    avg_entropy: float = 0.0
    encryption_start_offset: Optional[int] = None
    encryption_end_offset: Optional[int] = None
    plaintext_islands: List[Tuple[int, int]] = None  # (start_offset, size)

    def __post_init__(self):
        if self.plaintext_islands is None:
            self.plaintext_islands = []


# ---------------------------------------------------------------------------
# Shannon entropy
# ---------------------------------------------------------------------------
def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy in bits per byte (0.0–8.0)."""
    if not data:
        return 0.0
    n = len(data)
    freq = defaultdict(int)
    for b in data:
        freq[b] += 1
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def classify_block(entropy: float, data: bytes) -> str:
    """Classify a block by its entropy value."""
    if entropy < 0.1:
        return "zero_fill"
    elif entropy < DEFAULT_PLAINTEXT_THR:
        return "plaintext"
    elif entropy < DEFAULT_ENC_THRESHOLD:
        return "compressed_or_mixed"
    else:
        return "encrypted"


# ---------------------------------------------------------------------------
# File system signature detection
# ---------------------------------------------------------------------------
FS_SIGNATURES = {
    b"\xEB\x3C\x90": "FAT12/16/32 (VBR)",
    b"\xEB\x58\x90": "NTFS (VBR)",
    b"\xEF\x53":     "ext2/3/4 superblock",
    b"\x53\xEF":     "ext2/3/4 superblock (LE)",
    b"PK\x03\x04":   "ZIP archive",
    b"\xFF\xD8\xFF":  "JPEG image",
    b"\x89PNG":       "PNG image",
    b"MZ":            "PE executable",
    b"\x7FELF":       "ELF executable",
    b"SQLite":        "SQLite database",
    b"%PDF":          "PDF document",
    b"RIFF":          "RIFF container (AVI/WAV)",
    b"\x00\x00\x01\xBA": "MPEG video stream",
}

def detect_signature(data: bytes) -> Optional[str]:
    """Detect known file system or file type signatures in block header."""
    for sig, name in FS_SIGNATURES.items():
        if data[:len(sig)] == sig:
            return name
    return None


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------
def scan_image(
    image_path: Path,
    block_size: int = DEFAULT_BLOCK_SIZE,
    enc_threshold: float = DEFAULT_ENC_THRESHOLD,
    start_offset: int = 0,
    end_offset: Optional[int] = None,
    verbose: bool = False,
) -> Tuple[List[BlockRecord], EntropyReport]:
    """
    Scan a disk image and return per-block entropy records and summary report.
    """
    file_size = image_path.stat().st_size
    if end_offset is None:
        end_offset = file_size

    total_blocks = (end_offset - start_offset) // block_size
    records: List[BlockRecord] = []
    report  = EntropyReport()

    entropy_sum = 0.0
    in_plaintext_island = False
    island_start = 0

    print(f"\n[+] Scanning: {image_path.name}")
    print(f"    Block size:   {block_size} bytes")
    print(f"    Enc threshold:{enc_threshold} bits/byte")
    print(f"    Range:        {start_offset:,} – {end_offset:,} bytes")
    print(f"    Total blocks: {total_blocks:,}\n")

    with open(image_path, "rb") as f:
        f.seek(start_offset)
        block_idx = 0

        while True:
            offset = f.tell()
            if offset >= end_offset:
                break

            data = f.read(block_size)
            if not data:
                break

            # Pad short last block
            if len(data) < block_size:
                data = data + b"\x00" * (block_size - len(data))

            entropy = shannon_entropy(data)
            classification = classify_block(entropy, data)
            sig = detect_signature(data)

            rec = BlockRecord(
                offset=offset,
                lba=offset // SECTOR_SIZE,
                entropy=entropy,
                classification=classification,
                size=len(data),
                first_bytes=data[:8],
            )
            records.append(rec)

            # Track encryption boundary
            if entropy >= enc_threshold:
                if report.encryption_start_offset is None:
                    report.encryption_start_offset = offset
                report.encryption_end_offset = offset + block_size
                report.encrypted_blocks += 1
            elif entropy < DEFAULT_PLAINTEXT_THR:
                if classification == "zero_fill":
                    report.zero_blocks += 1
                else:
                    report.plaintext_blocks += 1
            else:
                report.mixed_blocks += 1

            # Track plaintext islands within encrypted regions
            if report.encryption_start_offset is not None:
                if entropy < enc_threshold - 0.5:
                    if not in_plaintext_island:
                        in_plaintext_island = True
                        island_start = offset
                else:
                    if in_plaintext_island:
                        island_size = offset - island_start
                        if island_size >= block_size * 4:  # Only note significant islands
                            report.plaintext_islands.append((island_start, island_size))
                        in_plaintext_island = False

            entropy_sum += entropy
            report.total_blocks += 1
            report.total_bytes += len(data)
            block_idx += 1

            # Progress
            if block_idx % 1000 == 0:
                pct = block_idx / total_blocks * 100
                print(f"\r    Progress: {pct:5.1f}%  ({block_idx:,}/{total_blocks:,})", end="", flush=True)

            if verbose and sig:
                print(f"\r    [sig] offset=0x{offset:X} ({sig})                     ")

    print(f"\r    Progress: 100.0%  ({report.total_blocks:,}/{total_blocks:,})")
    report.avg_entropy = entropy_sum / report.total_blocks if report.total_blocks else 0
    return records, report


# ---------------------------------------------------------------------------
# Entropy map (ASCII visualization)
# ---------------------------------------------------------------------------
def render_entropy_map(
    records: List[BlockRecord],
    width: int = 80,
    enc_threshold: float = DEFAULT_ENC_THRESHOLD,
) -> str:
    """
    Render a compact ASCII entropy map.
    Legend: '.' = zero/plaintext  '░' = mixed  '▓' = compressed  '█' = encrypted
    """
    chars = []
    for rec in records:
        e = rec.entropy
        if e < 0.1:
            chars.append(" ")   # zero fill
        elif e < DEFAULT_PLAINTEXT_THR:
            chars.append(".")   # plaintext
        elif e < 6.5:
            chars.append("o")   # mixed/compressed
        elif e < enc_threshold:
            chars.append("#")   # high entropy
        else:
            chars.append("X")   # encrypted

    lines = []
    for i in range(0, len(chars), width):
        lines.append("".join(chars[i:i+width]))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def print_report(report: EntropyReport, image_size: int, block_size: int) -> None:
    enc_pct  = report.encrypted_blocks / report.total_blocks * 100 if report.total_blocks else 0
    plain_pct = (report.plaintext_blocks + report.zero_blocks) / report.total_blocks * 100 if report.total_blocks else 0

    print(f"\n{'='*60}")
    print(f"  DISK ENTROPY SCAN REPORT")
    print(f"{'='*60}")
    print(f"  Image size:        {image_size / (1024**3):.2f} GB ({image_size:,} bytes)")
    print(f"  Block size:        {block_size} bytes")
    print(f"  Total blocks:      {report.total_blocks:,}")
    print(f"  Average entropy:   {report.avg_entropy:.3f} bits/byte")
    print(f"")
    print(f"  Encrypted blocks:  {report.encrypted_blocks:,}  ({enc_pct:.1f}%)")
    print(f"  Plaintext blocks:  {report.plaintext_blocks:,}  ({plain_pct:.1f}%)")
    print(f"  Zero-fill blocks:  {report.zero_blocks:,}")
    print(f"  Mixed blocks:      {report.mixed_blocks:,}")
    print(f"")

    if report.encryption_start_offset is not None:
        print(f"  Encryption start:  0x{report.encryption_start_offset:012X}  "
              f"(LBA {report.encryption_start_offset//512:,})")
        print(f"  Encryption end:    0x{report.encryption_end_offset:012X}  "
              f"(LBA {report.encryption_end_offset//512:,})")
        enc_size = report.encryption_end_offset - report.encryption_start_offset
        print(f"  Encrypted range:   {enc_size / (1024**2):.1f} MB")
    else:
        print(f"  No encrypted regions detected above threshold.")

    if report.plaintext_islands:
        print(f"\n  Plaintext islands within encrypted region: {len(report.plaintext_islands)}")
        for i, (start, size) in enumerate(report.plaintext_islands[:10]):
            print(f"    Island {i+1}: offset=0x{start:012X}  size={size/1024:.1f} KB")
        if len(report.plaintext_islands) > 10:
            print(f"    ... and {len(report.plaintext_islands)-10} more (see CSV)")

    print(f"{'='*60}")

    # Interpretation
    if enc_pct > 90:
        print(f"\n  [!] ASSESSMENT: Fully encrypted (>{enc_pct:.0f}% blocks)")
        print(f"      → Standard recovery path unavailable.")
        print(f"      → Focus on backup/VSS recovery and decryption pathways.")
    elif enc_pct > 20:
        print(f"\n  [!] ASSESSMENT: Partially encrypted ({enc_pct:.0f}% blocks)")
        print(f"      → Plaintext data recoverable from unencrypted regions.")
        if report.plaintext_islands:
            total_island = sum(s for _, s in report.plaintext_islands)
            print(f"      → {len(report.plaintext_islands)} recoverable islands ({total_island/(1024**2):.1f} MB)")
    else:
        print(f"\n  [✓] ASSESSMENT: Minimal encryption detected ({enc_pct:.0f}% blocks)")
        print(f"      → Data largely accessible through standard recovery.")


def export_csv(records: List[BlockRecord], out_path: Path) -> None:
    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["offset_hex", "lba", "entropy", "classification",
                         "first_bytes_hex", "signature"])
        for rec in records:
            sig = detect_signature(rec.first_bytes) or ""
            writer.writerow([
                f"0x{rec.offset:012X}",
                rec.lba,
                f"{rec.entropy:.4f}",
                rec.classification,
                rec.first_bytes.hex(),
                sig,
            ])
    print(f"[+] Block records exported → {out_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Disk Entropy Scanner — DFIR Ransomware Forensics Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick scan with defaults:
  python disk_entropy_scanner.py image.dd

  # Fine-grained 512B block scan:
  python disk_entropy_scanner.py image.dd --block-size 512

  # Custom encryption threshold + CSV export:
  python disk_entropy_scanner.py image.dd --threshold 7.2 --out entropy.csv

  # Find exact encryption boundary and print map:
  python disk_entropy_scanner.py image.dd --find-boundary --map

  # Scan partial range (offset in bytes):
  python disk_entropy_scanner.py image.dd --start 1073741824 --end 5368709120
        """,
    )
    parser.add_argument("image", help="Path to disk image file (raw/DD format)")
    parser.add_argument("--block-size", type=int, default=DEFAULT_BLOCK_SIZE,
                        help=f"Analysis block size in bytes (default: {DEFAULT_BLOCK_SIZE})")
    parser.add_argument("--threshold", type=float, default=DEFAULT_ENC_THRESHOLD,
                        help=f"Entropy threshold for encryption detection (default: {DEFAULT_ENC_THRESHOLD})")
    parser.add_argument("--start", type=int, default=0,
                        help="Start offset in bytes (default: 0)")
    parser.add_argument("--end", type=int, default=None,
                        help="End offset in bytes (default: end of file)")
    parser.add_argument("--out", default=None,
                        help="Export block records to CSV file")
    parser.add_argument("--map", action="store_true",
                        help="Print ASCII entropy map to stdout")
    parser.add_argument("--map-file", default=None,
                        help="Save entropy map to text file")
    parser.add_argument("--find-boundary", action="store_true",
                        help="Highlight encryption start/end boundaries")
    parser.add_argument("--verbose", action="store_true",
                        help="Show file system signatures as detected")

    args = parser.parse_args()

    image_path = Path(args.image)
    if not image_path.exists():
        print(f"[!] File not found: {image_path}", file=sys.stderr)
        sys.exit(1)

    records, report = scan_image(
        image_path=image_path,
        block_size=args.block_size,
        enc_threshold=args.threshold,
        start_offset=args.start,
        end_offset=args.end,
        verbose=args.verbose,
    )

    print_report(report, image_path.stat().st_size, args.block_size)

    if args.map or args.map_file:
        emap = render_entropy_map(records, enc_threshold=args.threshold)
        if args.map:
            print(f"\nEntropy Map (. = plaintext  o = mixed  # = high  X = encrypted):")
            print(emap)
        if args.map_file:
            Path(args.map_file).write_text(emap)
            print(f"[+] Entropy map saved → {args.map_file}")

    if args.out:
        export_csv(records, Path(args.out))

    print(f"\n[✓] Scan complete.")


if __name__ == "__main__":
    main()
