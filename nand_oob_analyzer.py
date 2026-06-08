#!/usr/bin/env python3
"""
nand_oob_analyzer.py — NAND Flash OOB Area Analyzer & L2P Map Reconstructor
============================================================================
Analyzes Out-of-Band (spare) areas from raw NAND flash dumps to reconstruct
the Flash Translation Layer (FTL) Logical-to-Physical address mapping.

This tool supports forensic recovery workflows for controller-locked NAND
devices where the storage controller is unresponsive and the FTL must be
reconstructed from raw NAND page data.

Companion tool to:
  "NAND Flash Forensics: Recovery Methodology for Controller-Locked
   Storage Devices" — D. Kharkovets, 2024

Usage:
  python nand_oob_analyzer.py dump.bin --page-size 4096 --oob-size 128
  python nand_oob_analyzer.py dump.bin --page-size 2048 --oob-size 64 --layout samsung
  python nand_oob_analyzer.py dump.bin --auto-detect --out l2p_map.csv

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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# OOB Layout Definitions
# Each layout describes where the LBA tag and other FTL metadata live within
# the OOB area. Offsets are in bytes from the start of the OOB region.
# ---------------------------------------------------------------------------
OOB_LAYOUTS = {
    "samsung": {
        "description": "Samsung OneNAND / eMMC controller (common in mobile/SD)",
        "lba_offset": 0,
        "lba_size": 4,
        "lba_mask": 0x0FFFFFFF,
        "erase_count_offset": 4,
        "erase_count_size": 4,
        "valid_flag_offset": 8,
        "valid_flag_byte": 0xFF,  # 0xFF = valid, 0x00 = invalid
        "bad_block_offset": 0,
        "bad_block_byte": 0xFF,
    },
    "hynix": {
        "description": "Hynix / SK Hynix flash controller",
        "lba_offset": 2,
        "lba_size": 4,
        "lba_mask": 0x7FFFFFFF,
        "erase_count_offset": 6,
        "erase_count_size": 4,
        "valid_flag_offset": 0,
        "valid_flag_byte": 0xFF,
        "bad_block_offset": 0,
        "bad_block_byte": 0xFF,
    },
    "toshiba": {
        "description": "Toshiba BiCS NAND / SD controller",
        "lba_offset": 4,
        "lba_size": 4,
        "lba_mask": 0xFFFFFFFF,
        "erase_count_offset": 0,
        "erase_count_size": 4,
        "valid_flag_offset": 8,
        "valid_flag_byte": 0xFF,
        "bad_block_offset": 0,
        "bad_block_byte": 0xFF,
    },
    "sandisk": {
        "description": "SanDisk / Western Digital embedded controller",
        "lba_offset": 1,
        "lba_size": 4,
        "lba_mask": 0x00FFFFFF,
        "erase_count_offset": 5,
        "erase_count_size": 3,
        "valid_flag_offset": 0,
        "valid_flag_byte": 0xFF,
        "bad_block_offset": 0,
        "bad_block_byte": 0xFF,
    },
    "generic": {
        "description": "Generic / unknown layout — LBA in first 4 bytes",
        "lba_offset": 0,
        "lba_size": 4,
        "lba_mask": 0x7FFFFFFF,
        "erase_count_offset": 4,
        "erase_count_size": 4,
        "valid_flag_offset": 8,
        "valid_flag_byte": 0xFF,
        "bad_block_offset": 0,
        "bad_block_byte": 0xFF,
    },
}

UNWRITTEN_LBA = 0xFFFFFFFF  # All-ones = erased / unwritten page
INVALID_LBA   = 0x00000000  # All-zeros may indicate invalid in some layouts


@dataclass
class PageRecord:
    physical_page: int
    lba: int
    erase_count: int
    is_valid: bool
    is_bad_block: bool
    oob_raw: bytes
    data_entropy: float = 0.0


@dataclass
class L2PMap:
    """Reconstructed Logical-to-Physical address map."""
    mapping: Dict[int, int] = field(default_factory=dict)       # lba -> physical_page
    conflicts: Dict[int, List[int]] = field(default_factory=dict)  # lba -> [page1, page2]
    unmapped_lbas: List[int] = field(default_factory=list)
    bad_blocks: List[int] = field(default_factory=list)
    total_pages: int = 0
    valid_pages: int = 0
    unwritten_pages: int = 0


# ---------------------------------------------------------------------------
# Shannon Entropy
# ---------------------------------------------------------------------------
def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence (0.0–8.0 bits/byte)."""
    if not data:
        return 0.0
    freq = defaultdict(int)
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# ---------------------------------------------------------------------------
# Auto-detection of page geometry
# ---------------------------------------------------------------------------
def auto_detect_geometry(dump_path: Path) -> Tuple[int, int]:
    """
    Attempt to auto-detect page size and OOB size from dump file size and
    common NAND geometry signatures.

    Common (page_size, oob_size) combinations:
      (512, 16), (2048, 64), (2048, 128), (4096, 128),
      (4096, 224), (8192, 376), (16384, 1280)
    """
    file_size = dump_path.stat().st_size
    common_geometries = [
        (512,   16),
        (2048,  64),
        (2048, 128),
        (4096, 128),
        (4096, 224),
        (8192, 376),
    ]
    for page_size, oob_size in common_geometries:
        total_page_size = page_size + oob_size
        if file_size % total_page_size == 0:
            page_count = file_size // total_page_size
            print(f"[auto-detect] Geometry match: page={page_size}B oob={oob_size}B "
                  f"→ {page_count:,} pages ({file_size / (1024**3):.2f} GB)")
            return page_size, oob_size
    # Default fallback
    print("[auto-detect] No clean geometry match — defaulting to 4096+128")
    return 4096, 128


# ---------------------------------------------------------------------------
# Auto-detection of OOB layout
# ---------------------------------------------------------------------------
def auto_detect_layout(oob_samples: List[bytes], page_size: int) -> str:
    """
    Score each layout against OOB samples and return the best match.
    Scoring: valid LBA values (not 0xFFFFFFFF, reasonable range) score +1.
    """
    max_lba_expected = (page_size * len(oob_samples)) // 512  # rough upper bound
    scores = defaultdict(int)

    for layout_name, layout in OOB_LAYOUTS.items():
        if layout_name == "generic":
            continue
        lo = layout["lba_offset"]
        ls = layout["lba_size"]
        mask = layout["lba_mask"]
        for oob in oob_samples:
            if len(oob) < lo + ls:
                continue
            raw = int.from_bytes(oob[lo:lo+ls], "little") & mask
            if raw != UNWRITTEN_LBA and raw < max_lba_expected * 4:
                scores[layout_name] += 1

    if not scores:
        return "generic"
    best = max(scores, key=lambda k: scores[k])
    print(f"[auto-detect] Layout scores: {dict(scores)}")
    print(f"[auto-detect] Best layout: {best}")
    return best


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------
def analyze_dump(
    dump_path: Path,
    page_size: int,
    oob_size: int,
    layout_name: str,
    max_pages: Optional[int] = None,
) -> Tuple[List[PageRecord], L2PMap]:
    """Parse all pages from a raw NAND dump and reconstruct L2P mapping."""

    layout = OOB_LAYOUTS[layout_name]
    total_page_size = page_size + oob_size
    file_size = dump_path.stat().st_size
    total_pages = file_size // total_page_size

    if max_pages:
        total_pages = min(total_pages, max_pages)

    print(f"\n[+] Analyzing: {dump_path.name}")
    print(f"    Page size:  {page_size}B  OOB: {oob_size}B  Total: {total_page_size}B/page")
    print(f"    Layout:     {layout_name} — {layout['description']}")
    print(f"    Total pages:{total_pages:,}  ({total_pages * page_size / (1024**2):.1f} MB data)")

    records: List[PageRecord] = []
    l2p = L2PMap(total_pages=total_pages)

    # Track LBA→(page, erase_count) for conflict resolution
    lba_candidates: Dict[int, List[Tuple[int, int]]] = defaultdict(list)

    lo = layout["lba_offset"]
    ls = layout["lba_size"]
    mask = layout["lba_mask"]
    eo = layout["erase_count_offset"]
    es_size = layout["erase_count_size"]
    vf_off = layout["valid_flag_offset"]
    vf_byte = layout["valid_flag_byte"]
    bb_off = layout["bad_block_offset"]
    bb_byte = layout["bad_block_byte"]

    with open(dump_path, "rb") as f:
        for page_idx in range(total_pages):
            if page_idx % 10000 == 0:
                pct = page_idx / total_pages * 100
                print(f"\r    Progress: {pct:5.1f}%  ({page_idx:,}/{total_pages:,} pages)", end="", flush=True)

            page_data = f.read(page_size)
            oob_data  = f.read(oob_size)

            if len(page_data) < page_size or len(oob_data) < oob_size:
                break

            # Bad block check (byte 0 of OOB on first page of block)
            is_bad = oob_data[bb_off] != bb_byte

            # LBA extraction
            if len(oob_data) >= lo + ls:
                raw_lba = int.from_bytes(oob_data[lo:lo+ls], "little") & mask
            else:
                raw_lba = UNWRITTEN_LBA

            # Erase count extraction
            erase_count = 0
            if len(oob_data) >= eo + es_size:
                ec_raw = int.from_bytes(oob_data[eo:eo+es_size], "little")
                if ec_raw != UNWRITTEN_LBA:
                    erase_count = ec_raw

            # Valid flag
            is_valid = (len(oob_data) > vf_off) and (oob_data[vf_off] == vf_byte)

            # Entropy of data area (quick estimate on first 512B)
            entropy = shannon_entropy(page_data[:512])

            rec = PageRecord(
                physical_page=page_idx,
                lba=raw_lba,
                erase_count=erase_count,
                is_valid=is_valid,
                is_bad_block=is_bad,
                oob_raw=oob_data,
                data_entropy=entropy,
            )
            records.append(rec)

            # Update L2P candidates
            if is_bad:
                l2p.bad_blocks.append(page_idx)
            elif raw_lba == UNWRITTEN_LBA or raw_lba == 0xFFFFFF:
                l2p.unwritten_pages += 1
            else:
                l2p.valid_pages += 1
                lba_candidates[raw_lba].append((page_idx, erase_count))

    print(f"\r    Progress: 100.0%  ({total_pages:,}/{total_pages:,} pages)")

    # Resolve conflicts: multiple physical pages claiming same LBA → pick highest erase count
    for lba, candidates in lba_candidates.items():
        if len(candidates) == 1:
            l2p.mapping[lba] = candidates[0][0]
        else:
            # Sort by erase count descending; highest = most recently written
            candidates.sort(key=lambda x: x[1], reverse=True)
            l2p.mapping[lba] = candidates[0][0]
            l2p.conflicts[lba] = [c[0] for c in candidates]

    return records, l2p


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def print_summary(records: List[PageRecord], l2p: L2PMap, layout_name: str) -> None:
    mapped = len(l2p.mapping)
    conflicts = len(l2p.conflicts)
    bad = len(l2p.bad_blocks)
    unwritten = l2p.unwritten_pages

    if l2p.mapping:
        max_lba = max(l2p.mapping.keys())
        coverage = mapped / (max_lba + 1) * 100 if max_lba > 0 else 0
    else:
        max_lba = 0
        coverage = 0

    avg_entropy = sum(r.data_entropy for r in records) / len(records) if records else 0
    encrypted_pages = sum(1 for r in records if r.data_entropy > 7.5)

    print(f"\n{'='*60}")
    print(f"  NAND OOB ANALYSIS SUMMARY")
    print(f"{'='*60}")
    print(f"  Layout used:        {layout_name}")
    print(f"  Total pages:        {l2p.total_pages:,}")
    print(f"  Mapped LBAs:        {mapped:,}")
    print(f"  Max LBA seen:       {max_lba:,}")
    print(f"  LBA space coverage: {coverage:.1f}%")
    print(f"  Mapping conflicts:  {conflicts:,}")
    print(f"  Bad blocks:         {bad:,}")
    print(f"  Unwritten pages:    {unwritten:,}")
    print(f"  Avg data entropy:   {avg_entropy:.2f} bits/byte")
    print(f"  High-entropy pages: {encrypted_pages:,} (>7.5 — possibly compressed/encrypted)")
    print(f"{'='*60}")

    if conflicts > mapped * 0.1:
        print(f"  [!] High conflict rate ({conflicts/mapped*100:.1f}%) — check layout selection")
    if coverage < 50:
        print(f"  [!] Low LBA coverage ({coverage:.1f}%) — layout may be incorrect")
    if avg_entropy > 7.0:
        print(f"  [!] High average entropy — data may be compressed or encrypted")


def export_csv(records: List[PageRecord], l2p: L2PMap, out_path: Path) -> None:
    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "physical_page", "lba", "erase_count",
            "is_valid", "is_bad_block", "data_entropy",
            "conflict", "oob_hex"
        ])
        for rec in records:
            in_conflict = rec.lba in l2p.conflicts
            writer.writerow([
                rec.physical_page,
                f"0x{rec.lba:08X}" if rec.lba != UNWRITTEN_LBA else "UNWRITTEN",
                rec.erase_count,
                rec.is_valid,
                rec.is_bad_block,
                f"{rec.data_entropy:.4f}",
                in_conflict,
                rec.oob_raw.hex(),
            ])
    print(f"\n[+] Full page records exported → {out_path}")


def export_l2p_csv(l2p: L2PMap, out_path: Path) -> None:
    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["lba", "physical_page", "conflict", "conflict_pages"])
        for lba in sorted(l2p.mapping.keys()):
            phys = l2p.mapping[lba]
            conf = lba in l2p.conflicts
            conf_pages = ";".join(str(p) for p in l2p.conflicts.get(lba, []))
            writer.writerow([lba, phys, conf, conf_pages])
    print(f"[+] L2P map exported ({len(l2p.mapping):,} entries) → {out_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="NAND OOB Analyzer & FTL L2P Map Reconstructor — DFIR Forensics Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-detect geometry and layout:
  python nand_oob_analyzer.py dump.bin --auto-detect

  # Specify geometry, use Samsung layout:
  python nand_oob_analyzer.py dump.bin --page-size 4096 --oob-size 128 --layout samsung

  # Full analysis with CSV exports:
  python nand_oob_analyzer.py dump.bin --page-size 2048 --oob-size 64 \\
      --layout hynix --out-records records.csv --out-l2p l2p_map.csv

  # Analyze only first 100,000 pages (fast triage):
  python nand_oob_analyzer.py dump.bin --auto-detect --max-pages 100000

Available layouts: """ + ", ".join(OOB_LAYOUTS.keys()),
    )
    parser.add_argument("dump", help="Path to raw NAND dump file")
    parser.add_argument("--page-size", type=int, default=None,
                        help="NAND page data size in bytes (e.g. 4096)")
    parser.add_argument("--oob-size", type=int, default=None,
                        help="NAND OOB/spare area size in bytes (e.g. 128)")
    parser.add_argument("--layout", choices=list(OOB_LAYOUTS.keys()), default=None,
                        help="OOB layout to use. Omit for auto-detection.")
    parser.add_argument("--auto-detect", action="store_true",
                        help="Auto-detect page geometry and OOB layout")
    parser.add_argument("--max-pages", type=int, default=None,
                        help="Limit analysis to first N pages (for triage)")
    parser.add_argument("--out-records", default=None,
                        help="Export full page records to CSV")
    parser.add_argument("--out-l2p", default="l2p_map.csv",
                        help="Export L2P map to CSV (default: l2p_map.csv)")
    parser.add_argument("--list-layouts", action="store_true",
                        help="Print available OOB layouts and exit")

    args = parser.parse_args()

    if args.list_layouts:
        print("\nAvailable OOB layouts:")
        for name, layout in OOB_LAYOUTS.items():
            print(f"  {name:12s} — {layout['description']}")
        sys.exit(0)

    dump_path = Path(args.dump)
    if not dump_path.exists():
        print(f"[!] File not found: {dump_path}", file=sys.stderr)
        sys.exit(1)

    # Geometry detection
    if args.auto_detect or (args.page_size is None or args.oob_size is None):
        page_size, oob_size = auto_detect_geometry(dump_path)
    else:
        page_size = args.page_size
        oob_size  = args.oob_size

    # Sample OOB areas for layout detection
    layout_name = args.layout
    if layout_name is None:
        print("[*] Sampling OOB areas for layout detection...")
        samples = []
        total_page_size = page_size + oob_size
        with open(dump_path, "rb") as f:
            for _ in range(min(500, dump_path.stat().st_size // total_page_size)):
                f.read(page_size)
                oob = f.read(oob_size)
                if oob:
                    samples.append(oob)
        layout_name = auto_detect_layout(samples, page_size)

    # Full analysis
    records, l2p = analyze_dump(
        dump_path=dump_path,
        page_size=page_size,
        oob_size=oob_size,
        layout_name=layout_name,
        max_pages=args.max_pages,
    )

    print_summary(records, l2p, layout_name)

    # Exports
    if args.out_records:
        export_csv(records, l2p, Path(args.out_records))

    export_l2p_csv(l2p, Path(args.out_l2p))

    print(f"\n[✓] Analysis complete.")


if __name__ == "__main__":
    main()
