#!/usr/bin/env python3
"""
ransomware_triage.py — Ransomware Incident Rapid Triage Tool
=============================================================
Performs automated first-response analysis of a ransomware-affected directory
tree or disk image. Identifies the ransomware family, assesses encryption scope,
checks for VSS deletion attempts in Windows Event Logs, estimates recovery
viability, and generates a structured triage report for incident response.

Companion tool to:
  "Enterprise Ransomware Recovery: A Structured Forensic Methodology for
   System Restoration Without Ransom Payment" — D. Kharkovets, 2024

Usage:
  python ransomware_triage.py --dir /mnt/affected_volume
  python ransomware_triage.py --dir C:\\affected --event-log System.evtx
  python ransomware_triage.py --dir /mnt/vol --out triage_report.json

Author:  Dmitrii Kharkovets
License: MIT
Version: 1.0.0
"""

import argparse
import hashlib
import json
import math
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Known ransomware family signatures
# Extension → family mapping (common variants)
# ---------------------------------------------------------------------------
KNOWN_FAMILIES: Dict[str, Dict] = {
    # Extension patterns → family metadata
    r"\.lockbit\d*$":    {"family": "LockBit",     "has_decryptor": False, "double_extortion": True},
    r"\.lock$":          {"family": "LockBit (old)","has_decryptor": False, "double_extortion": True},
    r"\.blackcat$":      {"family": "BlackCat/ALPHV","has_decryptor": False,"double_extortion": True},
    r"\.alphv$":         {"family": "BlackCat/ALPHV","has_decryptor": False,"double_extortion": True},
    r"\.ryuk$":          {"family": "Ryuk",         "has_decryptor": False, "double_extortion": False},
    r"\.conti$":         {"family": "Conti",        "has_decryptor": False, "double_extortion": True},
    r"\.revil$":         {"family": "REvil/Sodinokibi","has_decryptor": True, "double_extortion": True},
    r"\.[0-9a-f]{8}$":   {"family": "Dharma/CrySiS","has_decryptor": False, "double_extortion": False},
    r"\.dharma$":        {"family": "Dharma",       "has_decryptor": False, "double_extortion": False},
    r"\.phobos$":        {"family": "Phobos",       "has_decryptor": False, "double_extortion": False},
    r"\.makop$":         {"family": "Makop",        "has_decryptor": False, "double_extortion": True},
    r"\.wncry$":         {"family": "WannaCry",     "has_decryptor": True,  "double_extortion": False},
    r"\.wannacry$":      {"family": "WannaCry",     "has_decryptor": True,  "double_extortion": False},
    r"\.locky$":         {"family": "Locky",        "has_decryptor": False, "double_extortion": False},
    r"\.cerber\d?$":     {"family": "Cerber",       "has_decryptor": False, "double_extortion": False},
    r"\.encrypted$":     {"family": "Unknown (generic)", "has_decryptor": False, "double_extortion": False},
    r"\.enc$":           {"family": "Unknown (generic)", "has_decryptor": False, "double_extortion": False},
    r"\.crypt$":         {"family": "CryptXXX",     "has_decryptor": True,  "double_extortion": False},
    r"\.crypted$":       {"family": "Unknown",      "has_decryptor": False, "double_extortion": False},
    r"\.zenis$":         {"family": "Zenis",        "has_decryptor": False, "double_extortion": False},
    r"\.mamba$":         {"family": "Mamba",        "has_decryptor": False, "double_extortion": False},
    r"\.petya$":         {"family": "Petya",        "has_decryptor": False, "double_extortion": False},
    r"\.zepto$":         {"family": "Locky (Zepto)","has_decryptor": False, "double_extortion": False},
    r"\.hive$":          {"family": "Hive",         "has_decryptor": True,  "double_extortion": True},
    r"\.ech0raix$":      {"family": "QNAPCrypt",    "has_decryptor": True,  "double_extortion": False},
    r"\.blackbasta$":    {"family": "Black Basta",  "has_decryptor": False, "double_extortion": True},
}

# Known ransom note filenames
RANSOM_NOTE_PATTERNS = [
    r"README.*\.txt$", r"HOW_TO_DECRYPT.*", r"DECRYPT_FILES.*",
    r"RESTORE_FILES.*", r"!HELP.*\.txt$", r"READ_ME.*\.html$",
    r"RECOVER.*\.txt$", r"_readme\.txt$", r"#DECRYPT#.*",
    r"!!! IMPORTANT !!!.*", r"YOUR_FILES_ARE_ENCRYPTED.*",
    r"LOCKBIT.*\.txt$", r"BLACKCAT.*\.txt$",
]

# VSS deletion command patterns (for Event Log analysis)
VSS_DELETE_COMMANDS = [
    "vssadmin delete shadows",
    "wmic shadowcopy delete",
    "vssadmin.exe delete shadows",
    "bcdedit.exe /set",
    "wbadmin delete catalog",
    "Get-WmiObject Win32_Shadowcopy",
    "diskshadow.exe",
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclass
class FileStats:
    total_files: int = 0
    encrypted_files: int = 0
    ransom_notes_found: int = 0
    extension_counts: Dict[str, int] = field(default_factory=dict)
    top_encrypted_extensions: List[Tuple[str, int]] = field(default_factory=list)
    ransom_note_paths: List[str] = field(default_factory=list)
    sample_hashes: List[str] = field(default_factory=list)


@dataclass
class FamilyIdentification:
    detected_extension: str = ""
    family: str = "Unknown"
    has_decryptor: bool = False
    double_extortion: bool = False
    confidence: str = "low"
    nomoreransom_url: str = "https://www.nomoreransom.org/en/decryption-tools.html"


@dataclass
class VSSStatus:
    vss_delete_commands_found: List[str] = field(default_factory=list)
    deletion_likely_executed: bool = False
    event_log_analyzed: bool = False
    recommendation: str = ""


@dataclass
class TriageReport:
    scan_timestamp: str = ""
    target_path: str = ""
    file_stats: FileStats = field(default_factory=FileStats)
    family_id: FamilyIdentification = field(default_factory=FamilyIdentification)
    vss_status: VSSStatus = field(default_factory=VSSStatus)
    recovery_score: int = 0
    recovery_assessment: str = ""
    recommended_phases: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# File scanning
# ---------------------------------------------------------------------------
def scan_directory(target: Path, max_files: int = 100000) -> FileStats:
    """
    Walk directory tree and collect extension statistics,
    detect ransom notes, and sample encrypted file hashes.
    """
    stats = FileStats()
    ext_counter: Counter = Counter()
    scanned = 0

    print(f"\n[+] Scanning directory: {target}")

    for root, dirs, files in os.walk(target):
        # Skip known system directories
        dirs[:] = [d for d in dirs if d not in {
            "$RECYCLE.BIN", "System Volume Information", "Windows",
            "Program Files", "Program Files (x86)"
        }]

        for fname in files:
            if scanned >= max_files:
                print(f"    [!] Scan limit reached ({max_files:,} files)")
                break

            fpath = Path(root) / fname
            stats.total_files += 1
            scanned += 1

            suffix = fpath.suffix.lower()
            ext_counter[suffix] += 1

            # Ransom note detection
            for pattern in RANSOM_NOTE_PATTERNS:
                if re.search(pattern, fname, re.IGNORECASE):
                    stats.ransom_notes_found += 1
                    stats.ransom_note_paths.append(str(fpath))
                    break

            # Sample hash for first 50 encrypted-looking files
            if len(stats.sample_hashes) < 50 and suffix not in {
                ".txt", ".html", ".htm", ".log", ".ini", ".cfg"
            }:
                try:
                    h = hashlib.md5(fpath.read_bytes()[:4096]).hexdigest()
                    stats.sample_hashes.append(f"{h}:{fpath.name}")
                except (PermissionError, OSError):
                    pass

        if scanned >= max_files:
            break

        if scanned % 5000 == 0:
            print(f"\r    Scanned: {scanned:,} files...", end="", flush=True)

    print(f"\r    Scanned: {scanned:,} files total.      ")

    stats.extension_counts = dict(ext_counter)
    stats.top_encrypted_extensions = ext_counter.most_common(20)
    return stats


# ---------------------------------------------------------------------------
# Family identification
# ---------------------------------------------------------------------------
def identify_family(stats: FileStats) -> FamilyIdentification:
    """Identify ransomware family from extension patterns."""
    fid = FamilyIdentification()

    # Look for unusual extensions (not common legitimate ones)
    COMMON_LEGIT = {
        ".txt", ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".jpg",
        ".jpeg", ".png", ".mp4", ".mp3", ".zip", ".exe", ".dll",
        ".sys", ".ini", ".cfg", ".log", ".bak", ".html", ".htm",
        ".pptx", ".csv", ".xml", ".json", ".py", ".js", ".sql",
    }

    suspicious_exts = [
        (ext, count) for ext, count in stats.top_encrypted_extensions
        if ext not in COMMON_LEGIT and ext != "" and count > 5
    ]

    if not suspicious_exts:
        return fid

    # Take the most common suspicious extension
    candidate_ext, count = suspicious_exts[0]
    fid.detected_extension = candidate_ext

    # Match against known families
    for pattern, meta in KNOWN_FAMILIES.items():
        if re.search(pattern, candidate_ext, re.IGNORECASE):
            fid.family = meta["family"]
            fid.has_decryptor = meta["has_decryptor"]
            fid.double_extortion = meta["double_extortion"]
            fid.confidence = "high" if count > 100 else "medium"
            return fid

    # Unknown extension — still flag it
    fid.family = f"Unknown (extension: {candidate_ext})"
    fid.confidence = "low"
    return fid


# ---------------------------------------------------------------------------
# VSS analysis (text-based, no Winevt dependency)
# ---------------------------------------------------------------------------
def analyze_vss_from_strings(event_log_path: Optional[Path]) -> VSSStatus:
    """
    Scan event log file as raw text for VSS deletion command strings.
    Works without Windows-specific libraries (cross-platform).
    """
    status = VSSStatus()
    status.recommendation = "VSS snapshot status unknown — verify manually with: vssadmin list shadows"

    if event_log_path is None or not event_log_path.exists():
        return status

    status.event_log_analyzed = True
    print(f"\n[+] Analyzing event log: {event_log_path.name}")

    try:
        raw = event_log_path.read_bytes()
        text = raw.decode("utf-8", errors="replace") + raw.decode("utf-16-le", errors="replace")

        for cmd in VSS_DELETE_COMMANDS:
            if cmd.lower() in text.lower():
                status.vss_delete_commands_found.append(cmd)

        if status.vss_delete_commands_found:
            status.deletion_likely_executed = True
            status.recommendation = (
                "VSS deletion commands found in logs. Snapshots likely deleted. "
                "However: verify directly — failed deletion is common. Run: vssadmin list shadows"
            )
        else:
            status.recommendation = (
                "No VSS deletion commands found in analyzed log. "
                "Snapshots may be intact — verify: vssadmin list shadows"
            )
    except Exception as e:
        status.recommendation = f"Event log analysis failed: {e}"

    return status


# ---------------------------------------------------------------------------
# Recovery viability score (simplified — see recovery_viability_scorer.py for full version)
# ---------------------------------------------------------------------------
def calculate_quick_score(
    stats: FileStats,
    fid: FamilyIdentification,
    vss: VSSStatus,
) -> Tuple[int, str, List[str]]:
    """
    Quick recovery viability score based on triage findings.
    Returns (score, assessment, recommended_phases).
    """
    score = 0
    phases = []

    # Decryptor available
    if fid.has_decryptor:
        score += 3
        phases.append("Phase 3: Check NoMoreRansom for decryptor — HIGH PRIORITY")

    # VSS status
    if not vss.deletion_likely_executed:
        score += 2
        phases.append("Phase 4: VSS snapshot recovery — likely viable")
    elif vss.vss_delete_commands_found:
        score -= 1
        phases.append("Phase 4: VSS deletion attempted — verify if successful before assuming unavailable")

    # Ransom notes only in some dirs (partial encryption indicator)
    note_dirs = set(str(Path(p).parent) for p in stats.ransom_note_paths)
    if len(note_dirs) < 5 and stats.ransom_notes_found > 0:
        score += 1
        phases.append("Phase 5: Partial encryption suspected — storage-layer recovery viable")

    # No family identified — potentially less sophisticated
    if fid.family.startswith("Unknown"):
        score += 1

    # Storage-layer forensics always recommended
    phases.append("Phase 5: Entropy-based unallocated space recovery — file carving recommended")
    phases.append("Phase 1: Memory acquisition if any systems still running — key material may be recoverable")

    if score >= 4:
        assessment = "MODERATE-HIGH — Recovery without payment likely achievable"
    elif score >= 2:
        assessment = "MODERATE — Partial recovery achievable; residual data loss expected"
    else:
        assessment = "LOW — Storage-layer forensics is primary recovery path; consult decryptor databases"

    return score, assessment, phases


# ---------------------------------------------------------------------------
# Report output
# ---------------------------------------------------------------------------
def print_triage_report(report: TriageReport) -> None:
    s = report.file_stats
    f = report.family_id
    v = report.vss_status

    print(f"\n{'='*65}")
    print(f"  RANSOMWARE TRIAGE REPORT")
    print(f"  {report.scan_timestamp}")
    print(f"{'='*65}")

    print(f"\n  TARGET:  {report.target_path}")

    print(f"\n  FILE STATISTICS")
    print(f"  Total files scanned:    {s.total_files:,}")
    print(f"  Ransom notes found:     {s.ransom_notes_found}")
    if s.ransom_note_paths:
        for p in s.ransom_note_paths[:3]:
            print(f"    → {p}")
    print(f"\n  Top extensions (by count):")
    for ext, cnt in s.top_encrypted_extensions[:10]:
        bar = "█" * min(30, int(cnt / max(1, s.total_files) * 100))
        print(f"    {ext or '(no ext)':15s}  {cnt:6,}  {bar}")

    print(f"\n  FAMILY IDENTIFICATION")
    print(f"  Detected extension:  {f.detected_extension or 'Not identified'}")
    print(f"  Ransomware family:   {f.family}")
    print(f"  Confidence:          {f.confidence}")
    print(f"  Decryptor available: {'YES — CHECK NOMORERANSOM IMMEDIATELY' if f.has_decryptor else 'No'}")
    print(f"  Double extortion:    {'Suspected' if f.double_extortion else 'Not indicated'}")
    if f.has_decryptor:
        print(f"  NoMoreRansom URL:    {f.nomoreransom_url}")

    print(f"\n  VSS / SHADOW COPY STATUS")
    print(f"  Event log analyzed:  {v.event_log_analyzed}")
    if v.vss_delete_commands_found:
        print(f"  Delete commands:     {len(v.vss_delete_commands_found)} found")
        for cmd in v.vss_delete_commands_found:
            print(f"    → {cmd}")
    print(f"  Recommendation:      {v.recommendation}")

    print(f"\n  RECOVERY ASSESSMENT")
    print(f"  Viability score:     {report.recovery_score}/6")
    print(f"  Assessment:          {report.recovery_assessment}")
    print(f"\n  Recommended actions (priority order):")
    for i, phase in enumerate(report.recommended_phases, 1):
        print(f"    {i}. {phase}")

    if report.iocs:
        print(f"\n  INDICATORS OF COMPROMISE")
        for ioc in report.iocs:
            print(f"    {ioc}")

    print(f"\n{'='*65}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Ransomware Rapid Triage Tool — DFIR Forensics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Triage an affected directory:
  python ransomware_triage.py --dir /mnt/affected_volume

  # Include Windows Event Log analysis:
  python ransomware_triage.py --dir /mnt/vol --event-log /mnt/vol/System.evtx

  # Export full report to JSON:
  python ransomware_triage.py --dir /mnt/vol --out triage_report.json

  # Limit scan depth for large volumes:
  python ransomware_triage.py --dir /mnt/vol --max-files 50000
        """,
    )
    parser.add_argument("--dir", required=True, help="Path to affected directory or volume mount point")
    parser.add_argument("--event-log", default=None, help="Path to Windows Event Log file (optional)")
    parser.add_argument("--out", default=None, help="Export triage report to JSON file")
    parser.add_argument("--max-files", type=int, default=100000,
                        help="Max files to scan (default: 100,000)")

    args = parser.parse_args()

    target = Path(args.dir)
    if not target.exists():
        print(f"[!] Directory not found: {target}", file=sys.stderr)
        sys.exit(1)

    report = TriageReport(
        scan_timestamp=datetime.now().isoformat(),
        target_path=str(target),
    )

    # Scan files
    report.file_stats = scan_directory(target, args.max_files)

    # Identify family
    report.family_id = identify_family(report.file_stats)

    # VSS analysis
    event_log = Path(args.event_log) if args.event_log else None
    report.vss_status = analyze_vss_from_strings(event_log)

    # Recovery score
    score, assessment, phases = calculate_quick_score(
        report.file_stats, report.family_id, report.vss_status
    )
    report.recovery_score = score
    report.recovery_assessment = assessment
    report.recommended_phases = phases

    # Print report
    print_triage_report(report)

    # Export JSON
    if args.out:
        out_path = Path(args.out)
        with open(out_path, "w") as f:
            json.dump(asdict(report), f, indent=2)
        print(f"\n[+] Full report exported → {out_path}")

    print(f"\n[✓] Triage complete.")


if __name__ == "__main__":
    main()
