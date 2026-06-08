#!/usr/bin/env python3
"""
recovery_viability_scorer.py — Ransomware Recovery Viability Scoring Tool
==========================================================================
Interactive CLI implementation of the Recovery Viability Score Model
described in:

  "Enterprise Ransomware Recovery: A Structured Forensic Methodology for
   System Restoration Without Ransom Payment" — D. Kharkovets, 2024

The model evaluates 9 weighted factors to produce a 0–100 viability score
and a structured, prioritized recovery roadmap.

Scoring model factors:
  F1  Ransomware family identification and decryptor availability
  F2  Backup completeness and integrity
  F3  VSS / shadow copy status
  F4  Encryption scope (% of data affected)
  F5  Time elapsed since incident (key material volatility)
  F6  Volatile memory state (live vs. powered-off systems)
  F7  Storage device physical condition
  F8  Encryption implementation quality (signs of mistakes)
  F9  Organizational recovery capability (IR resources)

Usage:
  python recovery_viability_scorer.py                  # Interactive mode
  python recovery_viability_scorer.py --json           # Machine-readable output
  python recovery_viability_scorer.py --import f.json  # Resume saved assessment
  python recovery_viability_scorer.py --batch f.json   # Batch non-interactive run

Author:  Dmitrii Kharkovets
License: MIT
Version: 1.0.0
"""

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Factor definitions
# ---------------------------------------------------------------------------
@dataclass
class Factor:
    id: str
    name: str
    weight: int           # relative weight (higher = more impact on score)
    description: str
    options: List[str]    # displayed option labels (index 0 = best outcome)
    scores: List[int]     # score per option (index 0 = best)
    guidance: List[str]   # forensic guidance per option
    selected: Optional[int] = None   # index of user's selection


# The 9 scoring factors — weights sum to 100 for normalized scoring
FACTORS: List[Factor] = [
    Factor(
        id="F1",
        name="Ransomware Family & Decryptor Availability",
        weight=20,
        description=(
            "Known decryptors exist for some families (WannaCry, Hive, CrySiS variants, "
            "several others via NoMoreRansom). Family identification drives recovery strategy."
        ),
        options=[
            "Family identified, decryptor confirmed available (NoMoreRansom)",
            "Family identified, partial decryptor or known key leak",
            "Family identified, no decryptor but encryption bugs documented",
            "Family identified, no decryptor, no known weaknesses",
            "Family not identified / novel variant",
        ],
        scores=[100, 75, 50, 25, 10],
        guidance=[
            "→ CRITICAL: Obtain decryptor from NoMoreRansom before any other action. "
              "Do not pay ransom. Image affected systems, then decrypt offline copies.",
            "→ Apply available partial decryptor to isolated copies. Document which file "
              "types recover successfully. Storage-layer recovery for remainder.",
            "→ Search academic/security research for known weaknesses in implementation. "
              "Entropy analysis may reveal IV reuse or static key patterns.",
            "→ No fast path. Prioritize: backup restore, VSS recovery, storage forensics.",
            "→ Novel variant — do NOT pay without exhausting all forensic options. "
              "Entropy analysis first; family may be misidentified.",
        ],
    ),
    Factor(
        id="F2",
        name="Backup Completeness & Integrity",
        weight=22,
        description=(
            "Offline/air-gapped backups are the gold standard. Network-connected backups "
            "are often encrypted by modern ransomware. RPO determines acceptable data loss."
        ),
        options=[
            "Offline/tape/air-gapped backup tested within 30 days — full coverage",
            "Offline backup exists, older than 30 days or partial coverage",
            "Cloud backup (separate tenant), untouched by ransomware",
            "Network backup — suspected intact (unverified)",
            "Network backup — confirmed encrypted or deleted",
            "No backups exist",
        ],
        scores=[100, 80, 65, 40, 10, 0],
        guidance=[
            "→ Restore from backup. Forensic analysis secondary unless legal/compliance "
              "requires root-cause. Estimated RTO: hours.",
            "→ Restore what is available. Supplement gap with storage forensics and "
              "VSS recovery. Document acceptable data loss window.",
            "→ Verify cloud backup tenant isolation before restore. Check for cloud "
              "encryption events in tenant audit logs.",
            "→ ISOLATE and verify backup system before mounting. Treat as potentially "
              "compromised. Image backup storage before any read.",
            "→ Backup path closed. Shift to VSS, storage forensics, decryptor search.",
            "→ No quick path. Full forensic recovery workflow required.",
        ],
    ),
    Factor(
        id="F3",
        name="VSS / Shadow Copy Status",
        weight=12,
        description=(
            "Volume Shadow Copies are the fastest recovery path on Windows systems. "
            "Most modern ransomware attempts deletion but deletion frequently fails — "
            "do not assume deletion succeeded without direct verification."
        ),
        options=[
            "VSS snapshots confirmed intact (vssadmin list shows entries)",
            "VSS status unknown — deletion attempted but unverified",
            "VSS deletion commands logged — verification not yet performed",
            "VSS confirmed deleted — no snapshots available",
            "Non-Windows system (Linux/NAS/ESXi) — VSS not applicable",
        ],
        scores=[100, 60, 40, 0, 50],
        guidance=[
            "→ HIGH PRIORITY: Mount snapshots read-only to isolated system. "
              "Extract critical data. Document all snapshot timestamps.",
            "→ Run: vssadmin list shadows — immediately. If entries exist, proceed "
              "with snapshot mount. Deletion commands often fail.",
            "→ Verify directly: vssadmin list shadows. Do not assume deletion "
              "was successful — failure rates are significant.",
            "→ VSS path closed. Proceed to storage forensics and backup paths.",
            "→ Check platform-specific snapshot systems: "
              "LVM snapshots (Linux), ZFS snapshots, VMware snapshots, "
              "NetApp/QNAP snapshot features.",
        ],
    ),
    Factor(
        id="F4",
        name="Encryption Scope",
        weight=14,
        description=(
            "Partial encryption deployments (interrupted by detection, power loss, or "
            "targeting only specific extensions) leave recoverable plaintext. "
            "Entropy scanning quantifies the recoverable fraction."
        ),
        options=[
            "Minimal encryption (<20% of volume by entropy scan)",
            "Partial encryption (20–60%), interrupted or targeted",
            "Significant encryption (60–85%)",
            "Near-complete (85–99%)",
            "Complete encryption (>99% by entropy scan)",
        ],
        scores=[90, 65, 40, 15, 5],
        guidance=[
            "→ Substantial data recoverable via entropy-guided carving. "
              "Use disk_entropy_scanner.py to map recoverable regions.",
            "→ Run entropy scan to identify plaintext islands. File carving on "
              "unencrypted regions likely to yield significant recovery.",
            "→ Targeted file carving of unencrypted blocks. Focus on high-value "
              "file types. Expect incomplete recovery.",
            "→ Limited plaintext data. Focus on file system metadata recovery "
              "and any surviving MFT/directory structure.",
            "→ Storage forensics unlikely to yield file content. Focus on "
              "decryptor acquisition and backup restoration.",
        ],
    ),
    Factor(
        id="F5",
        name="Time Elapsed Since Incident",
        weight=10,
        description=(
            "Memory artifacts (encryption key material, process artifacts) degrade rapidly. "
            "Storage artifacts persist but may be overwritten by continued system activity. "
            "Time is critical for volatile evidence."
        ),
        options=[
            "< 4 hours — systems still running or freshly powered off",
            "4–24 hours — very recent",
            "1–7 days",
            "1–4 weeks",
            "> 1 month",
        ],
        scores=[100, 80, 55, 30, 15],
        guidance=[
            "→ IMMEDIATE: Memory acquisition is highest priority. "
              "Use Magnet RAM Capture or WinPMem before any other action. "
              "Key material may be present in process memory.",
            "→ Memory acquisition still viable if systems are running. "
              "Attempt RAM capture. Prioritize volatile evidence.",
            "→ Memory artifacts likely lost. Shift focus to storage forensics, "
              "VSS, and backup recovery. Document timeline carefully.",
            "→ Volatile artifacts gone. Comprehensive storage forensics approach.",
            "→ Standard recovery workflow. All volatile artifacts exhausted.",
        ],
    ),
    Factor(
        id="F6",
        name="Volatile Memory State",
        weight=8,
        description=(
            "Live systems with ransomware processes still running or recently terminated "
            "may retain key material in memory. This factor is distinct from time elapsed "
            "because systems may have been intentionally kept running."
        ),
        options=[
            "Systems live — ransomware process still active in memory",
            "Systems live — ransomware completed but RAM not cleared",
            "Systems powered off recently (< 4h) — cold memory possible",
            "Systems rebooted after incident",
            "Systems fully powered off for > 48h",
        ],
        scores=[100, 75, 40, 15, 0],
        guidance=[
            "→ CRITICAL: Do NOT shut down. Acquire memory image immediately. "
              "Key material likely present in active process heap. "
              "Isolate network, preserve power.",
            "→ Acquire memory now. Key material may persist in heap/stack. "
              "Prioritize over all other actions.",
            "→ Cold memory recovery possible for LPDDR3/DDR3 (minutes at room temp, "
              "longer if cooled). Consider physical memory extraction if critical.",
            "→ In-memory key material likely gone. Proceed to storage path.",
            "→ All volatile artifacts exhausted.",
        ],
    ),
    Factor(
        id="F7",
        name="Storage Device Physical Condition",
        weight=6,
        description=(
            "Physical damage, firmware faults, or controller failures may require "
            "hardware intervention before forensic analysis is possible."
        ),
        options=[
            "Healthy — no physical damage, fully readable",
            "Minor issues — some bad sectors, CRC errors, but mostly readable",
            "Degraded — significant bad sectors, read errors",
            "Controller failure / firmware fault — readable with specialized hardware",
            "Physical damage — requires cleanroom or chip-off",
        ],
        scores=[100, 80, 55, 30, 15],
        guidance=[
            "→ Standard imaging workflow. Use dcfldd or Guymager with hash verification.",
            "→ Image with ddrescue (3-pass). Map bad sector locations. "
              "Prioritize known-healthy regions for forensics.",
            "→ ddrescue with domain file. Consider imaging in phases. "
              "May require multiple passes over days.",
            "→ Requires specialist equipment (PC-3000, DeepSpar, Ace Lab). "
              "Do not power-cycle without specialist guidance.",
            "→ Cleanroom / chip-off procedure required. "
              "Halt all analysis until hardware intervention complete.",
        ],
    ),
    Factor(
        id="F8",
        name="Encryption Implementation Quality",
        weight=5,
        description=(
            "Ransomware developers make implementation mistakes. IV reuse, weak key "
            "derivation, static keys, and partial initialization are documented in "
            "real deployments. Entropy patterns may reveal exploitable weaknesses."
        ),
        options=[
            "Known implementation flaw documented (IV reuse, static key, weak RNG)",
            "Entropy anomalies detected — possible weakness (requires analysis)",
            "Standard implementation, no obvious weaknesses detected",
            "Professionally implemented, no weaknesses found",
        ],
        scores=[80, 50, 25, 5],
        guidance=[
            "→ HIGH VALUE: Document flaw, search public research for exploit. "
              "Submit sample to AV vendors and NoMoreRansom. May enable bulk decryption.",
            "→ Engage cryptographic analyst. Entropy map analysis warranted. "
              "Submit samples to relevant security researchers.",
            "→ No cryptographic shortcut. Focus on other recovery vectors.",
            "→ No cryptographic shortcut available.",
        ],
    ),
    Factor(
        id="F9",
        name="Organizational Recovery Capability",
        weight=3,
        description=(
            "Available IR resources, budget, timeline, and technical expertise "
            "affect which recovery paths are feasible."
        ),
        options=[
            "Dedicated IR team + specialist forensic vendor engaged",
            "Internal IT with forensic capability + external vendor available",
            "Competent internal IT, limited forensic expertise",
            "Limited IT resources, no forensic expertise",
        ],
        scores=[100, 75, 45, 20],
        guidance=[
            "→ All recovery paths viable. Prioritize by score-weighted order.",
            "→ Most paths viable. Escalate to vendor for hardware-level work.",
            "→ Prioritize the highest-impact automated paths. "
              "Engage specialist vendor for NAND/firmware work.",
            "→ Engage external IR vendor immediately. Focus internal efforts "
              "on evidence preservation only.",
        ],
    ),
]


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
def calculate_score(factors: List[Factor]) -> Tuple[int, str, List[str]]:
    """
    Compute weighted recovery viability score (0–100) and derive
    a classification and prioritized recovery roadmap.
    """
    answered = [f for f in factors if f.selected is not None]
    if not answered:
        return 0, "Not assessed", []

    total_weight = sum(f.weight for f in answered)
    weighted_sum = sum(
        f.scores[f.selected] * f.weight
        for f in answered
        if f.selected is not None
    )
    score = int(weighted_sum / total_weight) if total_weight else 0

    if score >= 70:
        classification = "HIGH — Recovery without payment is likely achievable"
    elif score >= 45:
        classification = "MODERATE — Partial recovery achievable; residual data loss expected"
    elif score >= 25:
        classification = "LOW — Limited recovery path; specialist intervention required"
    else:
        classification = "CRITICAL LOW — Standard recovery unlikely; evaluate all options carefully"

    # Build prioritized roadmap from guidance of selected options
    roadmap = []
    for f in sorted(answered, key=lambda f: -f.weight):
        if f.selected is not None and f.scores[f.selected] < 100:
            roadmap.append(f"[{f.id}] {f.name}:  {f.guidance[f.selected]}")

    return score, classification, roadmap


# ---------------------------------------------------------------------------
# Interactive session
# ---------------------------------------------------------------------------
def clear_line() -> None:
    print()


def prompt_factor(f: Factor, idx: int, total: int) -> int:
    """Display a factor and collect user selection. Returns option index."""
    print(f"\n{'─'*65}")
    print(f"  Factor {idx}/{total} — [{f.id}]  {f.name}  (weight: {f.weight})")
    print(f"  {f.description}")
    print()
    for i, opt in enumerate(f.options):
        print(f"    {i + 1}. {opt}")
    print()

    while True:
        raw = input(f"  Select [1–{len(f.options)}]: ").strip()
        try:
            val = int(raw) - 1
            if 0 <= val < len(f.options):
                return val
        except ValueError:
            pass
        print(f"  [!] Enter a number between 1 and {len(f.options)}")


def run_interactive(factors: List[Factor]) -> None:
    print("\n" + "═" * 65)
    print("  RECOVERY VIABILITY SCORER — D. Kharkovets DFIR Tools")
    print("  Implementation of the 9-Factor Ransomware Recovery Model")
    print("═" * 65)
    print(
        "\n  This tool scores your incident across 9 weighted factors and\n"
        "  generates a prioritized recovery roadmap.\n\n"
        "  Total factors: 9 | Max score: 100\n"
        "  Answer based on what is currently confirmed, not assumed.\n"
    )

    for i, f in enumerate(factors, 1):
        f.selected = prompt_factor(f, i, len(factors))
        selected_label = f.options[f.selected]
        score = f.scores[f.selected]
        bar = "█" * (score // 5) + "░" * (20 - score // 5)
        print(f"\n    → Selected: {selected_label}")
        print(f"    → Factor score: {score:3d}/100  [{bar}]")

    # Final report
    score, classification, roadmap = calculate_score(factors)
    print_full_report(factors, score, classification, roadmap)


def print_full_report(
    factors: List[Factor],
    score: int,
    classification: str,
    roadmap: List[str],
) -> None:
    bar_len = score // 2
    bar = "█" * bar_len + "░" * (50 - bar_len)

    print(f"\n{'═'*65}")
    print(f"  RECOVERY VIABILITY ASSESSMENT REPORT")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'═'*65}")

    print(f"\n  OVERALL SCORE:  {score}/100")
    print(f"  [{bar}]  {score}%")
    print(f"\n  CLASSIFICATION: {classification}")

    print(f"\n  FACTOR BREAKDOWN:")
    print(f"  {'Factor':<42} {'Score':>5}  {'Weight':>6}  {'Weighted':>8}")
    print(f"  {'─'*42} {'─'*5}  {'─'*6}  {'─'*8}")
    for f in factors:
        if f.selected is not None:
            s = f.scores[f.selected]
            w = f.weight
            wt = s * w / 100
            bar = "▓" * int(s // 10)
            print(f"  [{f.id}] {f.name[:36]:<36}  {s:>5}  {w:>5}%  {wt:>7.1f}")

    if roadmap:
        print(f"\n  PRIORITIZED RECOVERY ROADMAP (high impact first):")
        for i, action in enumerate(roadmap, 1):
            print(f"\n  {i}. {action}")

    print(f"\n{'═'*65}")
    print(
        "\n  REFERENCE: NoMoreRansom decryptor database:\n"
        "  https://www.nomoreransom.org/en/decryption-tools.html\n"
    )


# ---------------------------------------------------------------------------
# JSON export / import
# ---------------------------------------------------------------------------
def export_json(factors: List[Factor], score: int, classification: str, path: Path) -> None:
    data = {
        "timestamp": datetime.now().isoformat(),
        "score": score,
        "classification": classification,
        "factors": [
            {
                "id": f.id,
                "name": f.name,
                "weight": f.weight,
                "selected_option": f.options[f.selected] if f.selected is not None else None,
                "option_score": f.scores[f.selected] if f.selected is not None else None,
            }
            for f in factors
        ],
    }
    path.write_text(json.dumps(data, indent=2))
    print(f"\n[+] Assessment saved → {path}")


def load_json_answers(path: Path) -> Dict[str, int]:
    """Load saved factor selections from JSON file. Returns {factor_id: option_index}."""
    data = json.loads(path.read_text())
    answers = {}
    for item in data.get("factors", []):
        fid = item.get("id")
        label = item.get("selected_option")
        if fid and label:
            # Find matching factor and option index
            for f in FACTORS:
                if f.id == fid:
                    for idx, opt in enumerate(f.options):
                        if opt == label:
                            answers[fid] = idx
                            break
    return answers


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Ransomware Recovery Viability Scorer — DFIR Forensics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive assessment:
  python recovery_viability_scorer.py

  # Interactive + save to JSON:
  python recovery_viability_scorer.py --save assessment_2024.json

  # Batch mode (import answers, print report):
  python recovery_viability_scorer.py --batch assessment_2024.json

  # Machine-readable output only:
  python recovery_viability_scorer.py --json
        """,
    )
    parser.add_argument("--save", default=None, help="Save assessment to JSON file")
    parser.add_argument("--batch", default=None,
                        help="Non-interactive: load answers from JSON and print report")
    parser.add_argument("--json", action="store_true",
                        help="Output report in JSON format instead of text")

    args = parser.parse_args()

    factors = FACTORS  # Use module-level factor definitions

    if args.batch:
        batch_path = Path(args.batch)
        if not batch_path.exists():
            print(f"[!] File not found: {batch_path}", file=sys.stderr)
            sys.exit(1)
        answers = load_json_answers(batch_path)
        for f in factors:
            if f.id in answers:
                f.selected = answers[f.id]
    else:
        run_interactive(factors)

    score, classification, roadmap = calculate_score(factors)

    if args.json:
        data = {
            "score": score,
            "classification": classification,
            "roadmap": roadmap,
            "factors": [
                {
                    "id": f.id,
                    "name": f.name,
                    "selected": f.options[f.selected] if f.selected is not None else None,
                    "score": f.scores[f.selected] if f.selected is not None else None,
                    "weight": f.weight,
                    "guidance": f.guidance[f.selected] if f.selected is not None else None,
                }
                for f in factors
            ],
        }
        print(json.dumps(data, indent=2))

    if args.save:
        export_json(factors, score, classification, Path(args.save))

    if not args.batch and not args.json:
        # Interactive mode already printed the report in run_interactive()
        pass
    elif args.batch:
        print_full_report(factors, score, classification, roadmap)


if __name__ == "__main__":
    main()
