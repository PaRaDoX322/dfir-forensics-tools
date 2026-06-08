# dfir-forensics-tools

A collection of Python CLI tools for digital forensics and incident response, focused on NAND flash analysis and ransomware recovery. Built from fieldwork on real cases — these scripts implement techniques I use in practice, not just theoretical approaches.

---

## Tools

### `nand_oob_analyzer.py` — NAND Flash OOB / L2P Analyzer

Parses Out-of-Band (OOB / spare area) data from raw NAND dumps to reconstruct the Logical-to-Physical (L2P) page mapping without relying on the storage controller. Useful when the original flash controller is unavailable, damaged, or locked.

**When to use it:**
- Chip-off recovery from eMMC, NAND, or SD-card media
- Controller firmware fault or wear-threshold lock
- Post-mortem analysis of failed SSDs
- Validation of existing L2P maps against raw OOB data

**Highlights:**
- Auto-detects page geometry (2KB/4KB/8KB) and OOB layout (Samsung, Hynix, Toshiba, SanDisk, generic)
- Resolves mapping conflicts using erase count fields
- Exports full page records and clean L2P map to CSV
- Shannon entropy per page for identifying encrypted or compressed blocks

```bash
# Analyze a 64GB eMMC chip-off dump
python nand_oob_analyzer.py dump.bin --page-size 4096 --oob-size 128

# Auto-detect geometry, export L2P map
python nand_oob_analyzer.py dump.bin --auto --out pages.csv --l2p-out l2p_map.csv

# Verbose mode shows every OOB field
python nand_oob_analyzer.py dump.bin --verbose
```

---

### `disk_entropy_scanner.py` — Disk Entropy Scanner

Scans disk images sector-by-sector using Shannon entropy analysis to locate encrypted regions, detect partial encryption boundaries, and identify plaintext islands within otherwise-encrypted volumes. A core tool for quantifying recovery scope after ransomware incidents.

**When to use it:**
- Determine what percentage of a volume is recoverable
- Find the exact offset where ransomware stopped encrypting
- Locate unencrypted data blocks within an encrypted region
- Detect file system signatures that survived partial encryption

**Highlights:**
- Configurable block size (512B to 64KB)
- Classifies blocks: `zero_fill / plaintext / compressed_or_mixed / encrypted`
- Detects encryption start/end boundaries automatically
- ASCII entropy map for quick visual assessment
- File system signature detection at block boundaries
- CSV export of full per-block records

```bash
# Quick scan with defaults (4KB blocks, threshold 7.5 bits/byte)
python disk_entropy_scanner.py image.dd

# Fine-grained scan with map output
python disk_entropy_scanner.py image.dd --block-size 512 --map

# Export block records for further analysis
python disk_entropy_scanner.py image.dd --out entropy.csv --map-file entropy_map.txt

# Scan a specific range (e.g., first 10GB only)
python disk_entropy_scanner.py image.dd --end 10737418240
```

---

### `ransomware_triage.py` — Ransomware Rapid Triage Tool

First-response tool for ransomware incidents. Scans an affected directory tree, identifies the ransomware family from extension patterns and ransom notes, checks for VSS deletion artifacts, and produces a structured triage report with prioritized recovery recommendations.

**When to use it:**
- First 30 minutes of a ransomware incident response
- Rapid family identification before pulling in senior resources
- Quantifying scope: how many files, which extensions, how widespread
- Generating a triage artifact for the incident report

**Highlights:**
- 25+ ransomware family signatures (LockBit, BlackCat/ALPHV, REvil, Hive, WannaCry, etc.)
- Ransom note detection across 15+ naming patterns
- VSS deletion artifact search in Windows Event Log files
- MD5 fingerprints of sample encrypted files for deduplication
- JSON export for integration into IR workflows

```bash
# Triage an affected directory
python ransomware_triage.py --dir /mnt/affected_volume

# Include Windows Event Log analysis
python ransomware_triage.py --dir /mnt/vol --event-log System.evtx

# Export full triage report to JSON
python ransomware_triage.py --dir /mnt/vol --out triage_report.json
```

---

### `recovery_viability_scorer.py` — Recovery Viability Scorer

Interactive CLI implementation of the 9-Factor Recovery Viability Score Model. Walks through the key decision factors for a ransomware incident, weights each answer, and produces a 0–100 score with a prioritized recovery roadmap. Designed to structure the initial decision-making session between IR lead and client.

**The 9 factors:**
| Factor | Weight | What it measures |
|--------|--------|-----------------|
| F1 — Family & Decryptor | 20% | Known decryptors, documented weaknesses |
| F2 — Backup Completeness | 22% | Offline/cloud/network backup status |
| F3 — VSS Status | 12% | Shadow copy availability |
| F4 — Encryption Scope | 14% | % of volume affected |
| F5 — Time Elapsed | 10% | Memory artifact window |
| F6 — Memory State | 8% | Live system / volatile evidence |
| F7 — Storage Condition | 6% | Physical device health |
| F8 — Encryption Quality | 5% | Implementation flaws |
| F9 — IR Capability | 3% | Available resources |

```bash
# Interactive assessment
python recovery_viability_scorer.py

# Save results to JSON
python recovery_viability_scorer.py --save assessment.json

# Batch mode — load answers from JSON
python recovery_viability_scorer.py --batch assessment.json

# Machine-readable JSON output
python recovery_viability_scorer.py --json
```

**Score interpretation:**
- `70–100` → Recovery without payment likely achievable
- `45–69`  → Partial recovery achievable; residual data loss expected  
- `25–44`  → Limited recovery path; specialist intervention required
- `0–24`   → Critical low; evaluate all options carefully

---

## Background

These tools were developed over several years working DFIR cases that involved hardware-level storage forensics and ransomware incident response. Standard tools handle the common cases well — these fill specific gaps I kept running into:

- **L2P reconstruction:** Most recovery tools assume a working controller. Chip-off cases where the controller is dead or locked require parsing OOB directly.
- **Encryption scope:** Clients need to know *how much* of their data is actually gone vs. recoverable before making decisions. Entropy scanning gives that answer in minutes.
- **Triage structure:** The first 30–60 minutes of a ransomware IR are chaotic. Having a structured triage that produces a documentable artifact helps immediately.
- **Viability scoring:** The decision of whether to attempt recovery vs. pay is genuinely hard and context-dependent. A structured scoring session with the client forces the right questions.

The methodology behind these tools is described in more detail in the companion white papers:
- *"NAND Flash Memory Forensics: Bypassing Controller Dependencies in Embedded Storage Recovery"*
- *"Enterprise Ransomware Recovery: A Structured Forensic Methodology for System Restoration Without Ransom Payment"*

---

## Requirements

Python 3.8+ with standard library only. No external dependencies required.

```bash
# Optional (Windows terminal color support only)
pip install -r requirements.txt
```

---

## Usage notes

- All tools operate on **copies** of evidence — never run on original media.
- NAND dumps should be acquired with `nanddump` (Linux MTD layer) or specialist chip-off hardware.
- Disk images should be acquired with `dcfldd`, `Guymager`, or `FTK Imager` before analysis.
- For live system memory acquisition, use Magnet RAM Capture or WinPMem before running any of these tools.

---

## License

MIT License — see LICENSE file.

---

## Author

Dmitrii Kharkovets — DFIR / Hardware Forensics  
[LinkedIn](https://linkedin.com/in/dmitrii-kharkovets)
