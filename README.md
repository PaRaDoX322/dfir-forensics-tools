# DFIR Forensics Tools

**Digital Forensics & Incident Response — Open-Source Methodology Toolkit**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![Field: DFIR](https://img.shields.io/badge/Field-DFIR%20%7C%20Hardware%20Forensics-darkblue)]()

---

## Overview

This repository contains field-validated tools for digital forensics practitioners working at the intersection of hardware storage forensics and enterprise incident response. The tooling addresses scenarios where conventional forensic acquisition tools are insufficient — controller-locked NAND devices, partially encrypted ransomware volumes, and degraded storage media requiring physical-layer analysis before logical recovery.

All tools are derived from production casework and research documented in the accompanying white papers.

---

## Tools

### [`nand_oob_analyzer.py`](nand_oob_analyzer.py)
**NAND Flash Out-of-Band Metadata Analyzer**

Analyzes raw NAND flash dumps to extract and decode Out-of-Band (OOB) spare area metadata without access to the original storage controller. Reconstructs the logical-to-physical page mapping (FTL) from OOB byte patterns, supporting multiple common OOB layouts.

**Use case:** Chip-off recovery from controller-locked NAND devices (SSDs, mobile phones, SD cards, embedded storage) where the controller firmware has failed or entered a locked state.

```bash
python nand_oob_analyzer.py --dump device.bin --page-size 2048 --oob-size 64 --output mapping.json
```

---

### [`disk_entropy_scanner.py`](disk_entropy_scanner.py)
**Shannon Entropy-Based Encryption Coverage Scanner**

Performs block-by-block Shannon entropy analysis of disk images to map encryption coverage. Distinguishes encrypted regions (entropy ~8.0 bits/byte), plaintext regions (variable, <7.5), and zero-filled blocks (entropy 0). Generates an entropy map and coverage report.

**Use case:** First-hour ransomware triage to determine what percentage of a volume is actually encrypted — critical for deciding whether forensic recovery is viable before committing to a response strategy.

```bash
python disk_entropy_scanner.py --image volume.dd --block-size 512 --output entropy_report.json
```

---

### [`recovery_viability_scorer.py`](recovery_viability_scorer.py)
**Ransomware Recovery Viability Scorer (RVS)**

Implements a 9-factor quantitative scoring model for assessing ransomware recovery viability. Factors include: VSS integrity, backup architecture, encryption coverage, known decryptor availability, memory acquisition status, ransomware family identification, file extension targeting scope, partial encryption detection, and network reach of the incident.

**Use case:** Structured first-assessment framework for IR practitioners advising organizations on whether to pursue forensic recovery, pay the ransom, or restore from backup — before making an irreversible decision.

```bash
python recovery_viability_scorer.py --interactive
# or
python recovery_viability_scorer.py --config case_params.json
```

---

### [`ransomware_triage.py`](ransomware_triage.py)
**Ransomware Incident Triage Workflow**

Automated first-hour triage script for Windows and Linux ransomware incidents. Performs: network interface status check, VSS snapshot enumeration, running process and network connection capture, entropy sampling of affected volumes, and known ransomware family identification via ransom note signature matching.

**Use case:** Standardized triage automation for IR teams to preserve evidence and gather initial assessment data in the first 30 minutes of a ransomware response.

```bash
python ransomware_triage.py --target \\AFFECTED-HOST --output triage_report/
```

---

## Research

This toolset is accompanied by three technical white papers documenting the underlying methodology:

| White Paper | Topic | Status |
|-------------|-------|--------|
| [HDD Corrosive-Environment Recovery Methodology](docs/WhitePaper_HDD_Seawater_Recovery.pdf) | PCB reconstruction, ROM extraction, firmware adaptive transfer for seawater-damaged HDDs | Published |
| [NAND Flash Forensics: Controller-Locked Device Recovery](docs/WhitePaper_NAND_Forensics.pdf) | Chip-off acquisition, OOB analysis, FTL reconstruction methodology | Published |
| [Enterprise Ransomware Recovery Methodology](docs/WhitePaper_RansomwareRecovery.pdf) | RVS framework, entropy triage, VSS recovery, structured IR workflow | Published |

---

## Author

**Dmitrii Kharkovets**  
Digital Forensics & Incident Response Specialist  
Hardware Forensics | Enterprise Data Recovery | Cyber Resilience Research

- Email: dimas8598@gmail.com  
- LinkedIn: [linkedin.com/in/dmitrii-kharkovets](https://linkedin.com/in/dmitrii-kharkovets)  
- Research: [Forensic Focus](https://forensicfocus.com) | [ResearchGate](https://researchgate.net)

### Background

Five years of independent DFIR practice focused on storage-layer forensics and enterprise incident response. Specializations:

- **NAND flash forensics:** Test-point bypass, chip-off desoldering, OOB metadata reverse engineering, FTL reconstruction for controller-locked devices with no published documentation
- **Hardware-level HDD recovery:** PCB electronics repair, ROM extraction, firmware adaptation, corrosive-environment damage protocols
- **Ransomware recovery:** Entropy-based triage, VSS integrity verification, memory forensics, structured recovery viability assessment
- **Open-source methodology:** Practitioner-accessible tooling and published frameworks for the DFIR community

---

## Documentation

```
dfir-forensics-tools/
├── nand_oob_analyzer.py          # NAND OOB metadata analysis
├── disk_entropy_scanner.py       # Entropy-based encryption coverage detection
├── recovery_viability_scorer.py  # 9-factor ransomware recovery viability model
├── ransomware_triage.py          # First-hour IR triage automation
├── docs/
│   ├── WhitePaper_HDD_Seawater_Recovery.pdf
│   ├── WhitePaper_NAND_Forensics.pdf
│   └── WhitePaper_RansomwareRecovery.pdf
├── LICENSE
└── README.md
```

---

## Usage Notes

These tools are designed for use by qualified forensic practitioners. They are provided as methodology implementations — not as plug-and-play solutions. Hardware forensics in particular (chip-off, test-point access, PCB rework) requires physical competencies and appropriate equipment that are outside the scope of software tooling.

**Before using `nand_oob_analyzer.py`:** Read the accompanying NAND Forensics white paper for OOB layout background. The tool requires an understanding of NAND architecture to interpret its output correctly.

**Before using `disk_entropy_scanner.py`:** Image the affected volume forensically (write-blocker or `dd`-equivalent) before running the scan. Never scan a live, potentially still-running ransomware process.

---

## License

MIT License — see [LICENSE](LICENSE). 

Tools may be freely used, modified, and distributed with attribution.

---

## Contributing

Issues and pull requests welcome. If you've encountered a NAND controller OOB layout not covered by `nand_oob_analyzer.py`, opening an issue with the chip markings and a hex sample of the spare area is the most useful contribution.
