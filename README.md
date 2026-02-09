# 🔍  Digital Forensics Toolkit

<div align="center">

![Forensics Banner](https://raw.githubusercontent.com/mesquidar/ForensicsTools/master/FORENSICS%20TOOLS.png)

[![Awesome](https://awesome.re/badge.svg)](https://awesome.re)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**A curated arsenal of cutting-edge forensic investigation tools, frameworks, and resources for incident response, malware analysis, and digital evidence acquisition.**

[🚀 Quick Start](#-quick-start) • [🛠️ Tools](#-tools-by-category) • [📚 Learning](#-learning-resources) • [🎯 CTF Challenges](#-capture-the-flag-ctf-challenges) • [🤝 Contributing](#-contributing)

---

</div>

## 📖 Table of Contents

- [🎯 Overview](#-overview)
- [⭐ Featured Collections](#-featured-collections)
- [🛠️ Tools by Category](#-tools-by-category)
  - [💿 Forensic Distributions](#-forensic-distributions)
  - [🏗️ Investigation Frameworks](#️-investigation-frameworks)
  - [⚡ Live Forensics & IR](#-live-forensics--incident-response)
  - [📦 Evidence Acquisition](#-evidence-acquisition)
  - [💾 Disk Imaging & Cloning](#-disk-imaging--cloning)
  - [🔪 Data Carving & Recovery](#-data-carving--recovery)
  - [🧠 Memory Forensics](#-memory-forensics)
  - [🌐 Network Forensics](#-network-forensics)
  - [🪟 Windows Artifact Analysis](#-windows-artifact-analysis)
  - [🍎 macOS Forensics](#-macos-forensics)
  - [📱 Mobile Device Forensics](#-mobile-device-forensics)
  - [🐳 Container Forensics](#-container-forensics)
  - [🌐 Browser Forensics](#-browser-forensics)
  - [⏱️ Timeline Analysis](#️-timeline-analysis)
  - [💽 Disk Image Management](#-disk-image-management)
  - [🔓 Cryptanalysis & Decryption](#-cryptanalysis--decryption)
  - [📊 Case Management](#-case-management)
  - [🖼️ Image Analysis](#️-image-analysis)
  - [🕵️ Steganography](#️-steganography)
  - [📄 Metadata Extraction](#-metadata-extraction)
  - [🌍 Web Forensics](#-web-forensics)
- [📚 Learning Resources](#-learning-resources)
- [🎯 Capture The Flag (CTF) Challenges](#-capture-the-flag-ctf-challenges)
- [📚 Essential Reading](#-essential-reading)
- [🗂️ Datasets & Corpora](#️-datasets--corpora)
- [🐦 Community & Updates](#-community--updates)
- [🔗 Related Resources](#-related-resources)
- [🤝 Contributing](#-contributing)
- [📜 License](#-license)

---

## 🎯 Overview

This repository serves as a comprehensive knowledge base for digital forensics investigators, incident responders, security researchers, and cybersecurity professionals. Whether you're analyzing compromised systems, recovering deleted evidence, or hunting advanced persistent threats, this arsenal provides the tools you need.

**Key Focus Areas:**
- 🔍 Dead-box forensics & evidence preservation
- ⚡ Live system analysis & incident response
- 🧠 Memory dump analysis & malware detection
- 📱 Mobile device & cloud forensics
- 🌐 Network traffic analysis & threat hunting
- 🔐 Encrypted data recovery & password cracking

---

## ⭐ Featured Collections

### 🎓 Professional Resource Databases

| Resource | Description | Best For |
|----------|-------------|----------|
| **[DFIR - The Definitive Compendium](https://aboutdfir.com)** | Comprehensive index of certifications, books, blogs, and challenges | Career development & continuous learning |
| **[DFIR SQL Query Repository](https://github.com/abrignoni/DFIR-SQL-Query-Repo)** | Platform-specific SQL templates for forensic analysis | Database artifact extraction |
| **[DFIR.training](https://www.dfir.training/)** | Curated database of events, tools, and training | Skill development & networking |
| **[ForensicArtifacts.com](https://github.com/ForensicArtifacts/artifacts)** ⭐ | Machine-readable artifact knowledge base | Automated artifact collection |

### 📖 Reference Materials

- **[Wikipedia - Digital Forensics Tools](https://en.wikipedia.org/wiki/List_of_digital_forensics_tools)** - Industry overview
- **[Eric Zimmerman's Tools](https://ericzimmerman.github.io/#!index.md)** - Essential Windows forensics utilities

---

## 🛠️ Tools by Category

### 💿 Forensic Distributions

Pre-configured Linux distributions with forensic tools pre-installed for immediate deployment.

| Distribution | Platform | Specialization | Key Features |
|--------------|----------|----------------|--------------|
| **[SIFT Workstation](https://github.com/teamdfir/sift)** ⭐ | Ubuntu | General forensics | Industry standard, extensive toolkit |
| **[CAINE](https://www.caine-live.net/)** | Ubuntu | General forensics | User-friendly GUI, write-blocking |
| **[Remnux](https://remnux.org/)** | Ubuntu | Malware analysis | Reverse engineering focused |
| **[Tsurugi Linux](https://tsurugi-linux.org/)** | Ubuntu | DFIR | Japanese-developed, comprehensive |
| **[Paladin](https://sumuri.com/software/paladin/)** | Ubuntu | Forensically sound imaging | Simplified evidence collection |
| **[Bitscout](https://github.com/vitaly-kamluk/bitscout)** | Custom | Remote forensics | LiveCD for remote investigation |
| **[Santoku](https://santoku-linux.com/)** | Ubuntu | Mobile forensics | Android/iOS analysis |
| **[Predator OS](http://predator-os.ir/)** | Debian | Penetration testing | Security auditing tools |
| **[WinFE](https://www.winfe.net/home)** | Windows | Windows forensics | Windows PE environment |
| **[GRML-Forensic](https://grml-forensic.org/)** | Debian | Command-line forensics | Lightweight, fast boot |

**💡 Pro Tip:** Use SIFT for general investigations, Remnux for malware analysis, and Bitscout for remote acquisitions.

---

### 🏗️ Investigation Frameworks

End-to-end platforms for managing complex investigations.

#### 🔥 Enterprise-Grade Frameworks

- **[Autopsy](http://www.sleuthkit.org/autopsy/)** ⭐ - GUI for The Sleuth Kit with timeline analysis, keyword search, and registry parsing
- **[The Sleuth Kit](https://github.com/sleuthkit/sleuthkit)** ⭐ - Command-line tools for low-level forensic analysis
- **[IPED](https://github.com/sepinf-inc/IPED)** - Brazilian Federal Police's indexing and processing tool with OCR and machine learning
- **[Kuiper](https://github.com/DFIRKuiper/Kuiper)** - Digital investigation platform with artifact parsers and timeline generation

#### ⚙️ Specialized Frameworks

- **[DFF (Digital Forensics Framework)](https://github.com/arxsys/dff)** - Modular framework with Python scripting
- **[Turbinia](https://github.com/google/turbinia)** - Cloud-native forensic workload orchestration (Google)
- **[PowerForensics](https://github.com/Invoke-IR/PowerForensics)** - PowerShell framework for live disk analysis
- **[RegRippy](https://github.com/airbus-cert/regrippy)** - Windows Registry extraction framework

#### 🛡️ Threat Intelligence Integration

- **[IntelMQ](https://github.com/certtools/intelmq)** - Security feed collection and processing
- **[Laika BOSS](https://github.com/lmco/laikaboss)** - Object scanner and intrusion detection (Lockheed Martin)

---

### ⚡ Live Forensics & Incident Response

Tools for analyzing running systems without shutting them down.

| Tool | Platform | Use Case | Key Capability |
|------|----------|----------|----------------|
| **[Velociraptor](https://github.com/Velocidex/velociraptor)** | Cross-platform | Endpoint visibility | VQL querying, hunting |
| **[GRR Rapid Response](https://github.com/google/grr)** | Cross-platform | Remote live forensics | Agent-based collection |
| **[osquery](https://github.com/osquery/osquery)** | Cross-platform | System analytics | SQL-based OS queries |
| **[MIG](https://github.com/mozilla/mig)** | Cross-platform | Distributed forensics | Real-time investigation |
| **[Linux Explorer](https://github.com/intezer/linux-explorer)** | Linux | Live triage | Web-based interface |

**🎯 Use Case Examples:**
- **Velociraptor:** Hunt for IOCs across 1000+ endpoints simultaneously
- **GRR:** Remotely collect memory dumps from compromised systems
- **osquery:** Query all processes, network connections, and autoruns in real-time

---

### 📦 Evidence Acquisition

Tools for collecting forensic evidence from systems and devices.

#### 💻 System-Level Acquisition

- **[DFIR ORC](https://dfir-orc.github.io/)** - Windows artifact collection framework with configurable modules
- **[Artifact Collector](https://github.com/forensicanalysis/artifactcollector)** - Cross-platform artifact collection agent
- **[ArtifactExtractor](https://github.com/Silv3rHorn/ArtifactExtractor)** - VSC and source image extraction
- **[FastIR Collector](https://github.com/SekoiaLab/Fastir_Collector)** - Windows triage collection

#### 🧠 Memory Acquisition

- **[AVML](https://github.com/microsoft/avml)** - Portable Linux memory acquisition (Microsoft)
- **[LiME](https://github.com/504ensicsLabs/LiME)** - Loadable Kernel Module for Linux memory dumps
- **[Magnet RAM Capture](https://www.magnetforensics.com/resources/magnet-ram-capture/)** - Free Windows memory imaging
- **[Belkasoft RAM Capturer](https://belkasoft.com/ram-capturer)** ⭐ - Windows volatile memory dump tool
- **[DumpIt](https://www.comae.com/dumpit/)** - Fast Windows memory acquisition
- **[FireEye Memoryze](https://www.fireeye.com/services/freeware/memoryze.html)** - Memory analysis and acquisition

#### 📱 Mobile & Cloud Acquisition

- **[UFADE](https://github.com/prosch88/UFADE)** - Apple device extraction (iOS backups)
- **[Fuji](https://github.com/Lazza/Fuji)** - Logical acquisition of Mac computers

**⚡ Quick Win:** Use AVML for Linux servers, Belkasoft RAM Capturer for Windows workstations, and UFADE for iPhones.

---

### 💾 Disk Imaging & Cloning

Create forensically sound copies of storage media.

| Tool | Platform | Format Support | Features |
|------|----------|----------------|----------|
| **[Guymager](https://guymager.sourceforge.io/)** ⭐ | Linux | E01, AFF, DD | Multi-threaded, GUI |
| **[FTK Imager](https://accessdata.com/product-download/ftk-imager-version-3-4-3/)** | Windows | E01, DD, AD1 | Free, industry standard |
| **[Belkasoft Image](https://belkasoft.com/es/bat)** ⭐ | Cross-platform | Multiple formats | HDD, mobile, cloud |
| **[dc3dd](https://sourceforge.net/projects/dc3dd/)** | Linux | DD | Enhanced dd with hashing |
| **[dcfldd](https://github.com/adulau/dcfldd)** | Linux | DD | Forensic dd fork |

**📋 Best Practices:**
1. Always verify hash values (MD5, SHA-1, SHA-256)
2. Use write blockers for physical drives
3. Document chain of custody
4. Create working copies, preserve originals

---

### 🔪 Data Carving & Recovery

Extract files and artifacts from unallocated space.

- **[PhotoRec](https://www.cgsecurity.org/wiki/PhotoRec)** ⭐ - File carving for 480+ file formats
- **[bulk_extractor](https://github.com/simsong/bulk_extractor)** - Extract emails, credit cards, URLs, and more
- **[Scalpel](https://github.com/sleuthkit/scalpel)** - Fast file carver with header/footer detection
- **[bstrings](https://github.com/EricZimmerman/bstrings)** - Enhanced string extraction (Unicode support)
- **[FLOSS](https://github.com/fireeye/flare-floss)** - Deobfuscate strings from malware binaries
- **[swap_digger](https://github.com/sevagas/swap_digger)** - Linux swap file analysis and credential extraction

**🔍 Investigation Workflow:**
```bash
# 1. Carve deleted files
photorec /d recovered_files /cmd image.dd

# 2. Extract strings and IOCs
bulk_extractor -o output image.dd

# 3. Analyze swap files for credentials
./swap_digger.sh -x /dev/sda5
```

---

### 🧠 Memory Forensics

Analyze RAM dumps to find malware, credentials, and running processes.

#### 🏆 Core Frameworks

- **[Volatility 3](https://github.com/volatilityfoundation/volatility3)** ⭐ - The industry standard for memory analysis
- **[Volatility 2](https://github.com/volatilityfoundation/volatility)** - Legacy version with extensive plugin support
- **[Rekall](https://github.com/google/rekall)** - Advanced memory forensics framework (Google)
- **[MemProcFS](https://github.com/ufrisk/MemProcFS)** - Memory as a virtual file system

#### 🔧 Specialized Tools

- **[VolUtility](https://github.com/kevthehermit/VolUtility)** - Web interface for Volatility
- **[inVtero.net](https://github.com/ShaneK2/inVtero.net)** - High-speed Windows x64 memory analysis
- **[KeeFarce](https://github.com/denandz/KeeFarce)** - Extract KeePass passwords from memory
- **[FireEye RedLine](https://www.fireeye.com/services/freeware/redline.html)** - Host investigation with memory analysis

**💉 Common Volatility Commands:**
```bash
# Identify profile
vol.py -f memory.dmp imageinfo

# List processes
vol.py -f memory.dmp --profile=Win10x64 pslist

# Detect malware
vol.py -f memory.dmp --profile=Win10x64 malfind

# Extract process memory
vol.py -f memory.dmp --profile=Win10x64 memdump -p 1234 -D output/
```

---

### 🌐 Network Forensics

Capture and analyze network traffic for evidence of intrusions.

| Tool | Purpose | Key Features |
|------|---------|--------------|
| **[Wireshark](https://www.wireshark.org/)** ⭐ | Packet analysis | 3000+ protocols, deep inspection |
| **[NetworkMiner](https://www.netresec.com/?page=Networkminer)** | Network forensics | File extraction, credential harvesting |
| **[Xplico](https://www.xplico.org/)** | Traffic reconstruction | Email, VoIP, HTTP reconstruction |
| **[Zeek (Bro)](https://zeek.org/)** | Network monitoring | Scriptable, metadata extraction |

**🎯 Investigation Scenarios:**
- **Data Exfiltration:** Track large file transfers with NetworkMiner
- **Credential Theft:** Extract HTTP POST data with Wireshark filters
- **C2 Communication:** Identify beaconing with Zeek scripts

---

### 🪟 Windows Artifact Analysis

Parse Windows-specific evidence (Registry, Event Logs, MFT, Prefetch, etc.).

#### 🔑 Registry Analysis

- **[RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)** - Automated registry parsing with plugins
- **[FRED](https://www.pinguin.lu/fred)** - Cross-platform registry hive editor
- **[Registry Explorer](https://ericzimmerman.github.io/#!index.md)** - Eric Zimmerman's registry viewer with bookmarks

#### 📊 NTFS & MFT Analysis

- **[MFTECmd](https://github.com/EricZimmerman/MFTECmd)** - Parse $MFT with CSV output
- **[NTFSTool](https://github.com/thewhiteninja/ntfstool)** - Complete NTFS forensics toolkit
- **[python-ntfs](https://github.com/williballenthin/python-ntfs)** - Python library for NTFS analysis
- **[NTFS USN Journal Parser](https://github.com/PoorBillionaire/USN-Journal-Parser)** - Track file system changes
- **[RecuperaBit](https://github.com/Lazza/RecuperaBit)** - Reconstruct NTFS file systems

#### 📜 Event Log Analysis

- **[EvtxECmd](https://github.com/EricZimmerman/evtx)** - Parse Windows Event Logs (.evtx)
- **[python-evtx](https://github.com/williballenthin/python-evt)** - Python parser for .evt files
- **[LogonTracer](https://github.com/JPCERTCC/LogonTracer)** - Visualize Windows logon events
- **[Chainsaw](https://github.com/WithSecureLabs/chainsaw)** - Rapidly search and hunt through event logs

#### 🔍 Other Windows Artifacts

- **[PECmd](https://github.com/EricZimmerman/PECmd)** - Prefetch parser
- **[JLECmd](https://github.com/EricZimmerman/JLECmd)** - Jump List parser
- **[LECmd](https://github.com/EricZimmerman/LECmd)** - LNK file parser
- **[AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)** - Amcache.hve analysis
- **[LastActivityView](https://www.nirsoft.net/utils/computer_activity_view.html)** - Aggregate user activity timeline
- **[CrowdResponse](https://www.crowdstrike.com/resources/community-tools/crowdresponse/)** - Host data collection

**📂 Key Artifact Locations:**
```
Registry Hives:
  C:\Windows\System32\config\SAM
  C:\Windows\System32\config\SYSTEM
  C:\Windows\System32\config\SOFTWARE
  C:\Users\{User}\NTUSER.DAT

Event Logs:
  C:\Windows\System32\winevt\Logs\*.evtx

MFT:
  C:\$MFT

Prefetch:
  C:\Windows\Prefetch\*.pf
```

---

### 🍎 macOS Forensics

Specialized tools for analyzing Apple Mac systems.

#### 📁 File System Analysis

- **[APFS Fuse](https://github.com/sgan81/apfs-fuse)** - Read-only APFS driver for Linux
- **[Disk Arbitrator](https://github.com/aburgh/Disk-Arbitrator)** - Prevent auto-mounting during forensic imaging

#### 🔍 Artifact Parsers

- **[mac_apt](https://github.com/ydkhatri/mac_apt)** - macOS Artifact Parsing Tool
- **[APOLLO](https://github.com/mac4n6/APOLLO)** - Apple Pattern of Life Lazy Output
- **[MacLocationsScraper](https://github.com/mac4n6/Mac-Locations-Scraper)** - Extract location database
- **[macMRU Parser](https://github.com/mac4n6/macMRU-Parser)** - Most Recently Used files parser
- **[OSXCollector](https://github.com/Yelp/osxcollector)** - Live system triage (Yelp)
- **[OSXAuditor](https://github.com/jipegit/OSXAuditor)** - Analyze system artifacts

#### 📚 Reference Materials

- **[MAC OSX Artifact Locations](https://docs.google.com/spreadsheets/d/1X2Hu0NE2ptdRj023OVWIGp5dqZOw-CfxHLOW_GNGpX8/)** - Comprehensive artifact spreadsheet

**🍏 Key macOS Artifacts:**
```
/private/var/db/locationd/          # Location services
/Library/Preferences/               # System preferences
~/Library/Application Support/      # App data
/var/log/system.log                 # System logs
~/.bash_history                     # Command history
```

---

### 📱 Mobile Device Forensics

Extract and analyze evidence from smartphones and tablets.

#### 🤖 Android Analysis

- **[ALEAPP](https://github.com/abrignoni/ALEAPP)** - Android Logs Events and Protobuf Parser
- **[Andriller](https://github.com/den4uk/andriller)** - Android forensic utility suite
- **[MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)** - Mobile security assessment framework

#### 🍎 iOS Analysis

- **[iLEAPP](https://github.com/abrignoni/iLEAPP)** - iOS Logs Events and Preferences Parser
- **[iOS Frequent Locations Dumper](https://github.com/mac4n6/iOS-Frequent-Locations-Dumper)** - Extract location data
- **[OpenBackupExtractor](https://github.com/vgmoose/OpenBackupExtractor)** - Extract iPhone backups
- **[MEAT](https://github.com/jfarley248/MEAT)** - Mobile Evidence Acquisition Toolkit

#### 📲 Cross-Platform

- **[Santoku Linux](https://santoku-linux.com/)** - Mobile forensics distribution
- **[Autopsy](https://www.autopsy.com/)** - Now includes mobile analysis modules

**📱 Acquisition Methods:**
1. **Logical:** File system access (iTunes backup, ADB)
2. **File System:** Full file system dump (jailbreak/root required)
3. **Physical:** Chip-off, JTAG (advanced techniques)

---

### 🐳 Container Forensics

Analyze Docker containers and Kubernetes environments.

- **[Docker Forensics Toolkit (dof)](https://github.com/docker-forensics-toolkit/toolkit)** - Extract artifacts from Docker hosts
- **[Docker Explorer](https://github.com/google/docker-explorer)** - Forensic analysis of Docker installations (Google)

**🔍 Key Container Artifacts:**
```
/var/lib/docker/containers/         # Container configs
/var/lib/docker/overlay2/           # Container layers
/var/lib/docker/volumes/            # Persistent volumes
~/.docker/config.json               # Docker credentials
```

---

### 🌐 Browser Forensics

Extract browsing history, cookies, downloads, and cached files.

| Tool | Browsers Supported | Key Features |
|------|-------------------|--------------|
| **[Hindsight](https://github.com/obsidianforensics/hindsight)** | Chrome/Chromium | Timeline analysis, extension tracking |
| **[Dumpzilla](http://www.dumpzilla.org/)** | Firefox/Iceweasel | Complete profile extraction |
| **[ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html)** | Chrome | Cache viewer (NirSoft) |
| **[chrome-url-dumper](https://github.com/eLoopWoo/chrome-url-dumper)** | Chrome | URL history extraction |
| **[unfurl](https://github.com/obsidianforensics/unfurl)** | All | URL parsing and visualization |

**🌐 Browser Artifact Locations:**

**Chrome/Chromium:**
```
Linux:   ~/.config/google-chrome/Default/
Windows: %LOCALAPPDATA%\Google\Chrome\User Data\Default\
macOS:   ~/Library/Application Support/Google/Chrome/Default/
```

**Firefox:**
```
Linux:   ~/.mozilla/firefox/*.default/
Windows: %APPDATA%\Mozilla\Firefox\Profiles\*.default\
macOS:   ~/Library/Application Support/Firefox/Profiles/
```

---

### ⏱️ Timeline Analysis

Create unified timelines from multiple data sources.

- **[Plaso (log2timeline)](https://github.com/log2timeline/plaso)** ⭐ - Extract timestamps and create super timelines
- **[Timesketch](https://github.com/google/timesketch)** - Collaborative timeline analysis (Google)
- **[DFTimewolf](https://github.com/log2timeline/dftimewolf)** - Orchestrate forensic collection and processing
- **[timeliner](https://github.com/airbus-cert/timeliner)** - Bodyfile reader and timeline generator

**⏰ Timeline Creation Workflow:**
```bash
# 1. Extract timestamps with plaso
log2timeline.py timeline.plaso /evidence/image.dd

# 2. Generate CSV output
psort.py -o l2tcsv -w timeline.csv timeline.plaso

# 3. Import to Timesketch for analysis
timesketch_importer --timeline_name "Case123" timeline.csv
```

---

### 💽 Disk Image Management

Mount, convert, and manage forensic disk images.

| Tool | Capability | Supported Formats |
|------|-----------|-------------------|
| **[libewf](https://github.com/libyal/libewf)** | EWF library | E01, Ex01 |
| **[xmount](https://www.pinguin.lu/xmount)** | Format conversion | E01, DD, AFF, VHD |
| **[OSFMount](https://www.osforensics.com/tools/mount-disk-images.html)** | Windows mounting | E01, DD, VMDK, VHD |
| **[imagemounter](https://github.com/ralphje/imagemounter)** | Python mounting | Multiple formats |
| **[PancakeViewer](https://github.com/forensicmatt/PancakeViewer)** | Image viewer | E01, DD (dfvfs-based) |
| **[Disk Arbitrator](https://github.com/aburgh/Disk-Arbitrator)** | macOS mount control | Forensic procedures |

**🖥️ Mounting Examples:**
```bash
# Mount E01 as read-only
ewfmount image.E01 /mnt/ewf
mount -o ro,loop /mnt/ewf/ewf1 /mnt/evidence

# Convert E01 to DD
ewfexport -t output.dd image.E01
```

---

### 🔓 Cryptanalysis & Decryption

Crack passwords and decrypt protected data.

| Tool | Focus | GPU Support |
|------|-------|-------------|
| **[Hashcat](https://hashcat.net/hashcat/)** | Password cracking | ✅ CUDA, OpenCL |
| **[John the Ripper](https://www.openwall.com/john/)** | Password cracking | ⚠️ Limited |
| **[Ophcrack](https://ophcrack.sourceforge.io/)** | Windows passwords | ❌ |
| **[Elcomsoft](https://www.elcomsoft.com/)** | Commercial decryption | ✅ |

**🔑 Hash Identification:**
```bash
# Identify hash type
hashid '$2a$10$...'

# Crack with hashcat (mode 3200 = bcrypt)
hashcat -m 3200 -a 0 hashes.txt wordlist.txt

# Crack with John
john --wordlist=rockyou.txt hashes.txt
```

---

### 📊 Case Management

Organize investigations, track evidence, and manage workflows.

- **[dfirtrack](https://github.com/stuhli/dfirtrack)** - DFIR tracking application for managing systems under investigation
- **[Incidents](https://github.com/veeral-patel/incidents)** - Web app for organizing security investigations as ticket trees
- **[TheHive](https://github.com/TheHive-Project/TheHive)** - Security incident response platform
- **[Cortex](https://github.com/TheHive-Project/Cortex)** - Observable analysis and response engine

---

### 🖼️ Image Analysis

Analyze digital photographs and images for forensic evidence.

- **[Ghiro](http://www.getghiro.org/)** - Automated image forensics analysis
- **[ExifTool](https://exiftool.org/)** - Read/write metadata for images and files
- **[Forensically](https://29a.ch/photo-forensics/)** - Online photo forensics tools
- **[FotoForensics](https://fotoforensics.com/)** - Error level analysis for detecting manipulation

**📸 EXIF Extraction:**
```bash
# Extract all metadata
exiftool -a -G1 -s image.jpg

# Find GPS coordinates
exiftool -gps:all image.jpg

# Strip metadata
exiftool -all= image.jpg
```

---

---
### Metadata Forensics

- [ExifTool](https://exiftool.org/) by Phil Harvey
- [Exiv2](https://www.exiv2.org) - Exiv2 is a Cross-platform C++ library and a command line utility to manage image metadata
- [FOCA](https://github.com/ElevenPaths/FOCA) - FOCA is a tool used mainly to find metadata and hidden information in the documents

---
### Website Forensics

- [Freezing Internet Tool](https://github.com/fit-project/fit) - Python 3 application for forensic acquisition of online content, including web pages, emails, and social media.

---
## Learn forensics

- [Forensic challenges](https://www.amanhardikar.com/mindmaps/ForensicChallenges.html) - Mindmap of forensic challenges
- [OpenLearn](https://www.open.edu/openlearn/science-maths-technology/digital-forensics/content-section-0?active-tab=description-tab) - Digital forensic course
- [Training material](https://www.enisa.europa.eu/topics/trainings-for-cybersecurity-specialists/online-training-material/technical-operational) - Online training material by European Union Agency for Network and Information Security for different topics (e.g. [Digital forensics](https://www.enisa.europa.eu/topics/trainings-for-cybersecurity-specialists/online-training-material/technical-operational/#digital_forensics), [Network forensics](https://www.enisa.europa.eu/topics/trainings-for-cybersecurity-specialists/online-training-material/technical-operational/#network_forensics))

---
### Challenges

- [AnalystUnknown Cyber Range](https://aucr.io/auth/login?next=%2F)
- [Champlain College DFIR CTF](https://champdfa-ccsc-sp20.ctfd.io)
- [Corelight CTF](https://www3.corelight.com/l/420832/2020-03-31/lcxk2q)
- [CyberDefenders](https://cyberdefenders.org) 
- [DefCon CTFs](https://archive.ooo) - archive of DEF CON CTF challenges.
- [Forensics CTFs](https://github.com/apsdehal/awesome-ctf/blob/master/README.md#forensics)
- [IncidentResponse Challenge](https://incident-response-challenge.com)
- [MagnetForensics CTF Challenge](https://www.magnetforensics.com/blog/magnet-weekly-ctf-challenge)
- [MalwareTech Challenges](https://www.malwaretech.com/challenges)
- [MalwareTraffic Analysis](https://www.malware-traffic-analysis.net/training-exercises.html)
- [MemLabs](https://github.com/stuxnet999/MemLabs)
- [NW3C Chanllenges](https://nw3.ctfd.io)
- [PivotProject](https://pivotproject.org/challenges/digital-forensics-challenge)
- [Precision Widgets of North Dakota Intrusion](https://betweentwodfirns.blogspot.com/2017/11/dfir-ctf-precision-widgets-of-north.html)
- [ReverseEngineering Challenges](https://challenges.re)
- [SANS Forensics Challenges](https://digital-forensics.sans.org/community/challenges)

---
## Resources
---
### Webs

- [ForensicsFocus](https://www.forensicfocus.com/)
- [InsecInstitute Resources](https://resources.infosecinstitute.com/)
- [SANS Digital Forensics](https://digital-forensics.sans.org/)

---
### Blogs

- [Cyberforensics](https://cyberforensics.com/blog/)
- [Cyberforensicator](https://cyberforensicator.com/)
- [DigitalForensicsMagazine](https://digitalforensicsmagazine.com/blogs/)
- [FlashbackData](https://www.flashbackdata.com/blog/)
- [Netresec](https://www.netresec.com/index.ashx?page=Blog)
- [roDigitalForensics](https://prodigital4n6.com/blog/)
- [SANS Forensics Blog](https://www.sans.org/blog/?focus-area=digital-forensics)
- [SecurityAffairs](https://securityaffairs.co/wordpress/) - blog by Pierluigi Paganini
- [thisweekin4n6.wordpress.com](thisweekin4n6.wordpress.com) - Weekly updates for forensics
- [Zena Forensics](https://blog.digital-forensics.it/)

---
### Books

*more at [Recommended Readings](http://dfir.org/?q=node/8) by Andrew Case*

- [Network Forensics: Tracking Hackers through Cyberspace](https://www.pearson.com/us/higher-education/program/Davidoff-Network-Forensics-Tracking-Hackers-through-Cyberspace/PGM322390.html) - Learn to recognize hackers’ tracks and uncover network-based evidence
- [The Art of Memory Forensics](https://www.memoryanalysis.net/amf) - Detecting Malware and Threats in Windows, Linux, and Mac Memory
- [The Practice of Network Security Monitoring](https://nostarch.com/nsm) - Understanding Incident Detection and Response
- [Cell Phone Investigations: Search Warrants, Cell Sites and Evidence Recovery](https://cryptome.org/2015/11/Cell-Phone-Investigations.pdf) - Cell Phone Investigations is the most comprehensive book written on cell phones, cell sites, and cell related data.

---
### File System Corpora

- [Digital Forensic Challenge Images](https://www.ashemery.com/dfir.html) - Two DFIR challenges with images
- [Digital Forensics Tool Testing Images](http://dftt.sourceforge.net)
- [FAU Open Research Challenge Digital Forensics](https://openresearchchallenge.org/digitalForensics/appliedforensiccomputinggroup)
- [The CFReDS Project](https://www.cfreds.nist.gov)
  - [Hacking Case (4.5 GB NTFS Image)](https://www.cfreds.nist.gov/Hacking_Case.html)
---
### Twitter

- [@4n6ist](https://twitter.com/4n6ist)
- [@aheadless](https://twitter.com/aheadless)
- [@AppleExaminer](https://twitter.com/AppleExaminer) - Apple OS X & iOS Digital Forensics
- [@blackbagtech](https://twitter.com/blackbagtech)
- [@carrier4n6](https://twitter.com/carrier4n6) - Brian Carrier, author of Autopsy and the Sleuth Kit
- [@CindyMurph](https://twitter.com/CindyMurph) - Detective & Digital Forensic Examiner
- [@EricRZimmerman](https://twitter.com/EricRZimmerman) - Certified SANS Instructor
- [@forensikblog](https://twitter.com/forensikblog) - Computer forensic geek
- [@HECFBlog](https://twitter.com/HECFBlog) - SANS Certified Instructor
- [@Hexacorn](https://twitter.com/Hexacorn) - DFIR+Malware
- [@hiddenillusion](https://twitter.com/hiddenillusion)
- [@iamevltwin](https://twitter.com/iamevltwin) - Mac Nerd, Forensic Analyst, Author & Instructor of SANS FOR518
- [@jaredcatkinson](https://twitter.com/jaredcatkinson) - PowerShell Forensics
- [@maridegrazia](https://twitter.com/maridegrazia) - Computer Forensics Examiner
- [@sleuthkit](https://twitter.com/sleuthkit)
- [@williballenthin](https://twitter.com/williballenthin)
- [@XWaysGuide](https://twitter.com/XWaysGuide)

---
### Other

- [/r/computerforensics/](https://www.reddit.com/r/computerforensics/) - Subreddit for computer forensics
- [ForensicControl](https://www.forensiccontrol.com/free-software) - 
- [ForensicPosters](https://github.com/Invoke-IR/ForensicPosters) - Posters of file system structures
- [HFS+ Resources](https://github.com/mac4n6/HFSPlus_Resources)
- [mac4n6 Presentations](https://github.com/mac4n6/Presentations) - Presentation Archives for OS X and iOS Related Research
- [SANS Forensics CheatSheets](https://digital-forensics.sans.org/community/cheat-sheets) - Different CheatSheets from SANS
- [SANS Digital Forensics Posters](https://digital-forensics.sans.org/community/posters) - Digital Forensics Posters from SANS
- [SANS WhitePapers](https://digital-forensics.sans.org/community/whitepapers) - White Papers written by forensic practitioners seeking GCFA, GCFE, and GREM Gold

---
## Related Awesome Lists

- [Android Security](https://github.com/ashishb/android-security-awesome)
- [AppSec](https://github.com/paragonie/awesome-appsec)
- [Awesome Forensics](https://github.com/cugu/awesome-forensics)
- [CTFs](https://github.com/apsdehal/awesome-ctf)
- [Hacking](https://github.com/carpedm20/awesome-hacking)
- [Honeypots](https://github.com/paralax/awesome-honeypots)
- [Incident-Response](https://github.com/meirwah/awesome-incident-response)
- [Infosec](https://github.com/onlurking/awesome-infosec)
- [Malware Analysis](https://github.com/rshipp/awesome-malware-analysis)
- [Pentesting](https://github.com/enaqx/awesome-pentest)
- [Security](https://github.com/sbilly/awesome-security)
- [Social Engineering](https://github.com/v2-dev/awesome-social-engineering)
- [YARA](https://github.com/InQuest/awesome-yara)

---
Made with ❤️
Just learn, build, and grow.  
