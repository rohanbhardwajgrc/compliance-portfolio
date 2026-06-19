# Compliance Portfolio — Rohan Bhardwaj

Configuration Compliance & GRC Portfolio demonstrating practical, hands-on experience in vulnerability management, security baseline validation, and IT compliance automation using Python and PowerShell.

All scripts were developed and tested on Windows 11 and directly reflect day-to-day Configuration Compliance Engineer workflows. Projects are grounded in real compliance work performed at **General Dynamics Mission Systems Canada** and **Crosslinx Transit Solutions**.

---

## Projects

### 1. Tenable Vulnerability Scan Parser (Python)
**File:** `tenable_parser.py`

Parses Tenable vulnerability scan CSV exports, categorizes findings by CVSS severity score, identifies critical and high-priority remediation items, and generates a professional multi-sheet Excel compliance report.

**Key Features:**
- Filters informational noise and isolates actionable findings
- Prioritizes by CVSS score aligned with risk-based remediation standards
- Generates 5-sheet Excel report: Executive Summary, All Findings, Critical/High Priority, Findings by Host, and Remediation Plan
- Mirrors real Tenable scan analysis workflow from General Dynamics Mission Systems Canada

**Technologies:** Python 3.14, pandas, openpyxl

---

### 2. CIS Benchmark Compliance Checker (Python)
**File:** `cis_checker.py`

Evaluates system configuration settings against CIS Benchmark controls across seven security categories and generates a six-sheet Excel compliance report with scoring and remediation plan.

**Key Features:**
- Assesses 27 controls across Account Policies, Firewall, Remote Access, System Services, User Rights, and Network Security
- Generates compliance score and posture rating (Strong/Moderate/Weak/Critical)
- Produces structured remediation plan with assigned owner and target date fields
- Extensible to Linux, macOS, and network device benchmarks

**Technologies:** Python 3.14, pandas, openpyxl

---

### 3. Active Directory Compliance Audit (PowerShell)
**File:** `AD_Compliance_Audit.ps1`

Audits Active Directory for compliance violations including inactive user accounts, ghost computer systems, non-expiring passwords, stale password ages, and legacy operating systems.

**Key Features:**
- Flags accounts and systems inactive for 90+ days
- Identifies non-expiring passwords and legacy OS — both critical compliance violations
- Generates prioritized remediation report with Critical, High, and Medium action items
- In a live environment, uses Get-ADUser and Get-ADComputer cmdlets (documented in script)
- Directly mirrors AD compliance auditing performed at General Dynamics Mission Systems Canada, where this methodology improved compliance metrics from ~50% to over 95%

**Technologies:** PowerShell 5.1, Active Directory module

---

### 4. Security Baseline Configuration Checker (PowerShell)
**File:** `Security_Baseline_Checker.ps1`

Validates a live Windows 11 system against a defined security baseline across seven categories — querying actual registry values, firewall profiles, and security policy settings to produce real compliance findings.

**Key Features:**
- Runs against a real Windows 11 system — findings reflect actual configuration state
- Checks Password Policy, Windows Firewall, Windows Update, Remote Desktop, SMB Settings, Windows Defender, and Audit Policy
- Each failing control includes specific, actionable remediation guidance
- Aligned with CIS Benchmark and NIST 800-53 control requirements

**Technologies:** PowerShell 5.1, Registry API, secedit, Windows Firewall API, WMI

---

### 5. Automated Patch Status Reporter (PowerShell)
**File:** `Patch_Status_Reporter.ps1`

Queries the Windows Update COM API to retrieve complete patch history, categorizes updates by type, identifies failed updates, evaluates patch currency against compliance windows, and generates a structured patch compliance report.

**Key Features:**
- Queries Windows Update COM API directly — same data source used by enterprise patch management tools
- Configurable compliance windows: 30-day standard, 7-day critical
- Identifies failed and aborted updates requiring investigation
- Directly mirrors monthly patching cycle compliance work from General Dynamics Mission Systems Canada

**Technologies:** PowerShell 5.1, Windows Update COM API

---

## Tools & Technologies

| Category | Tools |
|----------|-------|
| Vulnerability Management | Tenable (hands-on), Qualys (familiarization) |
| Scripting Languages | Python 3.14, PowerShell 5.1 |
| Compliance Frameworks | CIS Benchmarks, NIST CSF, NIST 800-53 |
| Data & Reporting | pandas, openpyxl, ReportLab |
| Platform Training | ServiceNow CSA (In Progress) |
| Certifications | CompTIA Security+, CRISC (In Progress), ISACA Member |

---

## Professional Background

These projects are grounded in real compliance work performed across:

- **General Dynamics Mission Systems Canada** — System Integration, V&V Engineering Analyst (2022–2024): Tenable vulnerability scanning, PKI documentation, AD compliance auditing, and security baseline validation in a classified defence environment
- **Crosslinx Transit Solutions** — Configuration Controller (2022): Asset configuration governance, data reconciliation across 4 vendor organizations, audit-ready documentation on a government infrastructure program
- **Scotiabank** — Senior Financial Advisor (2019–2021): Regulatory compliance, OSFI guidelines, KYC and client due diligence in a Big 5 banking environment

---

## Contact

**Rohan Bhardwaj**
📧 rohan.bhardwaj89@hotmail.com
📱 905-616-8014
🔗 [linkedin.com/in/rohanbhardwaj89](https://www.linkedin.com/in/rohanbhardwaj89)