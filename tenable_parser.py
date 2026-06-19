# =============================================================
# Tenable Vulnerability Scan Parser
# Author: Rohan Bhardwaj
# Purpose: Parse Tenable scan exports, categorize findings by
#          severity, and generate a formatted compliance report
# Relevant to: Configuration Compliance Engineer/Specialist roles
# =============================================================

import pandas as pd
from datetime import datetime
import os

# =============================================================
# CONFIGURATION
# =============================================================

INPUT_FILE = "tenable_scan.csv"
OUTPUT_FILE = "vulnerability_report.xlsx"
REPORT_DATE = datetime.now().strftime("%Y-%m-%d")

# CVSS thresholds aligned with industry standard severity ratings
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "None"]

# =============================================================
# LOAD AND VALIDATE DATA
# =============================================================

print("=" * 60)
print("  Tenable Vulnerability Scan Parser")
print(f"  Report Date: {REPORT_DATE}")
print("=" * 60)

# Load the Tenable CSV export
try:
    df = pd.read_csv(INPUT_FILE)
    print(f"\n[+] Successfully loaded scan data: {len(df)} findings found")
except FileNotFoundError:
    print(f"[!] Error: Could not find {INPUT_FILE}")
    print("    Please ensure the Tenable export CSV is in the same folder")
    exit()

# =============================================================
# FILTER AND PROCESS DATA
# =============================================================

# Remove informational findings (Risk = None) for compliance focus
findings = df[df["Risk"] != "None"].copy()
print(f"[+] Actionable findings after filtering: {len(findings)}")

# Sort by CVSS Score descending (highest risk first)
findings = findings.sort_values("CVSS Score", ascending=False)

# Severity breakdown
print("\n[+] Severity Breakdown:")
severity_counts = findings["Risk"].value_counts()
for severity in SEVERITY_ORDER:
    if severity in severity_counts:
        count = severity_counts[severity]
        print(f"    {severity:<12}: {count} findings")

# Critical and High findings (immediate action required)
critical_high = findings[findings["Risk"].isin(["Critical", "High"])]
print(f"\n[!] Critical/High findings requiring immediate remediation: {len(critical_high)}")

# =============================================================
# GENERATE EXCEL REPORT
# =============================================================

print(f"\n[+] Generating compliance report: {OUTPUT_FILE}")

with pd.ExcelWriter(OUTPUT_FILE, engine="openpyxl") as writer:

    # --- Sheet 1: Executive Summary ---
    summary_data = {
        "Metric": [
            "Report Date",
            "Total Findings",
            "Critical Findings",
            "High Findings",
            "Medium Findings",
            "Low Findings",
            "Hosts Scanned",
            "Hosts with Critical/High"
        ],
        "Value": [
            REPORT_DATE,
            len(findings),
            len(findings[findings["Risk"] == "Critical"]),
            len(findings[findings["Risk"] == "High"]),
            len(findings[findings["Risk"] == "Medium"]),
            len(findings[findings["Risk"] == "Low"]),
            findings["Host"].nunique(),
            critical_high["Host"].nunique()
        ]
    }
    summary_df = pd.DataFrame(summary_data)
    summary_df.to_excel(writer, sheet_name="Executive Summary", index=False)

    # --- Sheet 2: All Findings ---
    findings_output = findings[[
        "Risk", "CVSS Score", "Host", "Port",
        "Name", "CVE", "Synopsis", "Solution"
    ]].copy()
    findings_output.to_excel(writer, sheet_name="All Findings", index=False)

    # --- Sheet 3: Critical and High Priority ---
    critical_high_output = critical_high[[
        "Risk", "CVSS Score", "Host", "Port",
        "Name", "CVE", "Synopsis", "Solution"
    ]].copy()
    critical_high_output.to_excel(writer, sheet_name="Critical-High Priority", index=False)

    # --- Sheet 4: Findings by Host ---
    host_summary = findings.groupby(["Host", "Risk"]).size().unstack(fill_value=0)
    host_summary.to_excel(writer, sheet_name="Findings by Host")

    # --- Sheet 5: Remediation Plan ---
    remediation = critical_high[[
        "Risk", "CVSS Score", "Host", "Name", "CVE", "Solution"
    ]].copy()
    remediation.insert(0, "Priority", range(1, len(remediation) + 1))
    remediation.insert(6, "Status", "Open")
    remediation.insert(7, "Assigned To", "")
    remediation.insert(8, "Target Date", "")
    remediation.to_excel(writer, sheet_name="Remediation Plan", index=False)

print("[+] Report successfully generated")
print("\n" + "=" * 60)
print("  COMPLIANCE SUMMARY")
print("=" * 60)
print(f"  Total Actionable Findings : {len(findings)}")
print(f"  Critical                  : {len(findings[findings['Risk'] == 'Critical'])}")
print(f"  High                      : {len(findings[findings['Risk'] == 'High'])}")
print(f"  Medium                    : {len(findings[findings['Risk'] == 'Medium'])}")
print(f"  Low                       : {len(findings[findings['Risk'] == 'Low'])}")
print(f"  Unique Hosts Affected     : {findings['Host'].nunique()}")
print(f"  Hosts with Critical/High  : {critical_high['Host'].nunique()}")
print("=" * 60)
print(f"\n  Report saved to: {os.path.abspath(OUTPUT_FILE)}")
print("\n[+] Scan parsing complete")