# =============================================================
# CIS Benchmark Compliance Checker
# Author: Rohan Bhardwaj
# Purpose: Validate system configuration against CIS Benchmark
#          controls and generate a compliance gap report
# Relevant to: Configuration Compliance Engineer/Specialist roles
# =============================================================

import pandas as pd
from datetime import datetime
import os

# =============================================================
# CONFIGURATION
# =============================================================

INPUT_FILE = "cis_benchmark.csv"
OUTPUT_FILE = "cis_compliance_report.xlsx"
REPORT_DATE = datetime.now().strftime("%Y-%m-%d")
SYSTEM_NAME = "WORKSTATION-001"
BENCHMARK = "CIS Microsoft Windows 11 Benchmark v1.0"

# =============================================================
# LOAD DATA
# =============================================================

print("=" * 60)
print("  CIS Benchmark Compliance Checker")
print(f"  System: {SYSTEM_NAME}")
print(f"  Benchmark: {BENCHMARK}")
print(f"  Assessment Date: {REPORT_DATE}")
print("=" * 60)

try:
    df = pd.read_csv(INPUT_FILE)
    print(f"\n[+] Loaded {len(df)} controls from benchmark")
except FileNotFoundError:
    print(f"[!] Error: Could not find {INPUT_FILE}")
    exit()

# =============================================================
# EVALUATE COMPLIANCE
# =============================================================

# Determine pass/fail for each control
def check_compliance(row):
    if str(row["Expected Value"]).strip().lower() == str(row["Actual Value"]).strip().lower():
        return "PASS"
    else:
        return "FAIL"

df["Status"] = df.apply(check_compliance, axis=1)

# Separate passing and failing controls
passed = df[df["Status"] == "PASS"]
failed = df[df["Status"] == "FAIL"]

# Calculate compliance score
total = len(df)
pass_count = len(passed)
fail_count = len(failed)
compliance_score = round((pass_count / total) * 100, 1)

# Failed controls by severity
critical_fails = failed[failed["Severity"] == "Critical"]
high_fails = failed[failed["Severity"] == "High"]
medium_fails = failed[failed["Severity"] == "Medium"]
low_fails = failed[failed["Severity"] == "Low"]

# =============================================================
# PRINT SUMMARY TO CONSOLE
# =============================================================

print(f"\n[+] Compliance Assessment Complete")
print(f"\n{'=' * 60}")
print(f"  COMPLIANCE SCORE: {compliance_score}%")
print(f"{'=' * 60}")
print(f"  Total Controls Assessed : {total}")
print(f"  Controls Passing        : {pass_count}")
print(f"  Controls Failing        : {fail_count}")
print(f"\n  Failed Controls by Severity:")
print(f"    Critical : {len(critical_fails)}")
print(f"    High     : {len(high_fails)}")
print(f"    Medium   : {len(medium_fails)}")
print(f"    Low      : {len(low_fails)}")

# Compliance posture rating
if compliance_score >= 90:
    posture = "STRONG - Minor remediation required"
elif compliance_score >= 75:
    posture = "MODERATE - Remediation plan required"
elif compliance_score >= 50:
    posture = "WEAK - Immediate action required"
else:
    posture = "CRITICAL - Urgent remediation required"

print(f"\n  Compliance Posture: {posture}")
print(f"{'=' * 60}")

# =============================================================
# GENERATE EXCEL REPORT
# =============================================================

print(f"\n[+] Generating compliance report: {OUTPUT_FILE}")

with pd.ExcelWriter(OUTPUT_FILE, engine="openpyxl") as writer:

    # --- Sheet 1: Executive Summary ---
    summary_data = {
        "Metric": [
            "Assessment Date",
            "System Name",
            "Benchmark Applied",
            "Total Controls Assessed",
            "Controls Passing",
            "Controls Failing",
            "Compliance Score",
            "Compliance Posture",
            "Critical Failures",
            "High Failures",
            "Medium Failures",
            "Low Failures"
        ],
        "Value": [
            REPORT_DATE,
            SYSTEM_NAME,
            BENCHMARK,
            total,
            pass_count,
            fail_count,
            f"{compliance_score}%",
            posture,
            len(critical_fails),
            len(high_fails),
            len(medium_fails),
            len(low_fails)
        ]
    }
    summary_df = pd.DataFrame(summary_data)
    summary_df.to_excel(writer, sheet_name="Executive Summary", index=False)

    # --- Sheet 2: All Controls ---
    all_controls = df[[
        "Control ID", "Category", "Control Name",
        "Expected Value", "Actual Value", "Severity", "Status"
    ]]
    all_controls.to_excel(writer, sheet_name="All Controls", index=False)

    # --- Sheet 3: Failed Controls ---
    failed_output = failed[[
        "Control ID", "Category", "Control Name",
        "Expected Value", "Actual Value", "Severity", "Status"
    ]].sort_values("Severity")
    failed_output.to_excel(writer, sheet_name="Failed Controls", index=False)

    # --- Sheet 4: Remediation Plan ---
    remediation = failed[[
        "Control ID", "Category", "Control Name",
        "Expected Value", "Actual Value", "Severity"
    ]].copy()
    remediation.insert(0, "Priority", range(1, len(remediation) + 1))
    remediation.insert(6, "Remediation Action", "")
    remediation.insert(7, "Assigned To", "")
    remediation.insert(8, "Target Date", "")
    remediation.insert(9, "Status", "Open")
    remediation.to_excel(writer, sheet_name="Remediation Plan", index=False)

    # --- Sheet 5: Passed Controls ---
    passed_output = passed[[
        "Control ID", "Category", "Control Name",
        "Expected Value", "Actual Value", "Severity", "Status"
    ]]
    passed_output.to_excel(writer, sheet_name="Passed Controls", index=False)

    # --- Sheet 6: Category Summary ---
    category_summary = df.groupby(["Category", "Status"]).size().unstack(fill_value=0)
    category_summary.to_excel(writer, sheet_name="Category Summary")

print("[+] Report successfully generated")
print(f"\n[+] Report saved to: {os.path.abspath(OUTPUT_FILE)}")
print("\n[+] CIS Benchmark assessment complete")