# =============================================================
# Automated Patch Status Reporter
# Author: Rohan Bhardwaj
# Purpose: Query Windows Update history, identify missing and
#          failed patches, and generate a patch compliance
#          report aligned with security baseline requirements
# Relevant to: Configuration Compliance Engineer/Specialist
# Note: Directly mirrors monthly patching cycle compliance
#       work performed at General Dynamics Mission Systems Canada
# =============================================================

# =============================================================
# CONFIGURATION
# =============================================================

$ReportDate = Get-Date -Format "yyyy-MM-dd"
$OutputFile = "Patch_Compliance_Report_$ReportDate.txt"
$SystemName = $env:COMPUTERNAME
$PatchWindowDays = 30     # Patches should be applied within 30 days
$CriticalWindowDays = 7   # Critical patches within 7 days
$PassCount = 0
$FailCount = 0

# =============================================================
# HEADER
# =============================================================

Write-Host ("=" * 65)
Write-Host "  Automated Patch Status Reporter"
Write-Host "  System    : $SystemName"
Write-Host "  Date      : $ReportDate"
Write-Host "  Standard  : Patches applied within $PatchWindowDays days"
Write-Host "              Critical patches within $CriticalWindowDays days"
Write-Host ("=" * 65)

# =============================================================
# QUERY WINDOWS UPDATE HISTORY
# =============================================================

Write-Host "`n[+] Querying Windows Update history..."

try {
    $UpdateSession = New-Object -ComObject Microsoft.Update.Session
    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
    $HistoryCount = $UpdateSearcher.GetTotalHistoryCount()
    $UpdateHistory = $UpdateSearcher.QueryHistory(0, $HistoryCount)

    Write-Host "[+] Found $HistoryCount update history entries"
} catch {
    Write-Host "[!] Unable to query Windows Update history: $_"
    exit
}

# =============================================================
# PROCESS UPDATE HISTORY
# =============================================================

$AllUpdates = @()
$CutoffDate = (Get-Date).AddDays(-$PatchWindowDays)
$CriticalCutoff = (Get-Date).AddDays(-$CriticalWindowDays)

foreach ($Update in $UpdateHistory) {
    if ($Update.Title -ne "") {
        # Determine result
        $Result = switch ($Update.ResultCode) {
            1 { "In Progress" }
            2 { "Succeeded" }
            3 { "Succeeded with Errors" }
            4 { "Failed" }
            5 { "Aborted" }
            default { "Unknown" }
        }

        # Determine category
        $Category = "General"
        if ($Update.Title -like "*Security*" -or 
    $Update.Title -like "*Critical*" -or
    $Update.Title -like "*KB5*" -or
    $Update.Title -like "*Cumulative Update for Windows*") { 
    $Category = "Security" 
}
        if ($Update.Title -like "*Defender*" -or 
            $Update.Title -like "*Malware*") { 
            $Category = "Defender" 
        }
        if ($Update.Title -like "*Cumulative*") { 
            $Category = "Cumulative" 
        }
        if ($Update.Title -like "*Driver*") { 
            $Category = "Driver" 
        }

        $AllUpdates += [PSCustomObject]@{
            Title       = $Update.Title
            Date        = $Update.Date
            Result      = $Result
            Category    = $Category
            HotFixID    = if ($Update.Title -match "KB\d+") { 
                            $matches[0] 
                          } else { 
                            "N/A" 
                          }
        }
    }
}

# =============================================================
# ANALYZE RESULTS
# =============================================================

# Successful updates
$SuccessfulUpdates = $AllUpdates | Where-Object { 
    $_.Result -eq "Succeeded" 
}

# Failed updates
$FailedUpdates = $AllUpdates | Where-Object { 
    $_.Result -eq "Failed" -or $_.Result -eq "Aborted" 
}

# Recent updates within patch window
$RecentUpdates = $SuccessfulUpdates | Where-Object { 
    $_.Date -ge $CutoffDate 
}

# Security updates
$SecurityUpdates = $AllUpdates | Where-Object { 
    $_.Category -eq "Security" 
}

$RecentSecurityUpdates = $SecurityUpdates | Where-Object { 
    $_.Date -ge $CutoffDate 
}

# Last patch date
$LastPatch = $SuccessfulUpdates | 
    Sort-Object Date -Descending | 
    Select-Object -First 1

$DaysSinceLastPatch = if ($LastPatch) {
    ((Get-Date) - $LastPatch.Date).Days
} else {
    999
}

# Patch compliance status
$PatchCompliant = $DaysSinceLastPatch -le $PatchWindowDays
$PatchStatus = if ($PatchCompliant) { "COMPLIANT" } else { "NON-COMPLIANT" }

# =============================================================
# CONSOLE OUTPUT
# =============================================================

Write-Host "`n[+] Patch History Analysis Complete"
Write-Host "`n$("=" * 65)"
Write-Host "  PATCH COMPLIANCE SUMMARY"
Write-Host "$("=" * 65)"
Write-Host "  Total Updates in History    : $($AllUpdates.Count)"
Write-Host "  Successful Updates          : $($SuccessfulUpdates.Count)"
Write-Host "  Failed/Aborted Updates      : $($FailedUpdates.Count)"
Write-Host "  Updates in Last 30 Days     : $($RecentUpdates.Count)"
Write-Host "  Security Updates (Total)    : $($SecurityUpdates.Count)"
Write-Host "  Security Updates (30 Days)  : $($RecentSecurityUpdates.Count)"
Write-Host "  Last Patch Applied          : $(if ($LastPatch) { $LastPatch.Date.ToString('yyyy-MM-dd') } else { 'Never' })"
Write-Host "  Days Since Last Patch       : $DaysSinceLastPatch"
Write-Host "  Patch Compliance Status     : $PatchStatus"
Write-Host "$("=" * 65)"

# Failed updates detail
if ($FailedUpdates.Count -gt 0) {
    Write-Host "`n[!] FAILED UPDATES REQUIRING ATTENTION:"
    $FailedUpdates | Select-Object -First 10 | ForEach-Object {
        Write-Host "  - [$($_.Category)] $($_.Title)"
        Write-Host "    Date: $($_.Date.ToString('yyyy-MM-dd')) | Result: $($_.Result) | KB: $($_.HotFixID)"
    }
}

# Recent successful updates
Write-Host "`n[+] RECENT SUCCESSFUL UPDATES (Last 30 Days):"
if ($RecentUpdates.Count -gt 0) {
    $RecentUpdates | 
        Sort-Object Date -Descending | 
        Select-Object -First 10 | 
        ForEach-Object {
            Write-Host "  [OK] [$($_.Category)] $($_.Title.Substring(0, [Math]::Min(60, $_.Title.Length)))..."
            Write-Host "       Date: $($_.Date.ToString('yyyy-MM-dd')) | KB: $($_.HotFixID)"
        }
} else {
    Write-Host "  [!] No successful updates in the last 30 days - COMPLIANCE RISK"
}

# Category breakdown
Write-Host "`n[+] UPDATE CATEGORIES:"
$AllUpdates | Group-Object Category | ForEach-Object {
    Write-Host "  $($_.Name.PadRight(15)): $($_.Count) updates"
}

# =============================================================
# COMPLIANCE ASSESSMENT
# =============================================================

Write-Host "`n$("=" * 65)"
Write-Host "  COMPLIANCE CONTROLS"
Write-Host "$("=" * 65)"

function Write-Control {
    param($Name, $Status, $Detail)
    $Symbol = if ($Status -eq "PASS") { 
        $script:PassCount++
        "[PASS]" 
    } else { 
        $script:FailCount++
        "[FAIL]" 
    }
    Write-Host "  $Symbol $Name"
    if ($Detail) { Write-Host "         $Detail" }
}

Write-Control `
    -Name "System patched within 30-day window" `
    -Status $(if ($PatchCompliant) { "PASS" } else { "FAIL" }) `
    -Detail "Days since last patch: $DaysSinceLastPatch"

Write-Control `
    -Name "No failed updates present" `
    -Status $(if ($FailedUpdates.Count -eq 0) { "PASS" } else { "FAIL" }) `
    -Detail "Failed updates found: $($FailedUpdates.Count)"

Write-Control `
    -Name "Security updates applied in last 30 days" `
    -Status $(if ($RecentSecurityUpdates.Count -gt 0) { "PASS" } else { "FAIL" }) `
    -Detail "Recent security updates: $($RecentSecurityUpdates.Count)"

Write-Control `
    -Name "Windows Defender definitions current" `
    -Status $(if (($AllUpdates | Where-Object { 
        $_.Category -eq "Defender" -and $_.Date -ge $CriticalCutoff 
    }).Count -gt 0) { "PASS" } else { "FAIL" }) `
    -Detail "Defender updates in last 7 days checked"

$TotalControls = $PassCount + $FailCount
$ComplianceScore = [math]::Round(($PassCount / $TotalControls) * 100, 1)

Write-Host "`n  Controls Passing : $PassCount / $TotalControls"
Write-Host "  Compliance Score : $ComplianceScore%"

# =============================================================
# GENERATE REPORT FILE
# =============================================================

$Report = @"
================================================
PATCH COMPLIANCE REPORT
================================================
System Name   : $SystemName
Report Date   : $ReportDate
Assessed By   : Rohan Bhardwaj
Patch Window  : $PatchWindowDays days (Critical: $CriticalWindowDays days)

================================================
EXECUTIVE SUMMARY
================================================
Total Updates in History   : $($AllUpdates.Count)
Successful Updates         : $($SuccessfulUpdates.Count)
Failed/Aborted Updates     : $($FailedUpdates.Count)
Updates in Last 30 Days    : $($RecentUpdates.Count)
Security Updates (Total)   : $($SecurityUpdates.Count)
Security Updates (30 Days) : $($RecentSecurityUpdates.Count)
Last Patch Applied         : $(if ($LastPatch) { $LastPatch.Date.ToString('yyyy-MM-dd') } else { 'Never' })
Days Since Last Patch      : $DaysSinceLastPatch
Patch Compliance Status    : $PatchStatus
Compliance Score           : $ComplianceScore%

================================================
FAILED UPDATES
================================================
$(if ($FailedUpdates.Count -gt 0) {
    $FailedUpdates | ForEach-Object {
        "Title    : $($_.Title)`nDate     : $($_.Date.ToString('yyyy-MM-dd'))`nResult   : $($_.Result)`nKB       : $($_.HotFixID)`nCategory : $($_.Category)`n---"
    }
} else {
    "No failed updates detected"
})

================================================
RECENT UPDATES (Last 30 Days)
================================================
$($RecentUpdates | Sort-Object Date -Descending | ForEach-Object {
    "[$($_.Result)] $($_.Title)`nDate: $($_.Date.ToString('yyyy-MM-dd')) | KB: $($_.HotFixID) | Category: $($_.Category)`n"
})

================================================
REMEDIATION RECOMMENDATIONS
================================================
$(if (-not $PatchCompliant) {
    "1. CRITICAL: System has not been patched in $DaysSinceLastPatch days`n   Action: Run Windows Update immediately and apply all pending patches"
})
$(if ($FailedUpdates.Count -gt 0) {
    "2. HIGH: $($FailedUpdates.Count) failed updates detected`n   Action: Investigate and resolve failed updates, retry installation"
})
$(if ($RecentSecurityUpdates.Count -eq 0) {
    "3. HIGH: No security updates applied in last 30 days`n   Action: Check Windows Update settings and apply security patches"
})

================================================
END OF REPORT
================================================
"@

$Report | Out-File -FilePath $OutputFile -Encoding UTF8
Write-Host "`n[+] Report saved to: $(Resolve-Path $OutputFile)"
Write-Host "[+] Patch compliance assessment complete"
Write-Host ("=" * 65)