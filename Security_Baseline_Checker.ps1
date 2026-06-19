# =============================================================
# Security Baseline Configuration Checker
# Author: Rohan Bhardwaj
# Purpose: Validate Windows system security settings against
#          a defined security baseline and generate a
#          compliance gap report
# Relevant to: Configuration Compliance Engineer/Specialist
# =============================================================

# =============================================================
# CONFIGURATION
# =============================================================

$ReportDate = Get-Date -Format "yyyy-MM-dd"
$OutputFile = "Security_Baseline_Report_$ReportDate.txt"
$SystemName = $env:COMPUTERNAME
$Benchmark = "CIS Windows 11 Security Baseline v1.0"
$PassCount = 0
$FailCount = 0
$Findings = @()

# =============================================================
# HELPER FUNCTION
# =============================================================

function Check-Control {
    param(
        [string]$ControlID,
        [string]$Category,
        [string]$ControlName,
        [string]$Expected,
        [string]$Actual,
        [string]$Severity,
        [string]$Recommendation
    )

    $Status = if ($Expected -eq $Actual) { "PASS" } else { "FAIL" }
    
    if ($Status -eq "PASS") {
        $script:PassCount++
        $Symbol = "[PASS]"
    } else {
        $script:FailCount++
        $Symbol = "[FAIL]"
    }

    Write-Host "  $Symbol [$Severity] $ControlName"
    if ($Status -eq "FAIL") {
        Write-Host "         Expected : $Expected"
        Write-Host "         Actual   : $Actual"
        Write-Host "         Fix      : $Recommendation"
    }

    $script:Findings += [PSCustomObject]@{
        ControlID      = $ControlID
        Category       = $Category
        ControlName    = $ControlName
        Expected       = $Expected
        Actual         = $Actual
        Severity       = $Severity
        Status         = $Status
        Recommendation = $Recommendation
    }
}

# =============================================================
# BEGIN ASSESSMENT
# =============================================================

Write-Host ("=" * 65)
Write-Host "  Security Baseline Configuration Checker"
Write-Host "  System    : $SystemName"
Write-Host "  Benchmark : $Benchmark"
Write-Host "  Date      : $ReportDate"
Write-Host ("=" * 65)

# =============================================================
# CATEGORY 1: PASSWORD POLICY
# =============================================================

Write-Host "`n[+] Checking Password Policy..."

# Get local security policy settings
$SecPol = @{}
$TempFile = "$env:TEMP\secpol.cfg"
secedit /export /cfg $TempFile /quiet
Get-Content $TempFile | ForEach-Object {
    if ($_ -match "^(.+)\s*=\s*(.+)$") {
        $SecPol[$matches[1].Trim()] = $matches[2].Trim()
    }
}

# Minimum password length
$MinPwdLength = $SecPol["MinimumPasswordLength"]
Check-Control `
    -ControlID "1.1" `
    -Category "Password Policy" `
    -ControlName "Minimum Password Length >= 14" `
    -Expected "14" `
    -Actual $MinPwdLength `
    -Severity "High" `
    -Recommendation "Set minimum password length to 14 characters via Group Policy"

# Maximum password age
$MaxPwdAge = $SecPol["MaximumPasswordAge"]
Check-Control `
    -ControlID "1.2" `
    -Category "Password Policy" `
    -ControlName "Maximum Password Age <= 60 days" `
    -Expected "60" `
    -Actual $MaxPwdAge `
    -Severity "Medium" `
    -Recommendation "Set maximum password age to 60 days via Group Policy"

# Account lockout threshold
$LockoutThreshold = $SecPol["LockoutBadCount"]
Check-Control `
    -ControlID "1.3" `
    -Category "Password Policy" `
    -ControlName "Account Lockout Threshold <= 5 attempts" `
    -Expected "5" `
    -Actual $LockoutThreshold `
    -Severity "High" `
    -Recommendation "Set account lockout threshold to 5 attempts via Group Policy"

# Password complexity
$Complexity = $SecPol["PasswordComplexity"]
Check-Control `
    -ControlID "1.4" `
    -Category "Password Policy" `
    -ControlName "Password Complexity Enabled" `
    -Expected "1" `
    -Actual $Complexity `
    -Severity "High" `
    -Recommendation "Enable password complexity requirements via Group Policy"

# =============================================================
# CATEGORY 2: WINDOWS FIREWALL
# =============================================================

Write-Host "`n[+] Checking Windows Firewall..."

# Domain profile
$FWDomain = (Get-NetFirewallProfile -Profile Domain).Enabled
Check-Control `
    -ControlID "2.1" `
    -Category "Windows Firewall" `
    -ControlName "Firewall Domain Profile Enabled" `
    -Expected "True" `
    -Actual "$FWDomain" `
    -Severity "High" `
    -Recommendation "Enable Windows Firewall Domain Profile via Group Policy"

# Private profile
$FWPrivate = (Get-NetFirewallProfile -Profile Private).Enabled
Check-Control `
    -ControlID "2.2" `
    -Category "Windows Firewall" `
    -ControlName "Firewall Private Profile Enabled" `
    -Expected "True" `
    -Actual "$FWPrivate" `
    -Severity "High" `
    -Recommendation "Enable Windows Firewall Private Profile via Group Policy"

# Public profile
$FWPublic = (Get-NetFirewallProfile -Profile Public).Enabled
Check-Control `
    -ControlID "2.3" `
    -Category "Windows Firewall" `
    -ControlName "Firewall Public Profile Enabled" `
    -Expected "True" `
    -Actual "$FWPublic" `
    -Severity "High" `
    -Recommendation "Enable Windows Firewall Public Profile via Group Policy"

# =============================================================
# CATEGORY 3: WINDOWS UPDATE
# =============================================================

Write-Host "`n[+] Checking Windows Update Settings..."

$WUAuto = (Get-ItemProperty -Path `
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" `
    -ErrorAction SilentlyContinue).AUOptions

$WUExpected = "4"
$WUActual = if ($WUAuto) { "$WUAuto" } else { "Not Configured" }

Check-Control `
    -ControlID "3.1" `
    -Category "Windows Update" `
    -ControlName "Automatic Updates Enabled (AUOptions=4)" `
    -Expected $WUExpected `
    -Actual $WUActual `
    -Severity "High" `
    -Recommendation "Configure automatic updates via Group Policy or Windows Update settings"

# =============================================================
# CATEGORY 4: REMOTE DESKTOP
# =============================================================

Write-Host "`n[+] Checking Remote Desktop Settings..."

$RDPEnabled = (Get-ItemProperty -Path `
    "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
    -Name "fDenyTSConnections").fDenyTSConnections

Check-Control `
    -ControlID "4.1" `
    -Category "Remote Access" `
    -ControlName "Remote Desktop Disabled (fDenyTSConnections=1)" `
    -Expected "1" `
    -Actual "$RDPEnabled" `
    -Severity "High" `
    -Recommendation "Disable RDP if not required or restrict via firewall rules"

# NLA for RDP
$NLAEnabled = (Get-ItemProperty -Path `
    "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication

Check-Control `
    -ControlID "4.2" `
    -Category "Remote Access" `
    -ControlName "Network Level Authentication Enabled" `
    -Expected "1" `
    -Actual "$NLAEnabled" `
    -Severity "High" `
    -Recommendation "Enable NLA for RDP via System Properties or Group Policy"

# =============================================================
# CATEGORY 5: SMB SETTINGS
# =============================================================

Write-Host "`n[+] Checking SMB Settings..."

$SMBv1 = (Get-WindowsOptionalFeature -Online `
    -FeatureName SMB1Protocol -ErrorAction SilentlyContinue).State

$SMBv1Status = if ($SMBv1 -eq "Disabled") { "Disabled" } else { "Enabled" }

Check-Control `
    -ControlID "5.1" `
    -Category "Network Protocols" `
    -ControlName "SMBv1 Protocol Disabled" `
    -Expected "Disabled" `
    -Actual $SMBv1Status `
    -Severity "Critical" `
    -Recommendation "Disable SMBv1 via PowerShell: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"

# =============================================================
# CATEGORY 6: WINDOWS DEFENDER
# =============================================================

Write-Host "`n[+] Checking Windows Defender..."

$DefenderStatus = (Get-MpComputerStatus -ErrorAction SilentlyContinue)

$RealTimeProtection = if ($DefenderStatus) { 
    "$($DefenderStatus.RealTimeProtectionEnabled)" 
} else { 
    "Unable to query" 
}

Check-Control `
    -ControlID "6.1" `
    -Category "Endpoint Protection" `
    -ControlName "Windows Defender Real-Time Protection Enabled" `
    -Expected "True" `
    -Actual $RealTimeProtection `
    -Severity "Critical" `
    -Recommendation "Enable Windows Defender Real-Time Protection immediately"

$DefenderUpdated = if ($DefenderStatus -and $DefenderStatus.AntivirusSignatureLastUpdated) {
    $SigAge = ((Get-Date) - [DateTime]$DefenderStatus.AntivirusSignatureLastUpdated).Days
    if ($SigAge -le 1) { "Current" } else { "$SigAge days old" }
} else { 
    "Unable to query - Defender may be inactive" 
}

Check-Control `
    -ControlID "6.2" `
    -Category "Endpoint Protection" `
    -ControlName "Defender Signatures Current (<=1 day)" `
    -Expected "Current" `
    -Actual $DefenderUpdated `
    -Severity "High" `
    -Recommendation "Update Windows Defender signatures immediately"

# =============================================================
# CATEGORY 7: AUDIT POLICY
# =============================================================

Write-Host "`n[+] Checking Audit Policy..."

$AuditLogon = $SecPol["AuditLogonEvents"]
Check-Control `
    -ControlID "7.1" `
    -Category "Audit Policy" `
    -ControlName "Audit Logon Events (Success and Failure)" `
    -Expected "3" `
    -Actual "$AuditLogon" `
    -Severity "High" `
    -Recommendation "Enable logon auditing for Success and Failure via Group Policy"

$AuditAccountLogon = $SecPol["AuditAccountLogon"]
Check-Control `
    -ControlID "7.2" `
    -Category "Audit Policy" `
    -ControlName "Audit Account Logon Events (Success and Failure)" `
    -Expected "3" `
    -Actual "$AuditAccountLogon" `
    -Severity "High" `
    -Recommendation "Enable account logon auditing via Group Policy"

# =============================================================
# CALCULATE RESULTS
# =============================================================

$TotalControls = $PassCount + $FailCount
$ComplianceScore = [math]::Round(($PassCount / $TotalControls) * 100, 1)

$Posture = switch ($true) {
    ($ComplianceScore -ge 90) { "STRONG - Minor remediation required" }
    ($ComplianceScore -ge 75) { "MODERATE - Remediation plan required" }
    ($ComplianceScore -ge 50) { "WEAK - Immediate action required" }
    default { "CRITICAL - Urgent remediation required" }
}

# =============================================================
# CONSOLE SUMMARY
# =============================================================

Write-Host "`n$("=" * 65)"
Write-Host "  COMPLIANCE SUMMARY"
Write-Host "$("=" * 65)"
Write-Host "  Total Controls Assessed : $TotalControls"
Write-Host "  Controls Passing        : $PassCount"
Write-Host "  Controls Failing        : $FailCount"
Write-Host "  Compliance Score        : $ComplianceScore%"
Write-Host "  Compliance Posture      : $Posture"
Write-Host "$("=" * 65)"

# Failed controls by severity
$CriticalFails = $Findings | Where-Object { $_.Status -eq "FAIL" -and $_.Severity -eq "Critical" }
$HighFails = $Findings | Where-Object { $_.Status -eq "FAIL" -and $_.Severity -eq "High" }
$MediumFails = $Findings | Where-Object { $_.Status -eq "FAIL" -and $_.Severity -eq "Medium" }

Write-Host "`n  Failed by Severity:"
Write-Host "    Critical : $($CriticalFails.Count)"
Write-Host "    High     : $($HighFails.Count)"
Write-Host "    Medium   : $($MediumFails.Count)"

# =============================================================
# GENERATE REPORT
# =============================================================

$FailedFindings = $Findings | Where-Object { $_.Status -eq "FAIL" }

$Report = @"
================================================
SECURITY BASELINE CONFIGURATION REPORT
================================================
System Name   : $SystemName
Benchmark     : $Benchmark
Assessment By : Rohan Bhardwaj
Date          : $ReportDate

================================================
EXECUTIVE SUMMARY
================================================
Total Controls Assessed : $TotalControls
Controls Passing        : $PassCount
Controls Failing        : $FailCount
Compliance Score        : $ComplianceScore%
Compliance Posture      : $Posture

Failed by Severity:
  Critical : $($CriticalFails.Count)
  High     : $($HighFails.Count)
  Medium   : $($MediumFails.Count)

================================================
FAILED CONTROLS - REMEDIATION REQUIRED
================================================
$($FailedFindings | ForEach-Object {
"Control ID     : $($_.ControlID)
Category       : $($_.Category)
Control Name   : $($_.ControlName)
Severity       : $($_.Severity)
Expected       : $($_.Expected)
Actual         : $($_.Actual)
Recommendation : $($_.Recommendation)
Status         : $($_.Status)
------------------------------------------------"
})

================================================
ALL CONTROLS ASSESSED
================================================
$($Findings | ForEach-Object {
"[$($_.Status)] [$($_.Severity)] $($_.ControlName)"
})

================================================
END OF REPORT
================================================
"@

$Report | Out-File -FilePath $OutputFile -Encoding UTF8
Write-Host "`n[+] Report saved to: $(Resolve-Path $OutputFile)"
Write-Host "[+] Security baseline assessment complete"
Write-Host ("=" * 65)

# Cleanup temp file
Remove-Item $TempFile -ErrorAction SilentlyContinue