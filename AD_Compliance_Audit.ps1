# =============================================================
# Active Directory Compliance Audit Script
# Author: Rohan Bhardwaj
# Purpose: Identify inactive accounts, ghost systems, and
#          stale objects that violate security baseline
#          requirements — directly mirrors remediation work
#          performed at General Dynamics Mission Systems Canada
# Relevant to: Configuration Compliance Engineer/Specialist
# =============================================================

# =============================================================
# CONFIGURATION
# =============================================================

$ReportDate = Get-Date -Format "yyyy-MM-dd"
$OutputFile = "AD_Compliance_Report_$ReportDate.txt"
$InactiveDays = 90        # Flag accounts inactive for 90+ days
$PasswordAgeDays = 60     # Flag passwords older than 60 days
$Organization = "Simulated Enterprise Environment"

# =============================================================
# SIMULATE AD DATA
# Note: In a live environment this would query Active Directory
# directly using Get-ADUser and Get-ADComputer cmdlets.
# Simulated data mirrors real findings from classified defence
# environment work at General Dynamics Mission Systems Canada.
# =============================================================

$SimulatedUsers = @(
    [PSCustomObject]@{
        Username = "jsmith"
        DisplayName = "John Smith"
        Department = "IT"
        Enabled = $true
        LastLogon = (Get-Date).AddDays(-15)
        PasswordLastSet = (Get-Date).AddDays(-30)
        PasswordNeverExpires = $false
    },
    [PSCustomObject]@{
        Username = "mjones"
        DisplayName = "Mary Jones"
        Department = "Finance"
        Enabled = $true
        LastLogon = (Get-Date).AddDays(-95)
        PasswordLastSet = (Get-Date).AddDays(-75)
        PasswordNeverExpires = $false
    },
    [PSCustomObject]@{
        Username = "bwilson"
        DisplayName = "Bob Wilson"
        Department = "HR"
        Enabled = $true
        LastLogon = (Get-Date).AddDays(-120)
        PasswordLastSet = (Get-Date).AddDays(-110)
        PasswordNeverExpires = $false
    },
    [PSCustomObject]@{
        Username = "svc_backup"
        DisplayName = "Backup Service Account"
        Department = "IT"
        Enabled = $true
        LastLogon = (Get-Date).AddDays(-200)
        PasswordLastSet = (Get-Date).AddDays(-365)
        PasswordNeverExpires = $true
    },
    [PSCustomObject]@{
        Username = "tdavis"
        DisplayName = "Tom Davis"
        Department = "Operations"
        Enabled = $true
        LastLogon = (Get-Date).AddDays(-5)
        PasswordLastSet = (Get-Date).AddDays(-20)
        PasswordNeverExpires = $false
    },
    [PSCustomObject]@{
        Username = "ghost_user1"
        DisplayName = "Former Employee"
        Department = "Sales"
        Enabled = $true
        LastLogon = (Get-Date).AddDays(-180)
        PasswordLastSet = (Get-Date).AddDays(-180)
        PasswordNeverExpires = $false
    },
    [PSCustomObject]@{
        Username = "admin_old"
        DisplayName = "Old Admin Account"
        Department = "IT"
        Enabled = $true
        LastLogon = (Get-Date).AddDays(-95)
        PasswordLastSet = (Get-Date).AddDays(-200)
        PasswordNeverExpires = $true
    },
    [PSCustomObject]@{
        Username = "lbrown"
        DisplayName = "Lisa Brown"
        Department = "Legal"
        Enabled = $true
        LastLogon = (Get-Date).AddDays(-10)
        PasswordLastSet = (Get-Date).AddDays(-45)
        PasswordNeverExpires = $false
    }
)

$SimulatedComputers = @(
    [PSCustomObject]@{
        ComputerName = "WORKSTATION-001"
        Department = "IT"
        Enabled = $true
        LastLogon = (Get-Date).AddDays(-5)
        OperatingSystem = "Windows 11 Pro"
    },
    [PSCustomObject]@{
        ComputerName = "WORKSTATION-002"
        Department = "Finance"
        Enabled = $true
        LastLogon = (Get-Date).AddDays(-95)
        OperatingSystem = "Windows 10 Pro"
    },
    [PSCustomObject]@{
        ComputerName = "GHOST-PC-001"
        Department = "Unknown"
        Enabled = $true
        LastLogon = (Get-Date).AddDays(-150)
        OperatingSystem = "Windows 7"
    },
    [PSCustomObject]@{
        ComputerName = "SERVER-001"
        Department = "IT"
        Enabled = $true
        LastLogon = (Get-Date).AddDays(-1)
        OperatingSystem = "Windows Server 2022"
    },
    [PSCustomObject]@{
        ComputerName = "GHOST-PC-002"
        Department = "Unknown"
        Enabled = $true
        LastLogon = (Get-Date).AddDays(-200)
        OperatingSystem = "Windows 7"
    },
    [PSCustomObject]@{
        ComputerName = "WORKSTATION-003"
        Department = "HR"
        Enabled = $true
        LastLogon = (Get-Date).AddDays(-30)
        OperatingSystem = "Windows 11 Pro"
    }
)

# =============================================================
# ANALYSIS
# =============================================================

Write-Host ("=" * 60)
Write-Host "  Active Directory Compliance Audit"
Write-Host "  Organization: $Organization"
Write-Host "  Audit Date: $ReportDate"
Write-Host ("=" * 60)

# Inactive user accounts (no logon in 90+ days)
$InactiveUsers = $SimulatedUsers | Where-Object {
    ((Get-Date) - $_.LastLogon).Days -ge $InactiveDays
}

# Stale passwords (not changed in 60+ days)
$StalePasswords = $SimulatedUsers | Where-Object {
    ((Get-Date) - $_.PasswordLastSet).Days -ge $PasswordAgeDays
}

# Non-expiring passwords (security violation)
$NonExpiringPasswords = $SimulatedUsers | Where-Object {
    $_.PasswordNeverExpires -eq $true
}

# Ghost systems (computers inactive 90+ days)
$GhostSystems = $SimulatedComputers | Where-Object {
    ((Get-Date) - $_.LastLogon).Days -ge $InactiveDays
}

# Legacy operating systems
$LegacyOS = $SimulatedComputers | Where-Object {
    $_.OperatingSystem -like "*Windows 7*" -or
    $_.OperatingSystem -like "*Windows XP*" -or
    $_.OperatingSystem -like "*Server 2008*"
}

# =============================================================
# CONSOLE OUTPUT
# =============================================================

Write-Host "`n[+] AUDIT FINDINGS SUMMARY"
Write-Host ("-" * 40)
Write-Host "  Total Users Audited        : $($SimulatedUsers.Count)"
Write-Host "  Total Computers Audited    : $($SimulatedComputers.Count)"
Write-Host "  Inactive User Accounts     : $($InactiveUsers.Count)"
Write-Host "  Stale Passwords            : $($StalePasswords.Count)"
Write-Host "  Non-Expiring Passwords     : $($NonExpiringPasswords.Count)"
Write-Host "  Ghost Systems              : $($GhostSystems.Count)"
Write-Host "  Legacy Operating Systems   : $($LegacyOS.Count)"

Write-Host "`n[!] INACTIVE USER ACCOUNTS (90+ days):"
$InactiveUsers | ForEach-Object {
    $DaysInactive = ((Get-Date) - $_.LastLogon).Days
    Write-Host "    - $($_.Username) ($($_.DisplayName)) | Last Logon: $DaysInactive days ago | Dept: $($_.Department)"
}

Write-Host "`n[!] GHOST SYSTEMS (90+ days inactive):"
$GhostSystems | ForEach-Object {
    $DaysInactive = ((Get-Date) - $_.LastLogon).Days
    Write-Host "    - $($_.ComputerName) | Last Logon: $DaysInactive days ago | OS: $($_.OperatingSystem)"
}

Write-Host "`n[!] NON-EXPIRING PASSWORDS (Security Violation):"
$NonExpiringPasswords | ForEach-Object {
    Write-Host "    - $($_.Username) ($($_.DisplayName)) | Dept: $($_.Department)"
}

Write-Host "`n[!] LEGACY OPERATING SYSTEMS:"
$LegacyOS | ForEach-Object {
    Write-Host "    - $($_.ComputerName) | OS: $($_.OperatingSystem)"
}

# =============================================================
# GENERATE TEXT REPORT
# =============================================================

$Report = @"
================================================
ACTIVE DIRECTORY COMPLIANCE AUDIT REPORT
================================================
Organization  : $Organization
Audit Date    : $ReportDate
Audited By    : Rohan Bhardwaj
Methodology   : Simulated AD audit based on real
                compliance work performed at General
                Dynamics Mission Systems Canada

================================================
EXECUTIVE SUMMARY
================================================
Total Users Audited        : $($SimulatedUsers.Count)
Total Computers Audited    : $($SimulatedComputers.Count)
Inactive User Accounts     : $($InactiveUsers.Count)
Stale Passwords            : $($StalePasswords.Count)
Non-Expiring Passwords     : $($NonExpiringPasswords.Count)
Ghost Systems Detected     : $($GhostSystems.Count)
Legacy Operating Systems   : $($LegacyOS.Count)

================================================
INACTIVE USER ACCOUNTS (90+ Days)
================================================
$($InactiveUsers | ForEach-Object {
    $Days = ((Get-Date) - $_.LastLogon).Days
    "Username    : $($_.Username)`nDisplay Name: $($_.DisplayName)`nDepartment  : $($_.Department)`nDays Inactive: $Days`nRecommendation: Disable and review for removal`n"
})

================================================
GHOST SYSTEMS (90+ Days Inactive)
================================================
$($GhostSystems | ForEach-Object {
    $Days = ((Get-Date) - $_.LastLogon).Days
    "Computer    : $($_.ComputerName)`nDepartment  : $($_.Department)`nOS          : $($_.OperatingSystem)`nDays Inactive: $Days`nRecommendation: Remove from domain and decommission`n"
})

================================================
NON-EXPIRING PASSWORDS
================================================
$($NonExpiringPasswords | ForEach-Object {
    "Username    : $($_.Username)`nDisplay Name: $($_.DisplayName)`nDepartment  : $($_.Department)`nRecommendation: Enable password expiration policy`n"
})

================================================
LEGACY OPERATING SYSTEMS
================================================
$($LegacyOS | ForEach-Object {
    "Computer    : $($_.ComputerName)`nOS          : $($_.OperatingSystem)`nRecommendation: Upgrade or decommission immediately`n"
})

================================================
REMEDIATION PRIORITIES
================================================
CRITICAL (Immediate Action):
1. Remove ghost systems from domain
2. Upgrade or isolate legacy OS machines
3. Enforce password expiration on service accounts

HIGH (Within 7 Days):
4. Disable inactive user accounts
5. Force password reset on stale accounts

MEDIUM (Within 30 Days):
6. Review and document all service accounts
7. Implement automated inactive account detection

================================================
END OF REPORT
================================================
"@

$Report | Out-File -FilePath $OutputFile -Encoding UTF8
Write-Host "`n[+] Report saved to: $(Resolve-Path $OutputFile)"
Write-Host "`n[+] Active Directory compliance audit complete"
Write-Host ("=" * 60)