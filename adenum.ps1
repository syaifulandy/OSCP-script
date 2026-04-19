# ===============================
# AD ENUM REPORT (OSCP STYLE - FINAL)
# powershell -NoProfile -ExecutionPolicy Bypass -File ./adenum.ps1
# ===============================

$outfile = "$env:USERPROFILE\ad_enum_report.txt"
Remove-Item $outfile -ErrorAction SilentlyContinue

function write-section {
    param($title)
    Add-Content $outfile "`n========== $title =========="
}

Write-Host "[+] Saving report to $outfile"

# ===============================
# LOAD POWERVIEW
# ===============================
if (-not (Get-Command Get-DomainUser -ErrorAction SilentlyContinue)) {
    try {
        . .\PowerView.ps1
    } catch {
        Write-Host "[!] PowerView.ps1 not found!"
        exit
    }
}

# ===============================
# GET DOMAIN (biar konsisten format user@domain)
# ===============================
$domain = (Get-Domain).Name

# ===============================
# 1. HOSTS
# ===============================
write-section "HOSTS"

$hosts = Get-DomainComputer

if ($hosts.Count -eq 0) {
    Add-Content $outfile "Null"
} else {
    $hosts | ForEach-Object {
        $ip = ""
        try {
            $ip = ([System.Net.Dns]::GetHostAddresses($_.dnshostname) |
            Where-Object {$_.AddressFamily -eq "InterNetwork"} |
            Select -First 1).IPAddressToString
        } catch {}

        "$($_.dnshostname);$($_.OperatingSystem);$ip" | Add-Content $outfile
    }
}

# ===============================
# 2. USERS
# ===============================
write-section "USERS"

$users = Get-DomainUser

if ($users.Count -eq 0) {
    Add-Content $outfile "Null"
} else {
    $users | ForEach-Object {
        "$($_.samaccountname)@$domain" | Add-Content $outfile
    }
}

# ===============================
# 3. DOMAIN ADMINS
# ===============================
write-section "DOMAIN ADMINS"

$da = Get-DomainGroupMember "Domain Admins"

if ($da.Count -eq 0) {
    Add-Content $outfile "Null"
} else {
    $da | ForEach-Object {
        "$($_.MemberName)" | Add-Content $outfile
    }
}

# ===============================
# 4. GROUPS
# ===============================
write-section "GROUPS"

$groups = Get-DomainGroup

if ($groups.Count -eq 0) {
    Add-Content $outfile "Null"
} else {
    $groups | Select -ExpandProperty Name | Add-Content $outfile
}

# ===============================
# 5. GPO
# ===============================
write-section "GPO"

$gpos = Get-DomainGPO

if ($gpos.Count -eq 0) {
    Add-Content $outfile "Null"
} else {
    $gpos | Select -ExpandProperty displayname | Add-Content $outfile
}

# ===============================
# 6. BLOODHOUND-LIKE (STEALTH LIMITATION)
# ===============================
write-section "RDP Access"
Add-Content $outfile "Null"

write-section "Local Admin Access"
Add-Content $outfile "Null"

write-section "Shortest Path to Domain Admins"
Add-Content $outfile "Null"

# ===============================
# 7. ACTIVE SESSIONS
# ===============================
write-section "ACTIVE SESSIONS"

$sessionsFound = @()

$hosts = Get-DomainComputer | Select -ExpandProperty dnshostname

foreach ($host in $hosts) {
    try {
        $sessions = Get-NetSession -ComputerName $host -ErrorAction SilentlyContinue

        foreach ($s in $sessions) {
            $user = $s.UserName

            if ($user -match "^S-1-5-21-.*-500$") {
                $user = "LOCAL_ADMINISTRATOR"
            }

            "$host;$user" | Add-Content $outfile
        }
    } catch {}
}

if (-not (Select-String -Path $outfile -Pattern "ACTIVE SESSIONS" -Quiet)) {
    Add-Content $outfile "Null"
}

# ===============================
# 8. KERBEROASTABLE USERS
# ===============================
write-section "KERBEROASTABLE USERS"

$spn = Get-DomainUser -SPN

if ($spn.Count -eq 0) {
    Add-Content $outfile "Null"
} else {
    $spn | ForEach-Object {
        "$($_.samaccountname)@$domain;$($_.serviceprincipalname)" | Add-Content $outfile
    }
}

# ===============================
# DONE
# ===============================
Write-Host "[+] DONE!"
Write-Host "[+] Report saved to: $outfile"
