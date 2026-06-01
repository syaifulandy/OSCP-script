# =============================================================
# AD ENUM REPORT (OSCP STYLE - ROBUST FULL VERSION)
# powershell -NoProfile -ExecutionPolicy Bypass -File ./adenum.ps1
# REQUIREMENTS: PowerView.ps1, PsLoggedon64.exe, sharpHound.exe
# =============================================================

$outfile = "$env:USERPROFILE\ad_enum_report.txt"
Remove-Item $outfile -ErrorAction SilentlyContinue

function write-section {
    param($title)
    Add-Content $outfile "`n========== $title =========="
}

Write-Host "[+] Saving report to $outfile"

# ===============================
# CHECK REQUIRED FILES
# ===============================
$required = @("PowerView.ps1","PsLoggedon64.exe","SharpHound.exe")
foreach ($file in $required) {
    if (-not (Test-Path ".\$file")) {
        Write-Host "[!] Missing required file: $file" -ForegroundColor Red
        exit
    } else {
        Write-Host "[+] Found: $file"
    }
}

# ===============================
# LOAD POWERVIEW
# ===============================
try {
    . .\PowerView.ps1
} catch {
    Write-Host "[!] Failed to load PowerView.ps1"
    exit
}

# ===============================
# DC AUTO DETECT
# ===============================
$DC = $null
try {
    $raw = nltest /dsgetdc:$env:USERDOMAIN
    if ($raw -match "Address:\s+\\\\(\d+\.\d+\.\d+\.\d+)") {
        $DC = $matches[1]
    }
} catch {}

if (-not $DC) {
    Write-Host "[!] DC auto-detect failed!" -ForegroundColor Yellow
    $DC = Read-Host "[?] Enter DC IP"
}
Write-Host "[+] Using DC: $DC"

# ===============================
# SAFE LDAP WRAPPER
# ===============================
function Invoke-LDAP {
    param($cmd,$name)
    try {
        return & $cmd
    } catch {
        Write-Host "[!] $name failed → retry using DC" -ForegroundColor Yellow
        try {
            return & $cmd -Server $DC
        } catch {
            Write-Host "[!] $name FAILED" -ForegroundColor Red
            Add-Content $outfile "[!] FAILED: $name"
            return $null
        }
    }
}

# ===============================
# DOMAIN INFO
# ===============================
$domainObj = Invoke-LDAP { Get-Domain -ErrorAction Stop } "Get-Domain"
$domainName = if ($domainObj) { $domainObj.Name } else { "UNKNOWN" }
$dnsRoot = if ($domainObj) { $domainObj.dnsroot } else { "UNKNOWN" }

# ===============================
# 1 HOSTS
# ===============================
Write-Host "[>] Enumerating Hosts..." -ForegroundColor Cyan
write-section "HOSTS"

$hosts = Invoke-LDAP { Get-DomainComputer -Properties dnshostname,OperatingSystem -ErrorAction Stop } "Get-DomainComputer"

if ($hosts) {
    foreach ($h in $hosts) {
        $ip=""
        try {
            $ip = ([System.Net.Dns]::GetHostAddresses($h.dnshostname) |
            Where-Object {$_.AddressFamily -eq "InterNetwork"} |
            Select -First 1).IPAddressToString
        } catch {}
        "$($h.dnshostname);$($h.OperatingSystem);$ip" | Add-Content $outfile
    }
}

# ===============================
# 2 USERS
# ===============================
Write-Host "[>] Enumerating Users..." -ForegroundColor Cyan
write-section "USERS"

$users = Invoke-LDAP { Get-DomainUser -Properties samaccountname -ErrorAction Stop } "Get-DomainUser"
if ($users) {
    $users | % { "$($_.samaccountname)@$domainName" } | Add-Content $outfile
}

# ===============================
# 3 ADMIN GROUPS
# ===============================
Write-Host "[>] Mapping Admin Groups..." -ForegroundColor Cyan
write-section "ADMIN GROUP MEMBERS"

$currentSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
$currentUser = whoami
$groups = @("Domain Admins","Administrators","Enterprise Admins")
$allAdmins = @()

foreach ($g in $groups) {
    try {
        $members = Get-DomainGroupMember -Identity $g -Recurse -Server $DC
        Add-Content $outfile "--- $g ---"
        foreach ($m in $members) {
            $line = "$($m.MemberName) ($($m.ObjectClass));$($m.MemberSID)"
            if ($m.MemberSID -eq $currentSID -or $m.MemberName -match $currentUser) {
                $line = "[CURRENT ADMIN] $line"
            }
            $allAdmins += $m
            Add-Content $outfile $line
        }
    } catch {
        Add-Content $outfile "[!] Failed group: $g"
    }
}

# ===============================
# 4 RELEVANT GROUPS
# ===============================
Write-Host "[>] Filtering Relevant Groups..." -ForegroundColor Cyan
write-section "RELEVANT GROUPS"

try {
    Get-DomainGroup -Server $DC -Properties Name,Description |
    Where-Object {$_.Name -match "Admin|Remote|SQL|Backup|IT|Dev"} |
    % { "$($_.Name) -- $($_.Description)" } | Add-Content $outfile
} catch {
    Add-Content $outfile "[!] Group enumeration failed"
}

# ===============================
# 5 GPO EXPLOIT
# ===============================
Write-Host "[>] Checking GPO Exploits..." -ForegroundColor Cyan
write-section "GPO EXPLOITABILITY"

$gpos = Invoke-LDAP { Get-DomainGPO -ErrorAction Stop } "Get-DomainGPO"
$me = whoami
$foundExploit = $false
$exploitable = @()

if ($gpos) {
    $domainLinks = Get-DomainObject -SearchScope Base -Server $DC
    $ous = Get-DomainOU -Server $DC
    $sites = Get-DomainSite -Server $DC

    foreach ($gpo in $gpos) {
        try {
            $acls = Get-DomainObjectAcl -Identity $gpo.distinguishedname -ResolveGUIDs -Server $DC |
            Where { $_.ActiveDirectoryRights -match "Write|Create|Delete" }

            foreach ($acl in $acls) {
                $id = ConvertFrom-SID $acl.SecurityIdentifier
                if ($id -ne $me) { continue }

                $foundExploit = $true
                $exploitable += $gpo.displayname

                Add-Content $outfile "[!] EXPLOITABLE GPO: $($gpo.displayname)"
                Add-Content $outfile "Rights: $($acl.ActiveDirectoryRights)"
            }
        } catch {}
    }
}

if (-not $foundExploit) {
    Add-Content $outfile "[+] No exploitable GPO"
}

# ===============================
# 6 LATERAL
# ===============================
Write-Host "[>] Hunting Lateral Movement..." -ForegroundColor Yellow
write-section "LATERAL MOVEMENT"

$localAdminFound = $false
try {
    Find-LocalAdminAccess -Server $DC | % {
        Add-Content $outfile "[+] LOCAL ADMIN: $_"
        $localAdminFound = $true
    }
} catch {}

if (-not $localAdminFound) {
    Add-Content $outfile "No Local Admin access"
}

# ===============================
# 7 ASREP
# ===============================
Write-Host "[>] ASREP..." -ForegroundColor Cyan
write-section "AS-REP"

try {
    Get-DomainUser -Server $DC -PreauthNotRequired |
    % { "[!!!] $($_.samaccountname)" } | Add-Content $outfile
} catch {
    Add-Content $outfile "None"
}

# ===============================
# 8 KERBEROAST
# ===============================
Write-Host "[>] Kerberoast..." -ForegroundColor Cyan
write-section "KERBEROAST"

try {
    Get-DomainUser -Server $DC -SPN |
    % { "$($_.samaccountname);$($_.serviceprincipalname)" } | Add-Content $outfile
} catch {
    Add-Content $outfile "None"
}

# ===============================
# 9 PSLOGGEDON
# ===============================
Write-Host "[>] Running PsLoggedon..." -ForegroundColor Yellow
write-section "PSLOGGEDON"

$results = @()
foreach ($c in $hosts.dnshostname) {
    try {
        $tmp = "$env:TEMP\$c.txt"
        cmd /c "PsLoggedon64.exe \\$c -accepteula > $tmp 2>&1"
        if (Test-Path $tmp) {
            Get-Content $tmp | Where {$_ -match "\\"} |
            % { $results += "$($c);$($_.Trim())" }
            Remove-Item $tmp
        }
    } catch {}
}

if ($results) { $results | sort -Unique | Add-Content $outfile }
else { Add-Content $outfile "Null" }

# ===============================
# SHARPHOUND AUTO RUN
# ===============================
Write-Host "[>] Running SharpHound..." -ForegroundColor Cyan
try {
    .\SharpHound.exe -c All
    Add-Content $outfile "[+] SharpHound executed"
} catch {
    Add-Content $outfile "[!] SharpHound failed"
}

# ===============================
# DONE
# ===============================
Write-Host "[+] DONE → $outfile" -ForegroundColor Green
