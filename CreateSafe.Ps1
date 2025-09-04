# --- Allow this process to load unsigned modules & unblock psPAS files (silent) ---
try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop } catch {}

$psPASDirs = @(
  "$env:ProgramFiles\WindowsPowerShell\Modules\psPAS\6.4.85",
  "$HOME\Documents\WindowsPowerShell\Modules\psPAS\6.4.85"
) | Where-Object { Test-Path $_ }

foreach ($dir in $psPASDirs) {
  try { Get-ChildItem -Path $dir -Recurse -File | Unblock-File -ErrorAction SilentlyContinue } catch {}
}

# --- Logging Utility ---
$LogPath = "E:\Installation Media\Script\OnboardScript\accountonboarding.txt"
Function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$Timestamp - $Message"
    try { Write-Host $LogEntry -ForegroundColor $Color } catch { Write-Host $LogEntry }
    try { Add-Content -Path $LogPath -Value $LogEntry } catch {}
}

# --- Console "box" helper (for fallback dialog text) ---
Function Show-Box {
    param([string]$Title, [string]$BodyLine1 = "", [string]$BodyLine2 = "")
    $line = ('=' * 72)
    Write-Host $line -ForegroundColor DarkGray
    if ($Title)    { Write-Host ("[ " + $Title + " ]") -ForegroundColor Gray }
    if ($BodyLine1){ Write-Host $BodyLine1 -ForegroundColor Gray }
    if ($BodyLine2){ Write-Host $BodyLine2 -ForegroundColor Gray }
    Write-Host $line -ForegroundColor DarkGray
}

# --- Load psPAS ---
try {
    Import-Module psPAS -Force -ErrorAction Stop
    $mod = Get-Module psPAS
    Write-Log ("psPAS loaded ({0})." -f $mod.Version) "Green"
} catch {
    Write-Log ("❌ psPAS module not found/loaded: {0}" -f $_.Exception.Message) "Red"
    exit 1
}

# --- Try to import AD module for OU validation (non-fatal if missing) ---
$ADModuleLoaded = $false
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $ADModuleLoaded = $true
} catch {
    Write-Log "⚠️ ActiveDirectory module not available; will still try to add group by UPN." "Yellow"
}

# --- CCP parameters (shared) ---
$CCPAddress = "https://vskau1p1231.cna.com"
$location   = "AIMWebService"
$application= "PAMDiscovery"
$safeCCP    = "CA_PCloud_Admins"
$headers    = @{ "Content-Type" = "application/json" }
$windowsAuth = $false

# --- Helper: start a PAS session from CCP creds using the SAME psPAS Identity method ---
Function Start-PASSessionFromCCP {
    param(
        [Parameter(Mandatory)] [string]$ObjectName,   # e.g. cna.com-CA_PAMDiscovery_SVC
        [Parameter(Mandatory)] [string]$UPUser        # e.g. CA_PAMDiscovery_SVC
    )
    $ccpUrl = "$CCPAddress/$location/api/Accounts?AppID=$application&Safe=$safeCCP&Object=$ObjectName"
    Write-Log ("Retrieving CyberArk API credentials from CCP ({0}) via Object method..." -f $UPUser)
    try {
        $resp = Invoke-RestMethod $ccpUrl -Method 'GET' -Headers $headers -UseDefaultCredentials:$windowsAuth
        if (-not $resp -or -not $resp.Content) { throw "Empty CCP response" }
        Write-Log ("✅ Successfully retrieved credentials for user: {0}" -f $resp.Username) "Green"
    } catch {
        Write-Log ("❌ ERROR: CCP credential fetch failed - {0}" -f $_) "Red"
        throw
    }

    try {
        Write-Log ("Requesting CyberArk PAS authentication (psPAS Identity header) as {0}..." -f $UPUser)
        $UPPass = ConvertTo-SecureString $resp.Content -AsPlainText -Force
        $UPCred = [PSCredential]::new($UPUser, $UPPass)

        $header = Get-IdentityHeader `
            -IdentityTenantURL "aat4012.id.cyberark.cloud" `
            -psPASFormat `
            -PCloudSubdomain "cna-prod" `
            -UPCreds $UPCred

        Use-PASSession $header
        if (-not (Get-PASSession)) { throw "psPAS session not established" }
        Write-Log ("✅ Authentication successful, PAS session established ({0})." -f $UPUser) "Green"
    } catch {
        Write-Log ("❌ Failed to authenticate via psPAS Identity header: {0}" -f $_.Exception.Message) "Red"
        throw
    }

    return $resp   # return CCP record (may be useful later)
}

# --- Permissions (psPAS-friendly) ---
$LimitedPermPAS = [PSCustomObject]@{
    UseAccounts                            = $false
    RetrieveAccounts                       = $false
    ListAccounts                           = $true
    AddAccounts                            = $false
    UpdateAccountContent                   = $false
    UpdateAccountProperties                = $false
    InitiateCPMAccountManagementOperations = $true
    SpecifyNextAccountContent              = $false
    RenameAccounts                         = $false
    DeleteAccounts                         = $false
    UnlockAccounts                         = $true
    ManageSafe                             = $false
    ManageSafeMembers                      = $false
    BackupSafe                             = $false
    ViewAuditLog                           = $true
    ViewSafeMembers                        = $true
    AccessWithoutConfirmation              = $true
    CreateFolders                          = $false
    DeleteFolders                          = $false
    MoveAccountsAndFolders                 = $false
    RequestsAuthorizationLevel1            = $true
    RequestsAuthorizationLevel2            = $false
}
$FullPermPAS = [PSCustomObject]@{
    UseAccounts                            = $true
    RetrieveAccounts                       = $true
    ListAccounts                           = $true
    AddAccounts                            = $true
    UpdateAccountContent                   = $true
    UpdateAccountProperties                = $true
    InitiateCPMAccountManagementOperations = $true
    SpecifyNextAccountContent              = $true
    RenameAccounts                         = $true
    DeleteAccounts                         = $true
    UnlockAccounts                         = $true
    ManageSafe                             = $true
    ManageSafeMembers                      = $true
    BackupSafe                             = $true
    ViewAuditLog                           = $true
    ViewSafeMembers                        = $true
    AccessWithoutConfirmation              = $true
    CreateFolders                          = $true
    DeleteFolders                          = $true
    MoveAccountsAndFolders                 = $true
    RequestsAuthorizationLevel1            = $true
    RequestsAuthorizationLevel2            = $false
}

# --- AD Group validation helper ---
$SearchBaseOU = 'OU=Groups,OU=CyberArk,DC=cna,DC=com'
Function Read-ValidGroup {
    while ($true) {
        $g = Read-Host "Enter the AD Safe Group (sAMAccountName only, e.g., ca_xxx_xxx_prod)"
        if ([string]::IsNullOrWhiteSpace($g)) { Write-Log "❌ Group cannot be empty." "Red"; continue }
        if ($g -notmatch '^[A-Za-z0-9_\-\.]+$') { Write-Log "❌ Invalid characters in group name. Try again." "Red"; continue }

        if ($ADModuleLoaded) {
            try {
                $adGroup = Get-ADGroup -LDAPFilter "(|(sAMAccountName=$g)(userPrincipalName=$g@cna.com))" -SearchBase $SearchBaseOU -ErrorAction Stop
                if ($adGroup) {
                    Write-Log ("✅ Found AD Group in {0}: {1} (sAM={2})" -f $SearchBaseOU, $adGroup.Name, $adGroup.SamAccountName) "Green"
                    return $g
                } else {
                    Write-Log ("❌ Group not found under {0}. Re-enter." -f $SearchBaseOU) "Red"
                }
            } catch {
                Write-Log ("❌ Error searching AD for '{0}' in {1}: {2}" -f $g, $SearchBaseOU, $_.Exception.Message) "Red"
            }
        } else {
            Write-Log "⚠️ AD module not loaded, proceeding with provided group name (will add as UPN)." "Yellow"
            return $g
        }
    }
}

# --- Member add helper (psPAS) ---
Function Add-MemberToSafe {
    param(
        [string]$SafeName,
        [string]$MemberName,
        [ValidateSet("Group","User","Role")]
        [string]$MemberType,
        [pscustomobject]$Permissions
    )
    try {
        Write-Log ("Adding {0} '{1}' to {2}..." -f $MemberType, $MemberName, $SafeName)
        $Permissions | Add-PASSafeMember -SafeName $SafeName -MemberType $MemberType -MemberName $MemberName -ErrorAction Stop | Out-Null
        Write-Log ("✅ Added {0}: {1}." -f $MemberType, $MemberName) "Green"
        return $true
    } catch {
        Write-Log ("❌ Failed to add '{0}' - {1}" -f $MemberName, $_.Exception.Message) "Red"
        return $false
    }
}

# =========================
# FIRST SESSION (DISCOVERY)
# =========================
# Login (psPAS) using CCP creds of CA_PAMDiscovery_SVC
$response1 = $null
try {
    $response1 = Start-PASSessionFromCCP -ObjectName "cna.com-CA_PAMDiscovery_SVC" -UPUser "CA_PAMDiscovery_SVC"
} catch { exit 1 }

# Prompt for Safe Name
$SafeName = Read-Host "Enter the Safe Name"

# GUI InputBox for description; fallback to Read-Host
$DescriptionRaw = $null
try {
    Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop
    $DescriptionRaw = [Microsoft.VisualBasic.Interaction]::InputBox(
        "Paste a single-line description for the Safe (max 200 chars).",
        "Safe Description",
        ""
    )
} catch {
    Show-Box -Title "Safe Description" `
        -BodyLine1 "Paste a single-line description for the Safe (max 200 characters)." `
        -BodyLine2 "Example: 'Service accounts for AppX PROD'."
    $DescriptionRaw = Read-Host "Enter the Safe Description (single line, up to 200 chars)"
}

if ([string]::IsNullOrWhiteSpace($SafeName))       { Write-Log "❌ ERROR: Safe Name cannot be empty. Exiting..." "Red"; exit 1 }
if ([string]::IsNullOrWhiteSpace($DescriptionRaw)) { Write-Log "❌ ERROR: Safe Description cannot be empty. Exiting..." "Red"; exit 1 }

$Description = $DescriptionRaw.Trim()
if ($Description.Length -gt 200) {
    Write-Log "ℹ️ Safe Description >200 chars, auto-truncating."
    $Description = $Description.Substring(0,200)
}

# Create Safe (updated: using NumberOfDaysRetention = 120)
$ManagingCPM = "CNA_PASS_MANG"
try {
    Write-Log ("🔹 Creating Safe: {0}..." -f $SafeName)
    Add-PASSafe -SafeName $SafeName -ManagingCPM $ManagingCPM -Description $Description -NumberOfDaysRetention 120 -ErrorAction Stop | Out-Null
    Write-Log ("✅ Successfully created Safe: {0}." -f $SafeName) "Green"
} catch {
    Write-Log ("⚠️ Could not create Safe '{0}': {1}. Continuing to member add..." -f $SafeName, $_.Exception.Message) "Yellow"
}

# Read target AD group & add members
$GroupSam       = Read-ValidGroup
$TargetGroupUPN = "$GroupSam@cna.com"

$MembersToAdd = @(
    @{ Name = $TargetGroupUPN;                     Type = "Group"; Perm = $LimitedPermPAS }, # target AD group (Limited)
    @{ Name = "CA_PCloud_Admins@cna.com";          Type = "Group"; Perm = $FullPermPAS    }, # Full
    @{ Name = "cna_pas_admin@cyberark.cloud.6679"; Type = "User";  Perm = $FullPermPAS    }, # Full
    @{ Name = "cnarestbot@cyberark.cloud.6679";    Type = "User";  Perm = $FullPermPAS    }  # Full
)

foreach ($m in $MembersToAdd) {
    [void](Add-MemberToSafe -SafeName $SafeName -MemberName $m.Name -MemberType $m.Type -Permissions $m.Perm)
}
Write-Log "✅ Safe member addition process completed." "Green"

# Close FIRST session
try { Close-PASSession | Out-Null; Write-Log "✅ PAS session closed (CA_PAMDiscovery_SVC)." "Green" } catch {}

# =========================
# SECOND SESSION (SAME USER, psPAS)
# =========================
$response2 = $null
try {
    $response2 = Start-PASSessionFromCCP -ObjectName "cna.com-CA_PAMDiscovery_SVC" -UPUser "CA_PAMDiscovery_SVC"
} catch { exit 1 }

# (Optional visibility) List members before removal
try {
    $members = Get-PASSafeMember -SafeName $SafeName -ErrorAction Stop
    foreach ($m in $members) {
        $n = $null; $t = $null
        if ($m.PSObject.Properties.Name -contains 'MemberName') { $n = "$($m.MemberName)" }
        elseif ($m.PSObject.Properties.Name -contains 'UserName') { $n = "$($m.UserName)" }
        elseif ($m.PSObject.Properties.Name -contains 'Username') { $n = "$($m.Username)" }
        if ($m.PSObject.Properties.Name -contains 'MemberType') { $t = "$($m.MemberType)" }
        Write-Log ("🔎 Member found: Name='{0}', Type='{1}'" -f $n, $t) "Gray"
    }
} catch {
    Write-Log ("ℹ️ Could not list members before removal: {0}" -f $_.Exception.Message) "Yellow"
}

# Remove the discovery user (self) using psPAS only - WITH @cna.com
$memberToRemove = 'CA_PAMDiscovery_SVC@cna.com'
try {
    Write-Log ("Attempting removal via psPAS: Remove-PASSafeMember -SafeName {0} -MemberName {1}" -f $SafeName, $memberToRemove)
    Remove-PASSafeMember -SafeName $SafeName -MemberName $memberToRemove -ErrorAction Stop | Out-Null
    Write-Log ("✅ Removed '{0}' from Safe '{1}' via psPAS." -f $memberToRemove, $SafeName) "Green"
} catch {
    Write-Log ("❌ Could not remove '{0}' via psPAS: {1}" -f $memberToRemove, $_.Exception.Message) "Red"
}

# Close SECOND session
try { Close-PASSession | Out-Null; Write-Log "✅ PAS session closed (second session, CA_PAMDiscovery_SVC)." "Green" } catch {}

Write-Log "✅ Completed Safe creation, member additions, second login (same user), and discovery principal cleanup." "Green"
