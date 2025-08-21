# --- Logging Utility ---
$LogPath = "E:\Installation Media\Script\OnboardScript\accountonboarding.txt"
Function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$Timestamp - $Message"
    Write-Host $LogEntry -ForegroundColor $Color
    Add-Content -Path $LogPath -Value $LogEntry
}

# Helper for JSON POSTs
Function Invoke-CybrPostJson {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][hashtable]$Headers,
        [Parameter(Mandatory)]$BodyObject
    )
    $json = ($BodyObject | ConvertTo-Json -Depth 8 -Compress)
    Invoke-RestMethod -Uri $Uri -Method Post -Headers $Headers -Body $json -ErrorAction Stop
}

# --- Retrieve CyberArk API Credentials from CCP ---
$CCPAddress = "https://vskau1p1231.cna.com"
$location   = "AIMWebService"
$application= "PAMDiscovery"
$safe       = "CA_PCloud_Admins"
$object     = "cna-prod.cyberark.cloud-cnarestbot@cyberark.cloud.6679"

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/json")
$windowsAuth = $false

Write-Log "Retrieving CyberArk API credentials from CCP via Object method..." "Cyan"
$ccpUrl = "$CCPAddress/$location/api/Accounts?AppID=$application&Safe=$safe&Object=$object"
try {
    $response = Invoke-RestMethod $ccpUrl -Method 'GET' -Headers $headers -UseDefaultCredentials:$windowsAuth
    if (-not $response -or -not $response.Username -or -not $response.Content) {
        Write-Log "ERROR: Failed to retrieve API credentials from CCP." "Red"
        exit 1
    }
    Write-Log "Successfully retrieved credentials for user: $($response.Username)" "Green"
} catch {
    Write-Log "ERROR: CCP credential fetch failed - $_" "Red"
    exit 1
}

# --- Prompt for Safe Name & single-line Description (<=200 chars) ---
$SafeName    = Read-Host "Enter the Safe Name"
$Description = Read-Host "Enter the Safe Description (single line, up to 200 chars)"
if ([string]::IsNullOrWhiteSpace($SafeName))    { Write-Log "❌ ERROR: Safe Name cannot be empty. Exiting..." "Red"; exit }
if ([string]::IsNullOrWhiteSpace($Description)) { Write-Log "❌ ERROR: Safe Description cannot be empty. Exiting..." "Red"; exit }
if ($Description.Length -gt 200) {
    Write-Log "ℹ️ Description longer than 200 chars; truncating."
    $Description = $Description.Substring(0,200)
}

# --- Authentication Variables (from CCP) ---
$IdentityTenantID = "aat4012"      # CyberArk Identity tenant ID
$PCloudSubdomain  = "cna-prod"     # PVWA subdomain
$ClientID         = $response.Username
$ClientSecret     = $response.Content

if ([string]::IsNullOrWhiteSpace($ClientID) -or [string]::IsNullOrWhiteSpace($ClientSecret)) {
    Write-Log "ERROR: Client ID or Client Secret is missing. Exiting..."
    exit
}

# --- Request OAuth Token (ISPSS) ---
Write-Log "Requesting initial CyberArk ISPSS token..."
$TokenURL = "https://$IdentityTenantID.id.cyberark.cloud/oauth2/platformtoken"
$TokenBody = @{
    grant_type    = "client_credentials"
    client_id     = $ClientID
    client_secret = $ClientSecret
}
$headers_token = @{ "Content-Type" = "application/x-www-form-urlencoded" }

try {
    $TokenResponse = Invoke-RestMethod -Uri $TokenURL -Method Post -Headers $headers_token -Body $TokenBody
    $BearerToken = [string]$TokenResponse.access_token
    if ([string]::IsNullOrWhiteSpace($BearerToken) -or $BearerToken.Length -lt 100) {
        Write-Log "ERROR: Received an invalid token. Length: $($BearerToken.Length)"
        exit
    }
    Write-Log "✅ Authentication successful, token obtained."
} catch {
    Write-Log "ERROR: Failed to authenticate with CyberArk ISPSS. $_"
    exit
}

# --- Define Headers for PVWA REST ---
$headers_api = @{
    "Authorization" = "Bearer $BearerToken"
    "Content-Type"  = "application/json"
}

# --- Create Safe Using REST API ---
Write-Log "🔹 Creating Safe: ${SafeName}..."
$SafesEndpoint = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/"
$SafePayload = @{
    safeName              = $SafeName
    description           = $Description
    olacEnabled           = $false
    autoPurgeEnabled      = $false
    managingCPM           = "CNA_PASS_MANG"
    numberOfDaysRetention = 180
}
Write-Log "Creating Safe: ${SafeName} with payload: $(($SafePayload | ConvertTo-Json -Depth 3))"
try {
    Invoke-CybrPostJson -Uri $SafesEndpoint -Headers $headers_api -BodyObject $SafePayload | Out-Null
    Write-Log "✅ Successfully created Safe: ${SafeName}."
} catch {
    # Usually indicates Safe already exists; proceed to member handling anyway.
    Write-Log "⚠️ Safe create returned: $($_.Exception.Message). Continuing..." "Yellow"
}

# --- Permissions (AFTER safe creation, per your pattern) ---
$LimitedPermissions = @{
    useAccounts = $false
    retrieveAccounts = $false
    listAccounts = $true
    addAccounts = $false
    updateAccountContent = $false
    updateAccountProperties = $false
    initiateCPMAccountManagementOperations = $true
    specifyNextAccountContent = $false
    renameAccounts = $false
    deleteAccounts = $false
    unlockAccounts = $true
    manageSafe = $false
    manageSafeMembers = $false
    backupSafe = $false
    viewAuditLog = $true
    viewSafeMembers = $true
    accessWithoutConfirmation = $true
    createFolders = $false
    deleteFolders = $false
    moveAccountsAndFolders = $false
    requestsAuthorizationLevel1 = $true
    requestsAuthorizationLevel2 = $false
}
$FullPermissions = @{
    useAccounts = $true
    retrieveAccounts = $true
    listAccounts = $true
    addAccounts = $true
    updateAccountContent = $true
    updateAccountProperties = $true
    initiateCPMAccountManagementOperations = $true
    specifyNextAccountContent = $true
    renameAccounts = $true
    deleteAccounts = $true
    unlockAccounts = $true
    manageSafe = $true
    manageSafeMembers = $true
    backupSafe = $true
    viewAuditLog = $true
    viewSafeMembers = $true
    accessWithoutConfirmation = $true
    createFolders = $true
    deleteFolders = $true
    moveAccountsAndFolders = $true
    requestsAuthorizationLevel1 = $true
    requestsAuthorizationLevel2 = $false
}

# Convert REST-style -> psPAS role object with PascalCase, for Add/Set-PASSafeMember
Function Convert-ToPasRole {
    param($perm)
    [PSCustomObject]@{
        UseAccounts                            = [bool]$perm.useAccounts
        RetrieveAccounts                       = [bool]$perm.retrieveAccounts
        ListAccounts                           = [bool]$perm.listAccounts
        AddAccounts                            = [bool]$perm.addAccounts
        UpdateAccountContent                   = [bool]$perm.updateAccountContent
        UpdateAccountProperties                = [bool]$perm.updateAccountProperties
        InitiateCPMAccountManagementOperations = [bool]$perm.initiateCPMAccountManagementOperations
        SpecifyNextAccountContent              = [bool]$perm.specifyNextAccountContent
        RenameAccounts                         = [bool]$perm.renameAccounts
        DeleteAccounts                         = [bool]$perm.deleteAccounts
        UnlockAccounts                         = [bool]$perm.unlockAccounts
        ManageSafe                             = [bool]$perm.manageSafe
        ManageSafeMembers                      = [bool]$perm.manageSafeMembers
        BackupSafe                             = [bool]$perm.backupSafe
        ViewAuditLog                           = [bool]$perm.viewAuditLog
        ViewSafeMembers                        = [bool]$perm.viewSafeMembers
        AccessWithoutConfirmation              = [bool]$perm.accessWithoutConfirmation
        CreateFolders                          = [bool]$perm.createFolders
        DeleteFolders                          = [bool]$perm.deleteFolders
        MoveAccountsAndFolders                 = [bool]$perm.moveAccountsAndFolders
        RequestsAuthorizationLevel1            = [bool]$perm.requestsAuthorizationLevel1
        RequestsAuthorizationLevel2            = [bool]$perm.requestsAuthorizationLevel2
    }
}
$LimitedRole = Convert-ToPasRole $LimitedPermissions
$FullRole    = Convert-ToPasRole $FullPermissions

# --- Ensure psPAS session (prefer your PAPMAPIConnect helper) ---
try {
    if (Get-Command -Name PAPMAPIConnect -ErrorAction SilentlyContinue) {
        Write-Log "Establishing PVWA session via PAPMAPIConnect..."
        PAPMAPIConnect
    } else {
        # Fallback: assume session is already established externally
        Write-Log "ℹ️ PAPMAPIConnect not found; assuming psPAS session already established." "Yellow"
    }
} catch {
    Write-Log "⚠️ PAPMAPIConnect failed: $($_.Exception.Message). Add/Set-PASSafeMember may fail without a session." "Yellow"
}

# --- Helper: add-or-update member via psPAS, NO -SearchIn used ---
Function Ensure-SafeMember {
    param(
        [Parameter(Mandatory)][string]$SafeName,
        [Parameter(Mandatory)][ValidateSet('User','Group','Role')]$MemberType,
        [Parameter(Mandatory)][string]$MemberName,
        [Parameter(Mandatory)]$RoleObject
    )
    try {
        $existing = (Get-PASSafeMember -SafeName $SafeName -ErrorAction SilentlyContinue).Username
    } catch { $existing = @() }

    if ($existing -and ($existing -contains $MemberName)) {
        Write-Log "Updating $MemberType '$MemberName' on $SafeName (psPAS)..."
        try {
            $RoleObject | Set-PASSafeMember -SafeName $SafeName -MemberName $MemberName -ErrorAction Stop | Out-Null
            Write-Log "✅ Updated $MemberType: $MemberName."
        } catch {
            Write-Log "❌ Failed to update '$MemberName' - $($_.Exception.Message)" "Red"
        }
    } else {
        Write-Log "Adding $MemberType '$MemberName' to $SafeName (psPAS)..."
        try {
            $RoleObject | Add-PASSafeMember -SafeName $SafeName -memberType $MemberType -MemberName $MemberName -ErrorAction Stop | Out-Null
            Write-Log "✅ Added $MemberType: $MemberName."
        } catch {
            Write-Log "❌ Failed to add '$MemberName' - $($_.Exception.Message)" "Red"
        }
    }
}

# --- Target AD group: validate in specific OU, then add with NO -SearchIn ---
$SearchBaseOU = "OU=Groups,OU=CyberArk,DC=cna,DC=com"
$TargetSam = $null
$ADReady = $true
if (-not (Get-Command Get-ADGroup -ErrorAction SilentlyContinue)) {
    Write-Log "⚠️ RSAT AD module not found. Cannot validate group in AD; proceeding without AD check." "Yellow"
    $ADReady = $false
}
do {
    $TargetSam = Read-Host "Enter the AD Safe Group (sAMAccountName only, e.g., ca_bud_ecf_prod)"
    if ([string]::IsNullOrWhiteSpace($TargetSam)) {
        Write-Log "❌ Group name cannot be empty. Please re-enter." "Red"
        $TargetSam = $null
        continue
    }
    if ($ADReady) {
        try {
            $adGroup = Get-ADGroup -LDAPFilter "(sAMAccountName=$TargetSam)" -SearchBase $SearchBaseOU -ErrorAction Stop
        } catch { $adGroup = $null }
        if (-not $adGroup) {
            Write-Log "❌ '$TargetSam' not found under $SearchBaseOU. Please re-enter." "Red"
            $TargetSam = $null
        }
    }
} while (-not $TargetSam)

# Format as UPN per your preference (no DOMAIN\GroupName)
$TargetUPN = "$TargetSam@cna.com"
Write-Log "Adding AD Group '$TargetUPN' via psPAS Add-PASSafeMember..."
Ensure-SafeMember -SafeName $SafeName -MemberType Group -MemberName $TargetUPN -RoleObject $LimitedRole

# --- Other full-permission members (unchanged) ---
Ensure-SafeMember -SafeName $SafeName -MemberType Group -MemberName "CA_PCloud_Admins@cna.com" -RoleObject $FullRole
Ensure-SafeMember -SafeName $SafeName -MemberType User  -MemberName "cna_pas_admin@cyberark.cloud.6679" -RoleObject $FullRole

Write-Log "🔹 Safe member addition process completed."
