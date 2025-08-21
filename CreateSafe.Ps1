# --- Logging Utility ---
$LogPath = "E:\Installation Media\Script\OnboardScript\accountonboarding.txt"
Function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$Timestamp - $Message"
    Write-Host $LogEntry -ForegroundColor $Color
    Add-Content -Path $LogPath -Value $LogEntry
}

# --- Helper: POST JSON with consistent error handling ---
Function Invoke-CybrPostJson {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][hashtable]$Headers,
        [Parameter(Mandatory)]$BodyObject
    )
    $json = ($BodyObject | ConvertTo-Json -Depth 6 -Compress)
    try {
        return Invoke-RestMethod -Uri $Uri -Method Post -Headers $Headers -Body $json -ErrorAction Stop
    } catch {
        throw
    }
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

# --- Prompt for Safe Name & (single-line) Description ---
$SafeName = Read-Host "Enter the Safe Name"
$Description = Read-Host "Enter the Safe Description (single line, up to 200 chars)"
if ($Description.Length -gt 200) {
    Write-Log "ℹ️ Description longer than 200 chars; truncating."
    $Description = $Description.Substring(0,200)
}

if ([string]::IsNullOrEmpty($SafeName)) {
    Write-Log "❌ ERROR: Safe Name cannot be empty. Exiting..." "Red"
    exit
}
if ([string]::IsNullOrEmpty($Description)) {
    Write-Log "❌ ERROR: Safe Description cannot be empty. Exiting..." "Red"
    exit
}

# --- Authentication Variables (from CCP) ---
$IdentityTenantID = "aat4012"       # CyberArk Identity tenant ID
$PCloudSubdomain  = "cna-prod"      # CyberArk Privilege Cloud Subdomain (PVWA base)
$ClientID         = $response.Username
$ClientSecret     = $response.Content

if ([string]::IsNullOrEmpty($ClientID) -or [string]::IsNullOrEmpty($ClientSecret)) {
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
    if ([string]::IsNullOrEmpty($BearerToken) -or $BearerToken.Length -lt 100) {
        Write-Log "ERROR: Received an invalid token. Length: $($BearerToken.Length)"
        exit
    }
    Write-Log "✅ Authentication successful, token obtained."
} catch {
    Write-Log "ERROR: Failed to authenticate with CyberArk ISPSS. $_"
    exit
}

# --- Define Headers for PVWA API Requests ---
$headers_api = @{
    "Authorization" = "Bearer $BearerToken"
    "Content-Type"  = "application/json"
}

# --- Permissions (as requested) ---
$LimitedPermissions = @{
    useAccounts                                = $false
    retrieveAccounts                           = $false
    listAccounts                               = $true
    addAccounts                                = $false
    updateAccountContent                       = $false
    updateAccountProperties                    = $false
    initiateCPMAccountManagementOperations     = $true
    specifyNextAccountContent                  = $false
    renameAccounts                             = $false
    deleteAccounts                             = $false
    unlockAccounts                             = $true
    manageSafe                                 = $false
    manageSafeMembers                          = $false
    backupSafe                                 = $false
    viewAuditLog                               = $true
    viewSafeMembers                            = $true
    accessWithoutConfirmation                  = $true
    createFolders                              = $false
    deleteFolders                              = $false
    moveAccountsAndFolders                     = $false
    requestsAuthorizationLevel1                = $true
    requestsAuthorizationLevel2                = $false
}
$FullPermissions = @{
    useAccounts                                = $true
    retrieveAccounts                           = $true
    listAccounts                               = $true
    addAccounts                                = $true
    updateAccountContent                       = $true
    updateAccountProperties                    = $true
    initiateCPMAccountManagementOperations     = $true
    specifyNextAccountContent                  = $true
    renameAccounts                             = $true
    deleteAccounts                             = $true
    unlockAccounts                             = $true
    manageSafe                                 = $true
    manageSafeMembers                          = $true
    backupSafe                                 = $true
    viewAuditLog                               = $true
    viewSafeMembers                            = $true
    accessWithoutConfirmation                  = $true
    createFolders                              = $true
    deleteFolders                              = $true
    moveAccountsAndFolders                     = $true
    requestsAuthorizationLevel1                = $true
    requestsAuthorizationLevel2                = $false
}

# --- Create Safe Using API ---
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
    Write-Log "❌ ERROR: Failed to create Safe: ${SafeName} - $_" "Red"
    exit
}

# --- Directory GUID (cna.com) for searchIn (per CyberArk guidance) ---
$DirectoryGuid = "4ac5fb05-f776-4be5-9b7f-9ec01c737fa4"

# --- Helper: Try add target AD group with several resolvers (only for target group) ---
Function Try-AddTargetAdGroup {
    param(
        [Parameter(Mandatory)][string]$SafeName,
        [Parameter(Mandatory)][string]$GroupSam,    # sAMAccountName only
        [Parameter(Mandatory)][string]$DirectoryGuid,
        [Parameter(Mandatory)][hashtable]$Headers,
        [Parameter(Mandatory)]$Permissions
    )
    $MembersEndpoint = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/$SafeName/Members/"

    # Build candidate names to try for MemberName
    $candidates = New-Object System.Collections.Generic.List[string]
    # 1) sAM as entered
    if ($GroupSam) { $candidates.Add($GroupSam) }

    # 2) Try to enrich from AD (if AD module is present)
    try {
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory -ErrorAction Stop | Out-Null
            $adGrp = Get-ADGroup -Identity $GroupSam -ErrorAction Stop -Properties mail,cn,distinguishedName,name
            if ($adGrp) {
                if ($adGrp.mail) { $candidates.Add($adGrp.mail) }             # mail-enabled group
                if ($adGrp.cn)   { $candidates.Add($adGrp.cn) }
                if ($adGrp.name) { $candidates.Add($adGrp.name) }
                if ($adGrp.distinguishedName) { $candidates.Add($adGrp.distinguishedName) }
                Write-Log "ℹ️ AD lookup found group; will try name variants: $($candidates -join ', ')"
            }
        } else {
            Write-Log "ℹ️ AD module not found; proceeding without AD enrichment."
        }
    } catch {
        Write-Log "⚠️ AD lookup failed for '$GroupSam' ($_) — proceeding with basic variants."
    }

    # Deduplicate & keep simple order
    $candidates = [System.Linq.Enumerable]::Distinct($candidates)

    foreach ($candidate in $candidates) {
        # Skip values containing backslash (invalid for memberName per API)
        if ($candidate -match "\\") {
            Write-Log "ℹ️ Skipping '$candidate' (backslash not allowed in memberName)."
            continue
        }

        $body = @{
            memberName  = $candidate
            searchIn    = $DirectoryGuid     # Directory GUID (NOT the directory name)
            memberType  = "Group"
            permissions = $Permissions
        }

        Write-Log "Adding AD Group '$candidate' (searchIn=$DirectoryGuid)..."
        try {
            Invoke-CybrPostJson -Uri $MembersEndpoint -Headers $Headers -BodyObject $body | Out-Null
            Write-Log "✅ Added Group: $candidate."
            return $true
        } catch {
            # If the PVWA replies with SFWS0010, log & continue to next variant
            $msg = $_.Exception.Message
            if ($msg -match "SFWS0010") {
                Write-Log "❌ Failed to add '$candidate' - Member has not been defined (SFWS0010)."
            } else {
                Write-Log "❌ Failed to add '$candidate' - $msg"
            }
        }
    }
    return $false
}

# --- Add Safe Members ---

# 1) Target AD Safe Group (sAM only prompt)
$TargetSam = Read-Host "Enter the AD Safe Group (sAMAccountName only, e.g., ca_bud_ecf_prod)"
if ([string]::IsNullOrWhiteSpace($TargetSam)) {
    Write-Log "❌ ERROR: AD Safe Group cannot be empty. Exiting..." "Red"
    exit
}
# Try add with Directory GUID searchIn (non-SCIM approach recommended by CyberArk)
$added = Try-AddTargetAdGroup -SafeName $SafeName -GroupSam $TargetSam -DirectoryGuid $DirectoryGuid -Headers $headers_api -Permissions $LimitedPermissions

if (-not $added) {
    Write-Log "❌ Could not add AD group '$TargetSam'."
    Write-Log "   This typically indicates the PVWA Directory Mapping cannot resolve the group name from 'cna.com' with directory GUID $DirectoryGuid (see CyberArk guidance on using directory GUID in 'searchIn')."
}

# 2) Registered group (leave exactly as you asked) — Directory search
$MembersEndpoint = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/$SafeName/Members/"
$registeredGroup = @{
    memberName  = "CA_PCloud_Admins@cna.com"
    searchIn    = $DirectoryGuid   # search in Directory (this one is known to resolve)
    memberType  = "Group"
    permissions = $FullPermissions
}
Write-Log "Adding Registered Group 'CA_PCloud_Admins@cna.com' (Directory search)..."
try {
    Invoke-CybrPostJson -Uri $MembersEndpoint -Headers $headers_api -BodyObject $registeredGroup | Out-Null
    Write-Log "✅ Added Group: CA_PCloud_Admins@cna.com."
} catch {
    Write-Log "❌ Failed to add 'CA_PCloud_Admins@cna.com' - $($_.Exception.Message)"
}

# 3) Vault user (no directory search)
$vaultUser = @{
    memberName  = "cna_pas_admin@cyberark.cloud.6679"
    searchIn    = "Vault"
    memberType  = "User"
    permissions = $FullPermissions
}
Write-Log "Adding Vault User 'cna_pas_admin@cyberark.cloud.6679' (Vault search)..."
try {
    Invoke-CybrPostJson -Uri $MembersEndpoint -Headers $headers_api -BodyObject $vaultUser | Out-Null
    Write-Log "✅ Added User: cna_pas_admin@cyberark.cloud.6679."
} catch {
    Write-Log "❌ Failed to add 'cna_pas_admin@cyberark.cloud.6679' - $($_.Exception.Message)"
}

Write-Log "🔹 Safe member addition process completed."
