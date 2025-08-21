# --- Logging Utility ---
$LogPath = "E:\Installation Media\Script\OnboardScript\accountonboarding.txt"
Function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$Timestamp - $Message"
    Write-Host $LogEntry -ForegroundColor $Color
    Add-Content -Path $LogPath -Value $LogEntry
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

# --- Prompt for Safe Name & Description (single line up to ~200 chars) ---
$SafeName = Read-Host "Enter the Safe Name"
$Description = Read-Host "Enter the Safe Description (single line, up to ~200 chars)"

if ([string]::IsNullOrEmpty($SafeName)) {
    Write-Log "❌ ERROR: Safe Name cannot be empty. Exiting..." "Red"
    exit
}
if ([string]::IsNullOrEmpty($Description)) {
    Write-Log "❌ ERROR: Safe Description cannot be empty. Exiting..." "Red"
    exit
}

# --- Authentication Variables (from CCP) ---
$IdentityTenantID = "aat4012"        # CyberArk Identity tenant ID
$PCloudSubdomain  = "cna-prod"       # CyberArk Privilege Cloud Subdomain
$ClientID         = $response.Username
$ClientSecret     = $response.Content

if ([string]::IsNullOrEmpty($ClientID) -or [string]::IsNullOrEmpty($ClientSecret)) {
    Write-Log "ERROR: Client ID or Client Secret is missing. Exiting..." "Red"
    exit
}

# --- Request OAuth Token ---
Write-Log "Requesting initial CyberArk ISPSS token..."
$TokenURL = "https://$IdentityTenantID.id.cyberark.cloud/oauth2/platformtoken"
$TokenBody = @{
    grant_type    = "client_credentials"
    client_id     = $ClientID
    client_secret = $ClientSecret
}
$headers_token = @{
    "Content-Type" = "application/x-www-form-urlencoded"
}

try {
    $TokenResponse = Invoke-RestMethod -Uri $TokenURL -Method Post -Headers $headers_token -Body $TokenBody
    $BearerToken = [string]$TokenResponse.access_token
    if ([string]::IsNullOrEmpty($BearerToken) -or $BearerToken.Length -lt 100) {
        Write-Log "ERROR: Received an invalid token. Length: $($BearerToken.Length)" "Red"
        exit
    }
    Write-Log "✅ Authentication successful, token obtained." "Green"
} catch {
    Write-Log "ERROR: Failed to authenticate with CyberArk ISPSS. $_" "Red"
    exit
}

# --- Define Headers for API Requests ---
$headers_api = @{
    "Authorization" = "Bearer $BearerToken"
    "Content-Type"  = "application/json"
}

# --- Create Safe Using API ---
Write-Log "🔹 Creating Safe: ${SafeName}..."

$SafesEndpoint = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/"
$SafePayload = @{
    "safeName"              = $SafeName
    "description"           = $Description
    "olacEnabled"           = $false
    "autoPurgeEnabled"      = $false
    "managingCPM"           = "CNA_PASS_MANG"
    "numberOfDaysRetention" = 180
} | ConvertTo-Json -Depth 3

Write-Log "Creating Safe: ${SafeName} with payload: $SafePayload"

try {
    $null = Invoke-RestMethod -Uri $SafesEndpoint -Method Post -Headers $headers_api -Body $SafePayload -ErrorAction Stop
    Write-Log "✅ Successfully created Safe: ${SafeName}." "Green"
} catch {
    Write-Log "❌ ERROR: Failed to create Safe: ${SafeName} - $_" "Red"
    exit
}

# ----------------------------
# PERMISSIONS DEFINITIONS
# (unchanged from your requirement)
# ----------------------------
$LimitedPermissions = @{
    "useAccounts"                             = $false
    "retrieveAccounts"                        = $false
    "listAccounts"                            = $true
    "addAccounts"                             = $false
    "updateAccountContent"                    = $false
    "updateAccountProperties"                 = $false
    "initiateCPMAccountManagementOperations"  = $true
    "specifyNextAccountContent"               = $false
    "renameAccounts"                          = $false
    "deleteAccounts"                          = $false
    "unlockAccounts"                          = $true
    "manageSafe"                              = $false
    "manageSafeMembers"                       = $false
    "backupSafe"                              = $false
    "viewAuditLog"                            = $true
    "viewSafeMembers"                         = $true
    "accessWithoutConfirmation"               = $true
    "createFolders"                           = $false
    "deleteFolders"                           = $false
    "moveAccountsAndFolders"                  = $false
    "requestsAuthorizationLevel1"             = $true
    "requestsAuthorizationLevel2"             = $false
}
$FullPermissions = @{
    "useAccounts"                             = $true
    "retrieveAccounts"                        = $true
    "listAccounts"                            = $true
    "addAccounts"                             = $true
    "updateAccountContent"                    = $true
    "updateAccountProperties"                 = $true
    "initiateCPMAccountManagementOperations"  = $true
    "specifyNextAccountContent"               = $true
    "renameAccounts"                          = $true
    "deleteAccounts"                          = $true
    "unlockAccounts"                          = $true
    "manageSafe"                              = $true
    "manageSafeMembers"                       = $true
    "backupSafe"                              = $true
    "viewAuditLog"                            = $true
    "viewSafeMembers"                         = $true
    "accessWithoutConfirmation"               = $true
    "createFolders"                           = $true
    "deleteFolders"                           = $true
    "moveAccountsAndFolders"                  = $true
    "requestsAuthorizationLevel1"             = $true
    "requestsAuthorizationLevel2"             = $false
}

# --- Helper: REST Add Member (kept for Admins as before) ---
Function Invoke-AddSafeMemberRest {
    param(
        [Parameter(Mandatory=$true)] [string]$SafeName,
        [Parameter(Mandatory=$true)] [ValidateSet("User","Group","Role")] [string]$MemberType,
        [Parameter(Mandatory=$true)] [string]$MemberName,
        [Parameter(Mandatory=$true)] $Permissions,
        [ValidateSet("Vault","Directory")] [string]$SearchIn = "Vault"
    )
    $Endpoint = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/$SafeName/Members/"
    $Body = @{
        memberName  = $MemberName
        memberType  = $MemberType
        permissions = $Permissions
        searchIn    = $SearchIn
    } | ConvertTo-Json -Depth 4
    try {
        Write-Log "Adding ${MemberType}: ${MemberName} to ${SafeName} (SearchIn=${SearchIn})..."
        Invoke-RestMethod -Uri $Endpoint -Method Post -Headers $headers_api -Body $Body -ErrorAction Stop | Out-Null
        Write-Log "✅ Added ${MemberType}: ${MemberName}."
        return $true
    } catch {
        Write-Log "❌ Failed to add '${MemberName}' - $($_.Exception.Message)" "Red"
        return $false
    }
}

# --- Only modify logic for the TARGET AD GROUP ---
# Ask for sAMAccountName (no @domain), validate it exists in the specific OU, then add as Directory Group (no GUIDs)
Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null

$TargetSam = $null
do {
    $TargetSam = Read-Host "Enter the AD Safe Group (sAMAccountName only, e.g., ca_bud_ecf_prod)"
    if ([string]::IsNullOrWhiteSpace($TargetSam)) {
        Write-Log "❌ AD Safe Group (sAMAccountName) is required." "Red"
        continue
    }

    $SearchBase = "OU=Groups,OU=CyberArk,DC=cna,DC=com"
    try {
        $adGroup = Get-ADGroup -LDAPFilter "(sAMAccountName=$TargetSam)" -SearchBase $SearchBase -Properties distinguishedName -ErrorAction Stop
    } catch {
        Write-Log "⚠️ Could not query Active Directory or group not found in $SearchBase — $_" "Yellow"
        $adGroup = $null
    }

    if (-not $adGroup) {
        Write-Log "❌ '$TargetSam' not found under $SearchBase. Please re-enter the sAMAccountName." "Red"
    }
}
until ($adGroup)

# We found the group in the required OU — add it as a Directory group using UPN-style name
$TargetUPN = "$TargetSam@cna.com"
Write-Log "Adding AD Group '$TargetUPN' as Safe member (Directory search, no GUID)..."

# Try REST using SearchIn='Directory' (NO GUIDS)
$addedTarget = Invoke-AddSafeMemberRest -SafeName $SafeName -MemberType Group -MemberName $TargetUPN -Permissions $LimitedPermissions -SearchIn Directory

if (-not $addedTarget) {
    # Fallback to sAM (still Directory)
    Write-Log "Retrying add with sAMAccountName '$TargetSam' (Directory search)..."
    $addedTarget = Invoke-AddSafeMemberRest -SafeName $SafeName -MemberType Group -MemberName $TargetSam -Permissions $LimitedPermissions -SearchIn Directory
    if (-not $addedTarget) {
        Write-Log "❌ Could not add AD group '$TargetSam' as Safe member. This typically indicates Directory Mapping cannot resolve the group from cna.com within PVWA. Please verify the Directory mapping includes the '$($adGroup.DistinguishedName)' path." "Red"
    }
}

# --- Keep your existing Admin members EXACTLY as before (no changes here) ---
# NOTE: Per your instruction, we are not altering the logic for these; they remain REST adds.
#       If you do NOT want to touch existing admins at all, comment the two calls below.
$null = Invoke-AddSafeMemberRest -SafeName $SafeName -MemberType Group -MemberName "CA_PCloud_Admins@cna.com" -Permissions $FullPermissions -SearchIn Directory
$null = Invoke-AddSafeMemberRest -SafeName $SafeName -MemberType User  -MemberName "cna_pas_admin@cyberark.cloud.6679" -Permissions $FullPermissions -SearchIn Vault

Write-Log "🔹 Safe member addition process completed."
