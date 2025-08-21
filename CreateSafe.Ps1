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

# --- Prompt for Safe Name & Description ---
$SafeName = Read-Host "Enter the Safe Name"
$Description = Read-Host "Enter the Safe Description (single line, up to 200 chars)"
if ($Description.Length -gt 200) { $Description = $Description.Substring(0,200) }

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

# Helper to URL-encode safe for REST paths
function Encode-Safe([string]$name){ return [System.Uri]::EscapeDataString($name) }

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

# --- Permissions (as requested) ---
$LimitedPermissions = @{
    "useAccounts" = $false
    "retrieveAccounts" = $false
    "listAccounts" = $true
    "addAccounts" = $false
    "updateAccountContent" = $false
    "updateAccountProperties" = $false
    "initiateCPMAccountManagementOperations" = $true
    "specifyNextAccountContent" = $false
    "renameAccounts" = $false
    "deleteAccounts" = $false
    "unlockAccounts" = $true
    "manageSafe" = $false
    "manageSafeMembers" = $false
    "backupSafe" = $false
    "viewAuditLog" = $true
    "viewSafeMembers" = $true
    "accessWithoutConfirmation" = $true
    "createFolders" = $false
    "deleteFolders" = $false
    "moveAccountsAndFolders" = $false
    "requestsAuthorizationLevel1" = $true
    "requestsAuthorizationLevel2" = $false
}
$FullPermissions = @{
    "useAccounts" = $true
    "retrieveAccounts" = $true
    "listAccounts" = $true
    "addAccounts" = $true
    "updateAccountContent" = $true
    "updateAccountProperties" = $true
    "initiateCPMAccountManagementOperations" = $true
    "specifyNextAccountContent" = $true
    "renameAccounts" = $true
    "deleteAccounts" = $true
    "unlockAccounts" = $true
    "manageSafe" = $true
    "manageSafeMembers" = $true
    "backupSafe" = $true
    "viewAuditLog" = $true
    "viewSafeMembers" = $true
    "accessWithoutConfirmation" = $true
    "createFolders" = $true
    "deleteFolders" = $true
    "moveAccountsAndFolders" = $true
    "requestsAuthorizationLevel1" = $true
    "requestsAuthorizationLevel2" = $false
}

# --- Add Safe Members (fixed flow) ---
$EncodedSafe = Encode-Safe $SafeName
$MembersEndpoint = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/$EncodedSafe/Members/"

# 1) Target AD group: search AD in the specific OU, then add with searchIn='cna.com'
Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
$GroupSam = Read-Host "Enter the AD Safe Group (sAMAccountName only, e.g., ca_bud_ecf_prod)"
if ([string]::IsNullOrWhiteSpace($GroupSam)) {
    Write-Log "❌ ERROR: AD Safe Group sAMAccountName cannot be empty. Exiting..." "Red"
    exit
}

# Validate the group exists in the requested SearchBase
$SearchBaseOU = 'OU=Groups,OU=CyberArk,DC=cna,DC=com'
try {
    $adGroup = Get-ADGroup -LDAPFilter "(sAMAccountName=$GroupSam)" -SearchBase $SearchBaseOU -ErrorAction Stop
    Write-Log "Found AD Group in $SearchBaseOU: $($adGroup.Name) (sAM=$($adGroup.sAMAccountName))" "Green"
} catch {
    Write-Log "❌ ERROR: Could not find sAMAccountName '$GroupSam' under $SearchBaseOU. Exiting..." "Red"
    exit
}

# Try add with sAM first, then with UPN
function Add-GroupViaREST {
    param(
        [string]$MemberName,   # sAM or UPN
        [hashtable]$Perms
    )
    $body = @{
        "memberName" = $MemberName
        "memberType" = "Group"
        "searchIn"   = "cna.com"             # IMPORTANT: use domain name, not 'Directory'
        "permissions"= $Perms
    } | ConvertTo-Json -Depth 5

    Write-Log "Adding Group: ${MemberName} to ${SafeName} (SearchIn=cna.com)..."
    try {
        $null = Invoke-RestMethod -Uri $MembersEndpoint -Method Post -Headers $headers_api -Body $body -ErrorAction Stop
        Write-Log "✅ Added Group: ${MemberName}." "Green"
        return $true
    } catch {
        $msg = $_.Exception.Message
        Write-Log "❌ Failed to add '${MemberName}' - $msg" "Red"
        return $false
    }
}

# Add target AD group with LimitedPermissions
$added = $false
$added = Add-GroupViaREST -MemberName $GroupSam -Perms $LimitedPermissions
if (-not $added) {
    # Retry with UPN
    $upn = "$GroupSam@cna.com"
    Write-Log "Retrying add with UPN '${upn}' (SearchIn=cna.com)..."
    $added = Add-GroupViaREST -MemberName $upn -Perms $LimitedPermissions
}
if (-not $added) {
    Write-Log "❌ Could not add AD group '${GroupSam}'. This typically indicates PVWA Directory Mapping cannot resolve the group from 'cna.com'. Please verify mapping includes '$SearchBaseOU'." "Red"
}

# 2) Keep existing full-permission members exactly as before
$AdminMembers = @(
    @{ memberName = "CA_PCloud_Admins@cna.com";            memberType = "Group"; permissions = $FullPermissions; searchIn = "Directory" },
    @{ memberName = "cna_pas_admin@cyberark.cloud.6679";   memberType = "User";  permissions = $FullPermissions; searchIn = "Vault" }
)

foreach ($m in $AdminMembers) {
    $MemberName = $m.memberName
    $MemberType = $m.memberType
    $SearchIn   = $m.searchIn
    $Perms      = $m.permissions

    $body = @{
        "memberName" = $MemberName
        "memberType" = $MemberType
        "searchIn"   = $SearchIn
        "permissions"= $Perms
    } | ConvertTo-Json -Depth 5

    Write-Log "Adding ${MemberType}: ${MemberName} to ${SafeName} (SearchIn=${SearchIn})..."
    try {
        $null = Invoke-RestMethod -Uri $MembersEndpoint -Method Post -Headers $headers_api -Body $body -ErrorAction Stop
        Write-Log "✅ Added ${MemberType}: ${MemberName}." "Green"
    } catch {
        Write-Log "❌ Failed to add ${MemberType}: ${MemberName} - $($_.Exception.Message)" "Red"
    }
}

Write-Log "🔹 Safe member addition process completed."
