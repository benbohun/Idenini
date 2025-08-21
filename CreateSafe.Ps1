
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
$SafeName    = Read-Host "Enter the Safe Name"
$Description = Read-Host "Enter the Safe Description"

if ([string]::IsNullOrWhiteSpace($SafeName))    { Write-Log "❌ ERROR: Safe Name cannot be empty. Exiting..."; exit }
if ([string]::IsNullOrWhiteSpace($Description)) { Write-Log "❌ ERROR: Safe Description cannot be empty. Exiting..."; exit }

# --- Authentication Variables (from CCP) ---
$IdentityTenantID = "aat4012"        # CyberArk Identity tenant ID
$PCloudSubdomain  = "cna-prod"       # CyberArk Privilege Cloud subdomain
$ClientID         = $response.Username
$ClientSecret     = $response.Content

if ([string]::IsNullOrWhiteSpace($ClientID) -or [string]::IsNullOrWhiteSpace($ClientSecret)) {
    Write-Log "ERROR: Client ID or Client Secret is missing. Exiting..."
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

# --- Define Headers for API Requests ---
$headers_api = @{
    "Authorization" = "Bearer $BearerToken"
    "Content-Type"  = "application/json"
}

# --- Create Safe Using API ---
Write-Log "🔹 Creating Safe: ${SafeName}..."
$APIEndpointSafes = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/"
$SafePayload = @{
    safeName              = $SafeName
    description           = $Description
    olacEnabled           = $false
    autoPurgeEnabled      = $false
    managingCPM           = "CNA_PASS_MANG"
    numberOfDaysRetention = 180
} | ConvertTo-Json -Depth 3

Write-Log "Creating Safe: ${SafeName} with payload: $SafePayload"
try {
    $null = Invoke-RestMethod -Uri $APIEndpointSafes -Method Post -Headers $headers_api -Body $SafePayload -ErrorAction Stop
    Write-Log "✅ Successfully created Safe: ${SafeName}."
} catch {
    Write-Log "❌ ERROR: Failed to create Safe: ${SafeName} - $_"
    exit
}

# --- Prompt for AD Safe Group (must be DOMAIN\GroupName) ---
function Prompt-ValidADGroup {
    param([string]$PromptText)

    while ($true) {
        $group = Read-Host $PromptText
        if ($group -match '^[^\\]+\\[^\\]+$') { return $group }
        Write-Log "❌ Invalid format. Please enter the group in DOMAIN\GroupName format (e.g., CNA\ca_bud_ecf_prod)." "Red"
    }
}
$PrimaryADGroup = Prompt-ValidADGroup -PromptText "Enter the AD Safe Group (DOMAIN\GroupName) to be added to the Safe"

# Derive the NetBIOS domain from the primary group entry
$DomainNetBIOS = $PrimaryADGroup.Split('\')[0]
$AdminsADGroup = "$DomainNetBIOS\CA_PCloud_Admins"   # enforce DOMAIN\CA_PCloud_Admins

# --- Members to Add ---
$APIEndpointMembers = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/$SafeName/Members/"

$Members = @(
    # Primary AD group (Directory)
    @{ memberName = $PrimaryADGroup; memberType = "Group"; searchIn = "Directory"; permissions = @{
        useAccounts = $false; retrieveAccounts = $false; listAccounts = $true; addAccounts = $false
        updateAccountContent = $false; updateAccountProperties = $false
        initiateCPMAccountManagementOperations = $true; specifyNextAccountContent = $false
        renameAccounts = $false; deleteAccounts = $false; unlockAccounts = $true
        manageSafe = $false; manageSafeMembers = $false; backupSafe = $false
        viewAuditLog = $true; viewSafeMembers = $true; accessWithoutConfirmation = $true
        createFolders = $false; deleteFolders = $false; moveAccountsAndFolders = $false
        requestsAuthorizationLevel1 = $true; requestsAuthorizationLevel2 = $false
    }},

    # Enforced Admins AD group (Directory)
    @{ memberName = $AdminsADGroup; memberType = "Group"; searchIn = "Directory"; permissions = @{
        useAccounts = $true; retrieveAccounts = $true; listAccounts = $true; addAccounts = $true
        updateAccountContent = $true; updateAccountProperties = $true
        initiateCPMAccountManagementOperations = $true; specifyNextAccountContent = $true
        renameAccounts = $true; deleteAccounts = $true; unlockAccounts = $true
        manageSafe = $true; manageSafeMembers = $true; backupSafe = $true
        viewAuditLog = $true; viewSafeMembers = $true; accessWithoutConfirmation = $true
        createFolders = $true; deleteFolders = $true; moveAccountsAndFolders = $true
        requestsAuthorizationLevel1 = $true; requestsAuthorizationLevel2 = $false
    }},

    # CyberArk cloud user (Vault)
    @{ memberName = "cna_pas_admin@cyberark.cloud.6679"; memberType = "User"; searchIn = "Vault"; permissions = @{
        useAccounts = $true; retrieveAccounts = $true; listAccounts = $true; addAccounts = $true
        updateAccountContent = $true; updateAccountProperties = $true
        initiateCPMAccountManagementOperations = $true; specifyNextAccountContent = $true
        renameAccounts = $true; deleteAccounts = $true; unlockAccounts = $true
        manageSafe = $true; manageSafeMembers = $true; backupSafe = $true
        viewAuditLog = $true; viewSafeMembers = $true; accessWithoutConfirmation = $true
        createFolders = $true; deleteFolders = $true; moveAccountsAndFolders = $true
        requestsAuthorizationLevel1 = $true; requestsAuthorizationLevel2 = $false
    }}
)

# --- Add Members ---
foreach ($Member in $Members) {
    $jsonBody = @{
        memberName = $Member.memberName
        memberType = $Member.memberType
        searchIn   = $Member.searchIn
        permissions= $Member.permissions
    } | ConvertTo-Json -Depth 6

    Write-Log "Adding $($Member.memberType): $($Member.memberName) (searchIn=$($Member.searchIn)) to Safe: $SafeName..."
    try {
        Invoke-RestMethod -Uri $APIEndpointMembers -Method Post -Headers $headers_api -Body $jsonBody -ErrorAction Stop | Out-Null
        Write-Log "✅ Successfully added $($Member.memberType): $($Member.memberName) to $SafeName."
    } catch {
        $errBody = $null
        try { $errBody = $_.Exception.Response.Content.ReadAsStringAsync().Result } catch {}
        if (-not $errBody) { $errBody = $_ | Out-String }
        Write-Log "❌ ERROR: Failed to add $($Member.memberType): $($Member.memberName) to $SafeName - $errBody" "Red"
    }
}

Write-Log "🔹 Safe member addition process completed."

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
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
$Description = Read-Host "Enter the Safe Description"

if ([string]::IsNullOrEmpty($SafeName)) {
    Write-Log "❌ ERROR: Safe Name cannot be empty. Exiting..."
    exit
}
if ([string]::IsNullOrEmpty($Description)) {
    Write-Log "❌ ERROR: Safe Description cannot be empty. Exiting..."
    exit
}

# --- Authentication Variables (from CCP) ---
$IdentityTenantID = "aat4012"        # CyberArk Identity tenant ID
$PCloudSubdomain  = "cna-prod"   # CyberArk Privilege Cloud Subdomain
$ClientID         = $response.Username
$ClientSecret     = $response.Content

if ([string]::IsNullOrEmpty($ClientID) -or [string]::IsNullOrEmpty($ClientSecret)) {
    Write-Log "ERROR: Client ID or Client Secret is missing. Exiting..."
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
        Write-Log "ERROR: Received an invalid token. Length: $($BearerToken.Length)"
        exit
    }
    Write-Log "✅ Authentication successful, token obtained."
} catch {
    Write-Log "ERROR: Failed to authenticate with CyberArk ISPSS. $_"
    exit
}

# --- Define Headers for API Requests ---
$headers_api = @{
    "Authorization" = "Bearer $BearerToken"
    "Content-Type"  = "application/json"
}

# --- Create Safe Using API ---
Write-Log "🔹 Creating Safe: ${SafeName}..."

$APIEndpoint = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/"
$SafePayload = @{
    "safeName"                  = $SafeName
    "description"               = $Description
    "olacEnabled"               = $false  # Default value
    "autoPurgeEnabled"          = $false  # Default value
    "managingCPM"               = "CNA_PASS_MANG"  # Default CPM
    "numberOfDaysRetention"     = 180  # Default retention policy
} | ConvertTo-Json -Depth 3

Write-Log "Creating Safe: ${SafeName} with payload: $SafePayload"

try {
    $Response = Invoke-RestMethod -Uri $APIEndpoint -Method Post -Headers $headers_api -Body $SafePayload -ErrorAction Stop
    Write-Log "✅ Successfully created Safe: ${SafeName}."
} catch {
    Write-Log "❌ ERROR: Failed to create Safe: ${SafeName} - $_"
    exit
}

# --- Add Safe Members ---
$GroupName = Read-Host "Enter the Group Name to be added to the Safe"
if ([string]::IsNullOrEmpty($GroupName)) {
    Write-Log "❌ ERROR: Group Name cannot be empty. Exiting..."
    exit
}

$APIEndpointMembers = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/$SafeName/Members/"

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
$Members = @(
    @{ "memberName" = $GroupName; "memberType" = "Group"; "permissions" = $LimitedPermissions },
    @{ "memberName" = "CA_PCloud_Admins@cna.com"; "memberType" = "Group"; "permissions" = $FullPermissions },
    @{ "memberName" = "cna_pas_admin@cyberark.cloud.6679"; "memberType" = "User"; "permissions" = $FullPermissions },
    @{ "memberName" = "safe_automation@cyberark.cloud.6679"; "memberType" = "User"; "permissions" = $FullPermissions }
)
foreach ($Member in $Members) {
    $MemberName = $Member.memberName
    $MemberType = $Member.memberType
    $Permissions = $Member.permissions

    $jsonBody = @{
        "memberName" = $MemberName
        "searchIn" = "Vault"
        "memberType" = $MemberType
        "permissions" = $Permissions
    } | ConvertTo-Json -Depth 3

    Write-Log "Adding ${MemberType}: ${MemberName} to Safe: ${SafeName}..."

    try {
        $Response = Invoke-RestMethod -Uri $APIEndpointMembers -Method Post -Headers $headers_api -Body $jsonBody -ErrorAction Stop
        Write-Log "✅ Successfully added ${MemberType}: ${MemberName} to ${SafeName}."
    } catch {
        Write-Log "❌ ERROR: Failed to add ${MemberType}: ${MemberName} to ${SafeName} - $_"
    }
}

Write-Log "🔹 Safe member addition process completed."
