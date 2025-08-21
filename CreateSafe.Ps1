# --- Logging Utility ---
$LogPath = "E:\Installation Media\Script\OnboardScript\accountonboarding.txt"
Function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$Timestamp - $Message"
    Write-Host $LogEntry -ForegroundColor $Color
    Add-Content -Path $LogPath -Value $LogEntry
}

# --- Single-line Description Prompt (Windows Forms, 200 chars) ---
Add-Type -AssemblyName System.Windows.Forms
function Prompt-DescriptionBox {
    param([string]$Title = "Safe Description", [string]$Prompt = "Enter Safe Description (max 200 chars)")

    $form = New-Object System.Windows.Forms.Form
    $form.Text = $Title
    $form.Width = 600
    $form.Height = 170
    $form.StartPosition = "CenterScreen"
    $form.TopMost = $true

    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Prompt
    $label.AutoSize = $true
    $label.Top = 10
    $label.Left = 10
    $form.Controls.Add($label)

    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Multiline = $false
    $textBox.Width = 560
    $textBox.Top = 40
    $textBox.Left = 10
    $textBox.MaxLength = 200
    $form.Controls.Add($textBox)

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = "OK"
    $okButton.Width = 100
    $okButton.Height = 30
    $okButton.Top = 80
    $okButton.Left = 360
    $okButton.Add_Click({ $form.Tag = $textBox.Text; $form.Close() })
    $form.Controls.Add($okButton)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = "Cancel"
    $cancelButton.Width = 100
    $cancelButton.Height = 30
    $cancelButton.Top = 80
    $cancelButton.Left = 470
    $cancelButton.Add_Click({ $form.Tag = $null; $form.Close() })
    $form.Controls.Add($cancelButton)

    try { $null = $form.ShowDialog(); return $form.Tag } finally { $form.Dispose() }
}

# ------------------- CCP → TOKEN → CREATE SAFE -------------------
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
    if (-not $response -or -not $response.Username -or -not $response.Content) { Write-Log "ERROR: Failed to retrieve API credentials from CCP." "Red"; exit 1 }
    Write-Log "Successfully retrieved credentials for user: $($response.Username)" "Green"
} catch { Write-Log "ERROR: CCP credential fetch failed - $_" "Red"; exit 1 }

$SafeName = Read-Host "Enter the Safe Name"
$Description = Prompt-DescriptionBox -Title "Safe Description" -Prompt "Enter Safe Description (max 200 chars)"
if ([string]::IsNullOrWhiteSpace($SafeName))    { Write-Log "❌ ERROR: Safe Name cannot be empty. Exiting..."; exit }
if ([string]::IsNullOrWhiteSpace($Description)) { Write-Log "❌ ERROR: Safe Description cannot be empty. Exiting..."; exit }

$IdentityTenantID = "aat4012"
$PCloudSubdomain  = "cna-prod"
$ClientID         = $response.Username
$ClientSecret     = $response.Content
if ([string]::IsNullOrWhiteSpace($ClientID) -or [string]::IsNullOrWhiteSpace($ClientSecret)) { Write-Log "ERROR: Client ID or Client Secret is missing. Exiting..."; exit }

Write-Log "Requesting initial CyberArk ISPSS token..."
$TokenURL = "https://$IdentityTenantID.id.cyberark.cloud/oauth2/platformtoken"
$TokenBody = @{ grant_type = "client_credentials"; client_id = $ClientID; client_secret = $ClientSecret }
$headers_token = @{ "Content-Type" = "application/x-www-form-urlencoded" }
try {
    $TokenResponse = Invoke-RestMethod -Uri $TokenURL -Method Post -Headers $headers_token -Body $TokenBody
    $BearerToken = [string]$TokenResponse.access_token
    if ([string]::IsNullOrWhiteSpace($BearerToken) -or $BearerToken.Length -lt 100) { Write-Log "ERROR: Received an invalid token. Length: $($BearerToken.Length)"; exit }
    Write-Log "✅ Authentication successful, token obtained."
} catch { Write-Log "ERROR: Failed to authenticate with CyberArk ISPSS. $_"; exit }

$headers_api = @{ "Authorization" = "Bearer $BearerToken"; "Content-Type" = "application/json" }

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
} catch { Write-Log "❌ ERROR: Failed to create Safe: ${SafeName} - $_"; exit }

# ------------------- Directory GUID (Hardcoded) -------------------
$DirectoryGUID = "4ac5fb05-f776-4be5-9b7f-9ec01c737fa4"

# ------------------- Prompt for Primary AD Group (UPN style) -------------------
function Prompt-ValidADGroupUpn {
    param([string]$PromptText)
    while ($true) {
        $group = Read-Host $PromptText
        if ($group -match '^[^@]+@[^@]+\.[^@]+$') { return $group }
        Write-Log "❌ Invalid format. Enter AD group as groupname@cna.com" "Red"
    }
}
$PrimaryADGroup = Prompt-ValidADGroupUpn -PromptText "Enter the AD Safe Group (groupname@cna.com) to add"

# ------------------- Permissions -------------------
$LimitedPermissions = @{
    useAccounts=$false; retrieveAccounts=$false; listAccounts=$true; addAccounts=$false
    updateAccountContent=$false; updateAccountProperties=$false
    initiateCPMAccountManagementOperations=$true; specifyNextAccountContent=$false
    renameAccounts=$false; deleteAccounts=$false; unlockAccounts=$true
    manageSafe=$false; manageSafeMembers=$false; backupSafe=$false
    viewAuditLog=$true; viewSafeMembers=$true; accessWithoutConfirmation=$true
    createFolders=$false; deleteFolders=$false; moveAccountsAndFolders=$false
    requestsAuthorizationLevel1=$true; requestsAuthorizationLevel2=$false
}
$FullPermissions = @{
    useAccounts=$true; retrieveAccounts=$true; listAccounts=$true; addAccounts=$true
    updateAccountContent=$true; updateAccountProperties=$true
    initiateCPMAccountManagementOperations=$true; specifyNextAccountContent=$true
    renameAccounts=$true; deleteAccounts=$true; unlockAccounts=$true
    manageSafe=$true; manageSafeMembers=$true; backupSafe=$true
    viewAuditLog=$true; viewSafeMembers=$true; accessWithoutConfirmation=$true
    createFolders=$true; deleteFolders=$true; moveAccountsAndFolders=$true
    requestsAuthorizationLevel1=$true; requestsAuthorizationLevel2=$false
}

# ------------------- Members to Add -------------------
$APIEndpointMembers = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/$SafeName/Members/"
$Members = @(
    @{ memberName = $PrimaryADGroup;               memberType = "Group"; searchIn = $DirectoryGUID; permissions = $LimitedPermissions },
    @{ memberName = "CA_PCloud_Admins@cna.com";    memberType = "Group"; searchIn = $DirectoryGUID; permissions = $FullPermissions },
    @{ memberName = "cna_pas_admin@cyberark.cloud.6679"; memberType = "User";  searchIn = "Vault";        permissions = $FullPermissions }
)

# ------------------- Add with smart retry for SFWS0010 -------------------
foreach ($Member in $Members) {
    # Build initial body
    $makeBody = {
        param($m)
        @{
            MemberName  = $m.memberName
            MemberType  = $m.memberType
            SearchIn    = $m.searchIn
            Permissions = $m.permissions
        } | ConvertTo-Json -Depth 6
    }

    $jsonBody = & $makeBody $Member
    Write-Log "Adding $($Member.memberType): $($Member.memberName) (searchIn=$($Member.searchIn)) to Safe: $SafeName..."

    $didRetry = $false
    try {
        Invoke-RestMethod -Uri $APIEndpointMembers -Method Post -Headers $headers_api -Body $jsonBody -ErrorAction Stop | Out-Null
        Write-Log "✅ Successfully added $($Member.memberType): $($Member.memberName) to $SafeName."
    } catch {
        # Read error body if available
        $errBody = $null
        try { $errBody = $_.Exception.Response.Content.ReadAsStringAsync().Result } catch {}
        if (-not $errBody) { $errBody = $_ | Out-String }

        # If this is a Directory GUID Group and we got 'not defined', retry once with sAM (strip @domain)
        $isDirGroup    = ($Member.memberType -eq "Group" -and $Member.searchIn -match '^[0-9a-fA-F-]{32,36}$')
        $isNotDefined  = ($errBody -match '"ErrorCode"\s*:\s*"SFWS0010"')
        $looksLikeUpn  = ($Member.memberName -match '^[^@]+@[^@]+\.[^@]+$')

        if ($isDirGroup -and $isNotDefined -and $looksLikeUpn -and -not $didRetry) {
            $didRetry = $true
            $samOnly = $Member.memberName.Split('@')[0]
            Write-Log "ℹ️ Directory lookup failed for '$($Member.memberName)'. Retrying with sAMAccountName '$samOnly'..." "Yellow"

            $retryMember = $Member.PSObject.Copy()
            $retryMember.memberName = $samOnly

            $jsonBodyRetry = & $makeBody $retryMember
            try {
                Invoke-RestMethod -Uri $APIEndpointMembers -Method Post -Headers $headers_api -Body $jsonBodyRetry -ErrorAction Stop | Out-Null
                Write-Log "✅ Retry succeeded: added Group '$samOnly' to $SafeName."
                continue
            } catch {
                $retryErr = $null
                try { $retryErr = $_.Exception.Response.Content.ReadAsStringAsync().Result } catch {}
                if (-not $retryErr) { $retryErr = $_ | Out-String }
                Write-Log "❌ Retry failed for '$samOnly' - $retryErr" "Red"
            }
        }

        # Final failure
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
