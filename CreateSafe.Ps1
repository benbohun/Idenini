<#
.SYNOPSIS
    CyberArk Privilege Cloud Safe Creation & Membership Assignment Script
#>

# ------------------- Setup -------------------
Add-Type -AssemblyName System.Windows.Forms

# Logging
$LogFile = "SafeCreationLog.txt"
function Write-Log {
    param([string]$Message,[string]$Color="White")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$Timestamp - $Message"
    Add-Content -Path $LogFile -Value $LogEntry
    Write-Host $LogEntry -ForegroundColor $Color
}

# ------------------- Prompt for Inputs -------------------
$SafeName      = Read-Host "Enter Safe Name"

# Use simple text box for description (single-line but long input allowed)
function Prompt-DescriptionBox {
    param([string]$Title = "Safe Description", [string]$Prompt = "Enter Safe Description (single line, up to 200 chars)")

    $form = New-Object System.Windows.Forms.Form
    $form.Text = $Title
    $form.Width = 600
    $form.Height = 180
    $form.StartPosition = "CenterScreen"

    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Prompt
    $label.AutoSize = $true
    $label.Top = 10
    $label.Left = 10
    $form.Controls.Add($label)

    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Width = 550
    $textBox.Top = 40
    $textBox.Left = 10
    $form.Controls.Add($textBox)

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = "OK"
    $okButton.Width = 100
    $okButton.Top = 80
    $okButton.Left = 370
    $okButton.Add_Click({ $form.Tag = $textBox.Text; $form.Close() })
    $form.Controls.Add($okButton)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = "Cancel"
    $cancelButton.Width = 100
    $cancelButton.Top = 80
    $cancelButton.Left = 480
    $cancelButton.Add_Click({ $form.Tag = $null; $form.Close() })
    $form.Controls.Add($cancelButton)

    $form.ShowDialog() | Out-Null
    return $form.Tag
}
$Description = Prompt-DescriptionBox
if ([string]::IsNullOrWhiteSpace($Description)) {
    Write-Log "❌ ERROR: Safe Description cannot be empty. Exiting..." "Red"
    exit
}

# Prompt for AD Group (sAMAccountName only)
function Prompt-ValidADGroupSam {
    param([string]$PromptText)
    while ($true) {
        $group = Read-Host $PromptText
        if ($group -match '^[a-zA-Z0-9_\-]+$') { return $group }
        Write-Log "❌ Invalid format. Enter the AD group using its sAMAccountName (e.g., ca_bud_ecf_prod)" "Red"
    }
}
$GroupName = Prompt-ValidADGroupSam -PromptText "Enter the AD Safe Group (sAMAccountName only, e.g. ca_bud_ecf_prod)"

# ------------------- Permissions Definitions -------------------
$LimitedPermissions = @{
    "useAccounts"                           = $false
    "retrieveAccounts"                      = $false
    "listAccounts"                          = $true
    "addAccounts"                           = $false
    "updateAccountContent"                  = $false
    "updateAccountProperties"               = $false
    "initiateCPMAccountManagementOperations"= $true
    "specifyNextAccountContent"             = $false
    "renameAccounts"                        = $false
    "deleteAccounts"                        = $false
    "unlockAccounts"                        = $true
    "manageSafe"                            = $false
    "manageSafeMembers"                     = $false
    "backupSafe"                            = $false
    "viewAuditLog"                          = $true
    "viewSafeMembers"                       = $true
    "accessWithoutConfirmation"             = $true
    "createFolders"                         = $false
    "deleteFolders"                         = $false
    "moveAccountsAndFolders"                = $false
    "requestsAuthorizationLevel1"           = $true
    "requestsAuthorizationLevel2"           = $false
}

$FullPermissions = @{
    "useAccounts"                           = $true
    "retrieveAccounts"                      = $true
    "listAccounts"                          = $true
    "addAccounts"                           = $true
    "updateAccountContent"                  = $true
    "updateAccountProperties"               = $true
    "initiateCPMAccountManagementOperations"= $true
    "specifyNextAccountContent"             = $true
    "renameAccounts"                        = $true
    "deleteAccounts"                        = $true
    "unlockAccounts"                        = $true
    "manageSafe"                            = $true
    "manageSafeMembers"                     = $true
    "backupSafe"                            = $true
    "viewAuditLog"                          = $true
    "viewSafeMembers"                       = $true
    "accessWithoutConfirmation"             = $true
    "createFolders"                         = $true
    "deleteFolders"                         = $true
    "moveAccountsAndFolders"                = $true
    "requestsAuthorizationLevel1"           = $true
    "requestsAuthorizationLevel2"           = $false
}

# ------------------- Members Block -------------------
$Members = @(
    # Target AD Group — Directory
    @{
        "memberName"     = $GroupName
        "memberType"     = "Group"
        "searchIn"       = "cna.com"
        "memberLocation" = @{
            "type" = "directory"
            "id"   = "cna.com"
            "name" = "cna.com"
        }
        "permissions"    = $LimitedPermissions
    },

    # CA_PCloud_Admins — already registered in tenant
    @{
        "memberName"  = "CA_PCloud_Admins@cna.com"
        "memberType"  = "Group"
        "permissions" = $FullPermissions
    },

    # Cloud User in Vault
    @{
        "memberName"  = "cna_pas_admin@cyberark.cloud.6679"
        "memberType"  = "User"
        "searchIn"    = "Vault"
        "permissions" = $FullPermissions
    }
)

# ------------------- API Authentication -------------------
$PCloudSubdomain = "cna-prod"
$IdentityTenantURL = "aat4012.id.cyberark.cloud"

Write-Log "Requesting CyberArk PAS authentication..."
$header = Get-IdentityHeader -IdentityTenantURL $IdentityTenantURL -psPASFormat -PCloudSubdomain $PCloudSubdomain -UPCreds $UPCred

use-PASSession $header
$session = Get-PASSession
if (-not $session) {
    Write-Log "❌ Authentication failed. Exiting..." "Red"
    exit
}
Write-Log "✅ Authentication successful."

# ------------------- Safe Creation -------------------
$APIEndpointSafes   = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/"
$SafeBody = @{
    SafeName     = $SafeName
    Description  = $Description
    OLACEnabled  = $false
    ManagingCPM  = "PasswordManager"
    NumberOfVersionsRetention = 5
    AutoPurgeEnabled = $true
}
try {
    Write-Log "Creating Safe: $SafeName..."
    Invoke-RestMethod -Uri $APIEndpointSafes -Method Post -Headers $header -Body ($SafeBody | ConvertTo-Json -Depth 5) -ContentType "application/json"
    Write-Log "✅ Safe created successfully."
} catch {
    Write-Log "⚠️ Safe may already exist: $($_.Exception.Message)" "Yellow"
}

# ------------------- Add Members -------------------
$APIEndpointMembers = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/$SafeName/Members/"

foreach ($member in $Members) {
    try {
        $body = $member | ConvertTo-Json -Depth 5 -Compress
        Write-Log "Adding Member: $($member.memberName) to Safe: $SafeName..."
        Invoke-RestMethod -Uri $APIEndpointMembers -Method Post -Headers $header -Body $body -ContentType "application/json"
        Write-Log "✅ Added $($member.memberName) successfully."
    } catch {
        Write-Log "❌ ERROR: Failed to add $($member.memberName) - $($_.Exception.Message)" "Red"
    }
}



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
