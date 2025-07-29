# Import the psPAS Module
Import-Module psPAS

# Define Log File
$LogFile = "SafeMemberAdditionLog.txt"
Function Write-Log {
    Param ([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$Timestamp - $Message"
    Add-Content -Path $LogFile -Value $LogEntry
    Write-Output $LogEntry
}

# Step 1: Define Required Variables (Prompt for Safe Name & Group Name)
$SafeName = Read-Host "Enter the Safe Name to add members to"
$GroupName = Read-Host "Enter the Group Name to be added to the Safe"

# Ensure values are provided
if ([string]::IsNullOrEmpty($SafeName)) {
    Write-Log "❌ ERROR: Safe Name cannot be empty. Exiting..."
    exit
}

if ([string]::IsNullOrEmpty($GroupName)) {
    Write-Log "❌ ERROR: Group Name cannot be empty. Exiting..."
    exit
}

# Step 2: Define CyberArk Authentication Variables
$IdentityTenantID = "aat4012"  # Replace with actual CyberArk Identity tenant ID
$PCloudSubdomain = "cna-prod"  # Replace with actual CyberArk Privilege Cloud Subdomain
$ClientID = Read-Host "Enter your CyberArk API Client ID"
$ClientSecret = Read-Host "Enter your CyberArk API Client Secret" -AsSecureString
$ClientSecret = [System.Net.NetworkCredential]::new("", $ClientSecret).Password  # Convert SecureString to plain text

# Ensure variables are set correctly
if ([string]::IsNullOrEmpty($ClientID) -or [string]::IsNullOrEmpty($ClientSecret)) {
    Write-Log "ERROR: Client ID or Client Secret is missing. Exiting..."
    exit
}

# Step 3: Request Initial Token
Write-Log "Requesting initial CyberArk ISPSS token..."
$TokenURL = "https://$IdentityTenantID.id.cyberark.cloud/oauth2/platformtoken"

$TokenBody = @{
    grant_type    = "client_credentials"
    client_id     = $ClientID
    client_secret = $ClientSecret
}

$headers = @{
    "Content-Type" = "application/x-www-form-urlencoded"
}

try {
    $TokenResponse = Invoke-RestMethod -Uri $TokenURL -Method Post -Headers $headers -Body $TokenBody
    $BearerToken = [string]$TokenResponse.access_token  # Ensure token is a string

    # Ensure Token is Valid
    if ([string]::IsNullOrEmpty($BearerToken) -or $BearerToken.Length -lt 100) {
        Write-Log "ERROR: Received an invalid token. Length: $($BearerToken.Length)"
        exit
    }
    Write-Log "✅ Authentication successful, token obtained."
} catch {
    Write-Log "ERROR: Failed to authenticate with CyberArk ISPSS. $_"
    exit
}

# Step 4: Define Headers for API Requests
$headers = @{
    "Authorization" = "Bearer $BearerToken"
    "Content-Type"  = "application/json"
}

# Step 5: Define API Endpoint for Adding Members to Safe
$APIEndpoint = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/$SafeName/Members/"

# Step 6: Define Permissions for Group & Predefined Members
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

# Step 7: Add Members with Correct `MemberType`
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

    # Construct JSON Payload
    $jsonBody = @{
        "memberName" = $MemberName
        "searchIn" = "Vault"
        "memberType" = $MemberType
        "permissions" = $Permissions
    } | ConvertTo-Json -Depth 3

    Write-Log "Adding ${MemberType}: ${MemberName} to Safe: ${SafeName}..."

    try {
        # Execute API Request
        $Response = Invoke-RestMethod -Uri $APIEndpoint -Method Post -Headers $headers -Body $jsonBody -ErrorAction Stop
        Write-Log "✅ Successfully added ${MemberType}: ${MemberName} to ${SafeName}."
    } catch {
        Write-Log "❌ ERROR: Failed to add ${MemberType}: ${MemberName} to ${SafeName} - $_"
    }
}

Write-Log "🔹 Safe member addition process completed."
