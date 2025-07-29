Create Safe and Add Default Permission
 
1. Create Safe
2. Add safe group ACL and default permissions
 
Pre-requisite
 
Ensure to check out the BOT API Identity Account (cnarestbot@cyberark.cloud.6679) AND password from CyberArk
 
Steps A (Create Safe)
1. Logon to VSKAU1P1230, Navigate to E:\Installation Media\Script
2. Click file and run PowerShell as an administrator
3. Run .\CreateSafe.ps1 script
4. Enter New Safe Name on the prompt 
5. Enter New Safe Description on the prompt 
6. Enter CyberArk API Client ID on the prompt  (Admin user with ability to change create safe)
7. Enter API Client Secret  on the prompt (Admin user Password)
 
Once Safe is created, follow next steps for adding default permissions
 
Steps B (Add Permission)
1. Navigate to E:\Installation Media\Script
2. Click file and run powershell as an administrator
3. Run .\AddDefaultSafemembership.ps1 script
4. Enter Safe Name on the prompt (Newly Created Safe)
5. Enter Group Name on the prompt  (CA_ safe group, MUST CONTAIN @CNA.COM)
6. Enter CyberArk API Client ID on the prompt  (Admin user with ability to change create safe)
7. Enter API Client Secret on the prompt  (Admin user Password)
8. Logon to PVWA to validate 
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

Retrival step
# CyberArk Account Report via CCP Credential Retrieval (With Process Logging)

# --- Logging Utility ---
$LogPath = "E:\Installation Media\RemovePendingAccount\CyberArk_AccountReport_RunLog.txt"
Function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$Timestamp - $Message"
    Write-Host $LogEntry -ForegroundColor $Color
    Add-Content -Path $LogPath -Value $LogEntry
}

# Settings for CCP/AIMWebService
$CCPAddress = "https://vskau1p1231.cna.com"
$location   = "AIMWebService"
$application= "PAMDiscovery"
$safe       = "CA_PCloud_Admins"
$object     = "cna.com-CA_PAMDiscovery_SVC"

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
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
# Import the psPAS Module
Import-Module psPAS

# Define Log File
$LogFile = "SafeCreationLog.txt"
Function Write-Log {
    Param ([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$Timestamp - $Message"
    Add-Content -Path $LogFile -Value $LogEntry
    Write-Output $LogEntry
}

# Step 1: Define Required Variables (Prompt for Safe Name & Description)
$SafeName = Read-Host "Enter the Safe Name"
$Description = Read-Host "Enter the Safe Description"

# Ensure values are provided
if ([string]::IsNullOrEmpty($SafeName)) {
    Write-Log "❌ ERROR: Safe Name cannot be empty. Exiting..."
    exit
}

if ([string]::IsNullOrEmpty($Description)) {
    Write-Log "❌ ERROR: Safe Description cannot be empty. Exiting..."
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

# Step 5: Create Safe Using API
Write-Log "🔹 Creating Safe: ${SafeName}..."

# Construct API Endpoint
$APIEndpoint = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/"

# Construct JSON Payload (Defaults Applied)
$SafePayload = @{
    "safeName"                  = $SafeName
    "description"               = $Description
    "olacEnabled"               = $false  # Default value
    "autoPurgeEnabled"          = $false  # Default value
    "managingCPM"               = "CNA_PASS_MANG"  # Default CPM
    "numberOfDaysRetention" = 180  # Default retention policy
} | ConvertTo-Json -Depth 3

Write-Log "Creating Safe: ${SafeName} with payload: $SafePayload"

try {
    $Response = Invoke-RestMethod -Uri $APIEndpoint -Method Post -Headers $headers -Body $SafePayload -ErrorAction Stop
    Write-Log "✅ Successfully created Safe: ${SafeName}."
} catch {
    Write-Log "❌ ERROR: Failed to create Safe: ${SafeName} - $_"
}

Write-Log "🔹 Safe creation process completed."

