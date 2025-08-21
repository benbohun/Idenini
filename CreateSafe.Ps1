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

# --- Permissio
