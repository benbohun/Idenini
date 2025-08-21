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

# Use a single-line dialog (200 chars) with headless fallback
function Prompt-DescriptionBox {
    param([string]$Title = "Safe Description", [string]$Prompt = "Enter Safe Description (max 200 chars)")
    try {
        Add-Type -AssemblyName System.Windows.Forms | Out-Null
        [System.Windows.Forms.Application]::EnableVisualStyles()

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

        $null = $form.ShowDialog()
        $desc = $form.Tag
        $form.Dispose()
        if ([string]::IsNullOrWhiteSpace($desc)) { return $null }
        return $desc
    } catch {
        # Headless/server-core fallback
        return Read-Host "Enter Safe Description (fallback, max 200 chars)"
    }
}
$Description = Prompt-DescriptionBox
if ([string]::IsNullOrWhiteSpace($SafeName)) {
    Write-Log "❌ ERROR: Safe Name cannot be empty. Exiting..."
    exit
}
if ([string]::IsNullOrWhiteSpace($Description)) {
    Write-Log "❌ ERROR: Safe Description cannot be empty. Exiting..."
    exit
}

# --- Authentication Variables (from CCP) ---
$IdentityTenantID = "aat4012"        # CyberArk Identity tenant ID
$PCloudSubdomain  = "cna-prod"       # CyberArk Privilege Cloud Subdomain
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

# --- Define Headers for API Requests ---
$headers_api = @{
    "Authorization" = "Bearer $BearerToken"
    "Content-Type"  = "application/json"
}

# --- Create Safe Using API ---
Write-Log "🔹 Creating Safe: ${SafeName}..."

$APIEndpointSafes = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/"
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
    $null = Invoke-RestMethod -Uri $APIEndpointSafes -Method Post -Headers $headers_api -Body $SafePayload -ErrorAction Stop
    Write-Log "✅ Successfully created Safe: ${SafeName}."
} catch {
    Write-Log "⚠️ WARNING: Safe may already exist - $($_.Exception.Message)" "Yellow"
}

# --- Permissions (your exact requirement) ---
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

# --- Helper: resolve Directory GUID for 'cna.com' ---
$DirectoryName = "cna.com"
$FallbackDirectoryGuid = "4ac5fb05-f776-4be5-9b7f-9ec01c737fa4"  # your known-good GUID
function Get-DirectoryGuidByName {
    param([string]$Name, [hashtable]$Headers, [string]$Subdomain)

    $dirsEndpoint = "https://$Subdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Directories"
    try {
        $dirs = Invoke-RestMethod -Uri $dirsEndpoint -Headers $Headers -Method Get -ErrorAction Stop
        # Expecting an array of directories with properties like id/name/...
        $match = $dirs | Where-Object { $_.name -and ($_.name -eq $Name -or $_.Name -eq $Name) } | Select-Object -First 1
        if ($match -and $match.id) {
            Write-Log "Resolved directory '$Name' to GUID: $($match.id)"
            return [string]$match.id
        } else {
            Write-Log "⚠️ Directory '$Name' not found via API. Using fallback GUID." "Yellow"
            return $null
        }
    } catch {
        Write-Log "⚠️ Failed to retrieve Directories list: $($_.Exception.Message). Using fallback GUID." "Yellow"
        return $null
    }
}

$ResolvedDirectoryGuid = Get-DirectoryGuidByName -Name $DirectoryName -Headers $headers_api -Subdomain $PCloudSubdomain
if ([string]::IsNullOrWhiteSpace($ResolvedDirectoryGuid)) {
    $ResolvedDirectoryGuid = $FallbackDirectoryGuid
    Write-Log "Using fallback Directory GUID: $ResolvedDirectoryGuid" "Yellow"
}

# --- Add Safe Members ---
$APIEndpointMembers = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/$SafeName/Members/"

# Prompt for AD Group (sAMAccountName only)
function Prompt-ValidADGroupSam {
    param([string]$PromptText)
    while ($true) {
        $group = Read-Host $PromptText
        if ($group -match '^[a-zA-Z0-9_\-\.]+$') { return $group }
        Write-Log "❌ Invalid format. Enter the AD group using its sAMAccountName (e.g., ca_bud_ecf_prod)" "Red"
    }
}
$GroupName = Read-Host "Enter the AD Group Name (sAMAccountName only, e.g., ca_bud_ecf_prod)"
if ([string]::IsNullOrEmpty($GroupName)) {
    Write-Log "❌ ERROR: Group Name cannot be empty. Exiting..."
    exit
}

# Build the three members exactly as required
$Members = @(
    # Target AD Group from CNA directory (Directory GUID + MemberLocation)
    @{
        "MemberName"     = $GroupName
        "MemberType"     = "Group"
        "SearchIn"       = $ResolvedDirectoryGuid
        "MemberLocation" = @{
            "Type" = "Directory"
            "Id"   = $ResolvedDirectoryGuid
            "Name" = $DirectoryName
        }
        "Permissions"    = $LimitedPermissions
    },

    # CA_PCloud_Admins — already registered in tenant (leave as-is)
    @{
        "MemberName"  = "CA_PCloud_Admins@cna.com"
        "MemberType"  = "Group"
        "Permissions" = $FullPermissions
    },

    # Cloud user in Vault
    @{
        "MemberName"  = "cna_pas_admin@cyberark.cloud.6679"
        "MemberType"  = "User"
        "SearchIn"    = "Vault"
        "Permissions" = $FullPermissions
    }
)

# Helper: POST a member with retry patterns for directory groups
function Add-MemberWithRetries {
    param(
        [Parameter(Mandatory)][string]$Endpoint,
        [Parameter(Mandatory)][hashtable]$Headers,
        [Parameter(Mandatory)][hashtable]$Member
    )

    $makeJson = { param($m) ($m | ConvertTo-Json -Depth 8) }

    $nameTried = @()
    $tryQueue = New-Object System.Collections.Queue

    # Enqueue original
    $tryQueue.Enqueue(($Member.Clone()))

    # If Directory Group, enqueue fallbacks (DOMAIN\sam, sam@domain)
    $isDirGroup = ($Member.MemberType -eq "Group" -and $Member.SearchIn -match '^[0-9a-fA-F-]{32,36}$')
    if ($isDirGroup) {
        $sam = ($Member.MemberName -split '@')[0] -replace '^[^\\]*\\',''  # strip domain\ if present
        $domainNetBIOS = "CNA"
        $upn = "$sam@$DirectoryName"

        # DOMAIN\sam
        $m1 = $Member.Clone()
        $m1.MemberName = "$domainNetBIOS\$sam"
        $tryQueue.Enqueue($m1)

        # sam@cna.com
        $m2 = $Member.Clone()
        $m2.MemberName = $upn
        $tryQueue.Enqueue($m2)
    }

    while ($tryQueue.Count -gt 0) {
        $m = $tryQueue.Dequeue()
        $name = $m.MemberName
        if ($nameTried -contains $name) { continue }
        $nameTried += $name

        $json = & $makeJson $m
        Write-Log "Adding $($m.MemberType): $name (searchIn=$($m.SearchIn))..."

        try {
            Invoke-RestMethod -Uri $Endpoint -Method Post -Headers $Headers -Body $json -ErrorAction Stop | Out-Null
            Write-Log "✅ Successfully added $($m.MemberType): $name."
            return $true
        } catch {
            $errBody = $null
            try { $errBody = $_.Exception.Response.Content.ReadAsStringAsync().Result } catch {}
            if (-not $errBody) { $errBody = $_ | Out-String }

            # 404 can occur if route is right but SafeName has special chars (need url-encode) OR bad SearchIn.
            # Here we specifically look for "has not been defined" and keep trying alternates.
            $notDefined = ($errBody -match '"ErrorCode"\s*:\s*"SFWS0010"')
            Write-Log "❌ Failed to add '$name' - $errBody" "Red"

            if (-not $notDefined) {
                # Non-resolution error; stop retrying
                break
            } else {
                # keep loop to try next alternate
                continue
            }
        }
    }

    return $false
}

# URL-encode SafeName in member endpoint to avoid 404 for special characters/spaces
$SafeNameForUrl = [System.Web.HttpUtility]::UrlEncode($SafeName)
$APIEndpointMembersEncoded = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/$SafeNameForUrl/Members/"

foreach ($m in $Members) {
    $null = Add-MemberWithRetries -Endpoint $APIEndpointMembersEncoded -Headers $headers_api -Member $m
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
