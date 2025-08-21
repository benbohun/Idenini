# --- Network hardening (helps avoid odd TLS/URI issues) ---
[System.Net.ServicePointManager]::Expect100Continue = $false
try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 } catch {}

# --- Logging Utility ---
$LogPath = "E:\Installation Media\Script\OnboardScript\accountonboarding.txt"
Function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$Timestamp - $Message"
    Write-Host $LogEntry -ForegroundColor $Color
    Add-Content -Path $LogPath -Value $LogEntry
}

# --- Safe URI builder (eliminates 'Invalid URI' issues) ---
function New-ApiUri {
    param(
        [Parameter(Mandatory)][string]$HostBase,  # e.g. cna-prod.privilegecloud.cyberark.cloud
        [Parameter(Mandatory)][string]$Path,      # e.g. /PasswordVault/API/Safes/
        [hashtable]$Query                         # optional key/val table
    )
    $hb = $HostBase.Trim()
    if ($hb -notmatch '^https?://') { $hb = "https://$hb" }
    $ub = [System.UriBuilder]::new($hb)
    # ensure leading slash in path
    if (-not $Path.StartsWith('/')) { $Path = "/$Path" }
    # avoid double slashes
    $ub.Path = ($Path -replace '//+', '/')
    if ($Query) {
        $pairs = @()
        foreach ($k in $Query.Keys) {
            $pairs += ("{0}={1}" -f [uri]::EscapeDataString($k), [uri]::EscapeDataString([string]$Query[$k]))
        }
        $ub.Query = ($pairs -join '&')
    } else {
        $ub.Query = $null
    }
    return $ub.Uri.AbsoluteUri
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
        Write-Log "ERROR: Failed to retrieve API credentials from CCP." "Red"; exit 1
    }
    Write-Log "Successfully retrieved credentials for user: $($response.Username)" "Green"
} catch {
    Write-Log "ERROR: CCP credential fetch failed - $_" "Red"; exit 1
}

# --- Prompt for Safe Name & Description ---
$SafeName = Read-Host "Enter the Safe Name"

function Prompt-DescriptionBox {
    param([string]$Title = "Safe Description", [string]$Prompt = "Enter Safe Description (max 200 chars)")
    try {
        Add-Type -AssemblyName System.Windows.Forms | Out-Null
        [System.Windows.Forms.Application]::EnableVisualStyles()
        $form = New-Object System.Windows.Forms.Form
        $form.Text = $Title; $form.Width = 600; $form.Height = 170; $form.StartPosition = "CenterScreen"; $form.TopMost = $true
        $label = New-Object System.Windows.Forms.Label
        $label.Text = $Prompt; $label.AutoSize = $true; $label.Top = 10; $label.Left = 10; $form.Controls.Add($label)
        $textBox = New-Object System.Windows.Forms.TextBox
        $textBox.Multiline = $false; $textBox.Width = 560; $textBox.Top = 40; $textBox.Left = 10; $textBox.MaxLength = 200; $form.Controls.Add($textBox)
        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Text = "OK"; $okButton.Width = 100; $okButton.Height = 30; $okButton.Top = 80; $okButton.Left = 360
        $okButton.Add_Click({ $form.Tag = $textBox.Text; $form.Close() }); $form.Controls.Add($okButton)
        $cancelButton = New-Object System.Windows.Forms.Button
        $cancelButton.Text = "Cancel"; $cancelButton.Width = 100; $cancelButton.Height = 30; $cancelButton.Top = 80; $cancelButton.Left = 470
        $cancelButton.Add_Click({ $form.Tag = $null; $form.Close() }); $form.Controls.Add($cancelButton)
        [void]$form.ShowDialog(); $desc = $form.Tag; $form.Dispose()
        if ([string]::IsNullOrWhiteSpace($desc)) { return $null } else { return $desc }
    } catch {
        return Read-Host "Enter Safe Description (fallback, max 200 chars)"
    }
}
$Description = Prompt-DescriptionBox

if ([string]::IsNullOrWhiteSpace($SafeName))    { Write-Log "❌ ERROR: Safe Name cannot be empty. Exiting..."; exit }
if ([string]::IsNullOrWhiteSpace($Description)) { Write-Log "❌ ERROR: Safe Description cannot be empty. Exiting..."; exit }

# --- Auth / base hosts ---
$IdentityTenantID = "aat4012"    # Identity tenant
$PCloudSubdomain  = "cna-prod"   # Privilege Cloud subdomain
$ClientID         = $response.Username
$ClientSecret     = $response.Content

if ([string]::IsNullOrWhiteSpace($ClientID) -or [string]::IsNullOrWhiteSpace($ClientSecret)) { Write-Log "ERROR: Client ID or Client Secret is missing. Exiting..."; exit }

Write-Log "Requesting initial CyberArk ISPSS token..."
$TokenURL = New-ApiUri -HostBase "$IdentityTenantID.id.cyberark.cloud" -Path "/oauth2/platformtoken"
$TokenBody = @{ grant_type="client_credentials"; client_id=$ClientID; client_secret=$ClientSecret }
$headers_token = @{ "Content-Type" = "application/x-www-form-urlencoded" }

try {
    $TokenResponse = Invoke-RestMethod -Uri $TokenURL -Method Post -Headers $headers_token -Body $TokenBody
    $BearerToken = [string]$TokenResponse.access_token
    if ([string]::IsNullOrWhiteSpace($BearerToken) -or $BearerToken.Length -lt 100) { Write-Log "ERROR: Received an invalid token. Length: $($BearerToken.Length)"; exit }
    Write-Log "✅ Authentication successful, token obtained."
} catch { Write-Log "ERROR: Failed to authenticate with CyberArk ISPSS. $_"; exit }

$headers_api = @{ "Authorization" = "Bearer $BearerToken"; "Content-Type" = "application/json" }
$PVWAHost    = "$PCloudSubdomain.privilegecloud.cyberark.cloud"

# --- Create Safe ---
Write-Log "🔹 Creating Safe: ${SafeName}..."
$SafesUri = New-ApiUri -HostBase $PVWAHost -Path "/PasswordVault/API/Safes/"
$SafePayload = @{
    safeName              = $SafeName
    description           = $Description
    olacEnabled           = $false
    autoPurgeEnabled      = $false
    managingCPM           = "CNA_PASS_MANG"
    numberOfDaysRetention = 180
} | ConvertTo-Json -Depth 3

Write-Log "Creating Safe: ${SafeName} with payload: $SafePayload"
try { Invoke-RestMethod -Uri $SafesUri -Method Post -Headers $headers_api -Body $SafePayload -ErrorAction Stop | Out-Null
      Write-Log "✅ Successfully created Safe: ${SafeName}."
} catch { Write-Log "⚠️ WARNING: Safe may already exist - $($_.Exception.Message)" "Yellow" }

# --- Permissions (exact as requested) ---
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

# --- Members endpoint (URL-encoded Safe) ---
$SafeNameForUrl  = [System.Uri]::EscapeDataString($SafeName)
$MembersUri      = New-ApiUri -HostBase $PVWAHost -Path "/PasswordVault/API/Safes/$SafeNameForUrl/Members/"

function Add-MemberRest {
    param([hashtable]$Body)
    $json = $Body | ConvertTo-Json -Depth 10
    try {
        Invoke-RestMethod -Uri $MembersUri -Method Post -Headers $headers_api -Body $json -ErrorAction Stop | Out-Null
        Write-Log "✅ Added $($Body.memberType): $($Body.memberName)."; return $true
    } catch {
        $err = $_.Exception; $msg = $null
        try { $msg = $err.Response.Content.ReadAsStringAsync().Result } catch {}
        if (-not $msg) { $msg = $_ | Out-String }
        Write-Log "❌ Failed to add '$($Body.memberName)' - $msg" "Red"; return $false
    }
}

# --- Find PVWA directory group (optional helper, now URI-safe) ---
function Find-PVWA-DirectoryGroup {
    param([string]$Search)
    $bases = @("/PasswordVault/API/Groups", "/PasswordVault/API/UserGroups")
    foreach ($p in $bases) {
        $query = @{
            filter = 'groupType eq Directory'
            search = $Search
        }
        $uri = New-ApiUri -HostBase $PVWAHost -Path $p -Query $query
        try {
            $res = Invoke-RestMethod -Uri $uri -Headers $headers_api -Method Get -ErrorAction Stop
            $items = @()
            if ($res -is [System.Array]) { $items = $res }
            elseif ($res.value)          { $items = $res.value }
            elseif ($res.Resources)      { $items = $res.Resources }
            elseif ($res.groups)         { $items = $res.groups }
            else                         { $items = @($res) }

            $candidates = $items | Where-Object { $_.groupType -eq "Directory" -and $_.groupName }
            if ($candidates.Count -gt 0) {
                $pick = $candidates | Select-Object -First 1
                # Try to grab directoryId if present
                $dirId = $null
                foreach ($k in 'directoryId','DirectoryId') {
                    if ($pick.$k) { $dirId = [string]$pick.$k; break }
                }
                return [pscustomobject]@{ GroupName=[string]$pick.groupName; DirectoryId=$dirId }
            }
        } catch { Write-Log "ℹ️ PVWA groups query failed on '$uri' ($($_.Exception.Message)); trying next..." "Yellow" }
    }
    return $null
}

# --- Prompt for target AD group (sAM only) ---
function Prompt-ValidADGroupSam {
    param([string]$PromptText)
    while ($true) {
        $group = Read-Host $PromptText
        if ($group -match '^[a-zA-Z0-9_\-\.]+$') { return $group }
        Write-Log "❌ Invalid format. Enter AD group sAMAccountName (e.g., ca_bud_ecf_prod)" "Red"
    }
}
$DirectoryName = "cna.com"
$FallbackDirectoryGuid = "4ac5fb05-f776-4be5-9b7f-9ec01c737fa4"

$GroupSam = Prompt-ValidADGroupSam -PromptText "Enter the AD Safe Group (sAMAccountName only, e.g., ca_bud_ecf_prod)"
if ([string]::IsNullOrWhiteSpace($GroupSam)) { Write-Log "❌ ERROR: Group Name cannot be empty. Exiting..."; exit }

# --- Try to resolve group in PVWA (URI-safe) ---
Write-Log "Searching PVWA for directory group matching '$GroupSam'..."
$found = Find-PVWA-DirectoryGroup -Search $GroupSam
if (-not $found) {
    $upn = "$GroupSam@$DirectoryName"
    Write-Log "No direct hit. Searching PVWA for '$upn'..."
    $found = Find-PVWA-DirectoryGroup -Search $upn
}

# Build variants to try
$dirGuidToUse = $FallbackDirectoryGuid
$memberNames  = @($GroupSam, "$GroupSam@$DirectoryName")  # sAM first, then UPN

if ($found) {
    Write-Log "Resolved PVWA Directory Group candidate: '$($found.GroupName)'."
    if ($found.GroupName -and ($memberNames -notcontains $found.GroupName)) { $memberNames = @($found.GroupName) + $memberNames }
    if ($found.DirectoryId) { $dirGuidToUse = [string]$found.DirectoryId; Write-Log "Using PVWA DirectoryId: $dirGuidToUse" }
}

# try sAM / UPN / (ask for DN only if needed)
$added = $false
foreach ($mn in $memberNames | Select-Object -Unique) {
    $body = @{
        memberName     = $mn
        memberType     = "Group"
        searchIn       = $dirGuidToUse
        memberLocation = @{ type="Directory"; id=$dirGuidToUse; name=$DirectoryName }
        permissions    = $LimitedPermissions
    }
    Write-Log "Attempting AD Group add: MemberName='$mn' SearchIn(GUID)=$dirGuidToUse ..."
    if (Add-MemberRest -Body $body) { $added = $true; break }
}

# Optional DN prompt if not yet added
if (-not $added) {
    $dn = Read-Host "Paste the AD Group Distinguished Name (DN) or press Enter to skip (e.g., CN=Group,OU=Groups,DC=cna,DC=com)"
    if ($dn -and $dn -match '(?i)CN=.+,.*DC=.+,DC=.+') {
        $bodyDn = @{
            memberName     = $dn
            memberType     = "Group"
            searchIn       = $dirGuidToUse
            memberLocation = @{ type="Directory"; id=$dirGuidToUse; name=$DirectoryName }
            permissions    = $LimitedPermissions
        }
        Write-Log "Attempting AD Group add with DN: '$dn' ..."
        $added = Add-MemberRest -Body $bodyDn
    } else {
        if ($dn) { Write-Log "⚠️ DN format invalid or not provided; skipping DN attempt." "Yellow" }
    }
}

if (-not $added) {
    Write-Log "❌ Could not add AD group '$GroupSam'. This usually means the PVWA Directory Mapping cannot resolve the group from '$DirectoryName' with DirectoryId $dirGuidToUse." "Red"
}

# --- Add CA_PCloud_Admins@cna.com (unchanged) ---
$tenantGroupBody = @{
    memberName  = "CA_PCloud_Admins@cna.com"
    memberType  = "Group"
    permissions = $FullPermissions
}
Write-Log "Adding Registered Group 'CA_PCloud_Admins@cna.com'..."
$null = Add-MemberRest -Body $tenantGroupBody

# --- Add cloud vault user (unchanged) ---
$cloudUserBody = @{
    memberName  = "cna_pas_admin@cyberark.cloud.6679"
    memberType  = "User"
    searchIn    = "Vault"
    permissions = $FullPermissions
}
Write-Log "Adding Vault User 'cna_pas_admin@cyberark.cloud.6679'..."
$null = Add-MemberRest -Body $cloudUserBody

Write-Log "🔹 Safe member addition process completed."
