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

# --- Authentication Variables (from CCP) ---
$IdentityTenantID = "aat4012"    # CyberArk Identity tenant ID
$PCloudSubdomain  = "cna-prod"   # Privilege Cloud subdomain
$ClientID         = $response.Username
$ClientSecret     = $response.Content
if ([string]::IsNullOrWhiteSpace($ClientID) -or [string]::IsNullOrWhiteSpace($ClientSecret)) { Write-Log "ERROR: Client ID or Client Secret is missing. Exiting..."; exit }

# --- Request OAuth Token ---
Write-Log "Requesting initial CyberArk ISPSS token..."
$TokenURL = "https://$IdentityTenantID.id.cyberark.cloud/oauth2/platformtoken"
$TokenBody = @{ grant_type="client_credentials"; client_id=$ClientID; client_secret=$ClientSecret }
$headers_token = @{ "Content-Type" = "application/x-www-form-urlencoded" }
try {
    $TokenResponse = Invoke-RestMethod -Uri $TokenURL -Method Post -Headers $headers_token -Body $TokenBody
    $BearerToken = [string]$TokenResponse.access_token
    if ([string]::IsNullOrWhiteSpace($BearerToken) -or $BearerToken.Length -lt 100) { Write-Log "ERROR: Received an invalid token. Length: $($BearerToken.Length)"; exit }
    Write-Log "✅ Authentication successful, token obtained."
} catch { Write-Log "ERROR: Failed to authenticate with CyberArk ISPSS. $_"; exit }

# --- API Headers ---
$headers_api = @{ "Authorization" = "Bearer $BearerToken"; "Content-Type" = "application/json" }

# --- Create Safe ---
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
    Invoke-RestMethod -Uri $APIEndpointSafes -Method Post -Headers $headers_api -Body $SafePayload -ErrorAction Stop | Out-Null
    Write-Log "✅ Successfully created Safe: ${SafeName}."
} catch {
    Write-Log "⚠️ WARNING: Safe may already exist - $($_.Exception.Message)" "Yellow"
}

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

# --- Directory context for AD group ---
$DirectoryName = "cna.com"
$FallbackDirectoryGuid = "4ac5fb05-f776-4be5-9b7f-9ec01c737fa4"   # your known GUID

# Attempt to resolve Directory GUID (ok if it fails; fallback used)
$ResolvedDirectoryGuid = $null
try {
    $dirsEndpoint = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Configuration/LDAP/Directories/"
    $dirs = Invoke-RestMethod -Uri $dirsEndpoint -Headers $headers_api -Method Get -ErrorAction Stop
    $match = $dirs | Where-Object { $_.Name -eq $DirectoryName -or $_.DomainName -eq $DirectoryName -or $_.LDAPDomainName -eq $DirectoryName } | Select-Object -First 1
    if ($match -and $match.Id) { $ResolvedDirectoryGuid = [string]$match.Id; Write-Log "Resolved directory '$DirectoryName' to GUID: $ResolvedDirectoryGuid" }
} catch { Write-Log "⚠️ Failed to query Directories: $($_.Exception.Message). Using fallback GUID." "Yellow" }
if ([string]::IsNullOrWhiteSpace($ResolvedDirectoryGuid)) { $ResolvedDirectoryGuid = $FallbackDirectoryGuid; Write-Log "Using fallback Directory GUID: $ResolvedDirectoryGuid" "Yellow" }

# --- Member inputs ---
function Prompt-ValidADGroupSam {
    param([string]$PromptText)
    while ($true) {
        $group = Read-Host $PromptText
        if ($group -match '^[a-zA-Z0-9_\-\.]+$') { return $group }
        Write-Log "❌ Invalid format. Enter AD group sAMAccountName (e.g., ca_bud_ecf_prod)" "Red"
    }
}
$GroupName = Prompt-ValidADGroupSam -PromptText "Enter the AD Safe Group (sAMAccountName only, e.g., ca_bud_ecf_prod)"
if ([string]::IsNullOrWhiteSpace($GroupName)) { Write-Log "❌ ERROR: Group Name cannot be empty. Exiting..."; exit }

# --- Helpers ---
$SafeNameForUrl   = [System.Uri]::EscapeDataString($SafeName)
$MembersEndpoint  = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/$SafeNameForUrl/Members/"
$UserGroupsBase   = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/API/UserGroups"

function Add-MemberRest {
    param([hashtable]$Body)
    $json = $Body | ConvertTo-Json -Depth 10
    try {
        Invoke-RestMethod -Uri $MembersEndpoint -Method Post -Headers $headers_api -Body $json -ErrorAction Stop | Out-Null
        Write-Log "✅ Added $($Body.memberType): $($Body.memberName)."; return $true
    } catch {
        $err = $_.Exception
        $msg = $null; try { $msg = $err.Response.Content.ReadAsStringAsync().Result } catch {}
        if (-not $msg) { $msg = $_ | Out-String }
        Write-Log "❌ Failed to add '$($Body.memberName)' - $msg" "Red"; return $false
    }
}

function Resolve-DirectoryGroupName {
    param([string]$Sam, [string]$DomainName)
    # Use PVWA "Get Groups" to find the Directory group name PVWA recognizes (contains search)
    $targetSearches = @($Sam, "$Sam@$DomainName")
    foreach ($search in $targetSearches) {
        $q = "$UserGroupsBase?filter=" + [uri]::EscapeDataString("groupType eq Directory") + "&search=" + [uri]::EscapeDataString($search)
        try {
            $res = Invoke-RestMethod -Uri $q -Headers $headers_api -Method Get -ErrorAction Stop
            # Response may be an array or have a 'value' property depending on version
            $groups = @()
            if ($res -is [System.Array]) { $groups = $res }
            elseif ($res.value) { $groups = $res.value }
            else { $groups = @($res) }

            # Prefer exact (case-insensitive) matches, then a single best candidate
            $candidates = $groups | Where-Object { $_.groupType -eq "Directory" -and $_.groupName }
            if ($candidates.Count -gt 0) {
                $exact = $candidates | Where-Object { $_.groupName -ieq $search } | Select-Object -First 1
                if ($exact) { return [string]$exact.groupName }
                # If multiple, prefer those ending with @Domain
                $prefer = $candidates | Where-Object { $_.groupName -match "@$([Regex]::Escape($DomainName))$" } | Select-Object -First 1
                if ($prefer) { return [string]$prefer.groupName }
                return [string]$candidates[0].groupName
            }
        } catch {
            Write-Log "⚠️ Group lookup failed for '$search' - $($_.Exception.Message)" "Yellow"
        }
    }
    return $null
}

# --- 1) Target AD group: resolve group name in PVWA first, then add with SearchIn=<Directory GUID> ---
$ResolvedGroupName = Resolve-DirectoryGroupName -Sam $GroupName -DomainName $DirectoryName
if ($ResolvedGroupName) {
    Write-Log "Found directory group in PVWA as '$ResolvedGroupName' (type=Directory)."
} else {
    Write-Log "⚠️ Directory group '$GroupName' not found via PVWA group search; will try fallbacks." "Yellow"
}

# Build try order for MemberName
$adCandidates = @()
if ($ResolvedGroupName) { $adCandidates += $ResolvedGroupName }
$adCandidates += "$GroupName@$DirectoryName"
$adCandidates += $GroupName
$adCandidates = $adCandidates | Select-Object -Unique

foreach ($mn in $adCandidates) {
    $adGroupBody = @{
        MemberName  = $mn
        MemberType  = "Group"
        SearchIn    = $ResolvedDirectoryGuid         # Directory GUID per Priv Cloud guidance
        Permissions = $LimitedPermissions
    }
    Write-Log "Attempting AD group add with MemberName='$mn' and SearchIn(GUID)=$ResolvedDirectoryGuid..."
    if (Add-MemberRest -Body $adGroupBody) { break }
}

# --- 2) CA_PCloud_Admins@cna.com (registered tenant group - unchanged) ---
$tenantGroupBody = @{
    memberName  = "CA_PCloud_Admins@cna.com"
    memberType  = "Group"
    permissions = $FullPermissions
}
Write-Log "Adding Registered Group 'CA_PCloud_Admins@cna.com'..."
$null = Add-MemberRest -Body $tenantGroupBody

# --- 3) Vault user (unchanged; SearchIn='Vault') ---
$cloudUserBody = @{
    memberName  = "cna_pas_admin@cyberark.cloud.6679"
    memberType  = "User"
    searchIn    = "Vault"
    permissions = $FullPermissions
}
Write-Log "Adding Vault User 'cna_pas_admin@cyberark.cloud.6679'..."
$null = Add-MemberRest -Body $cloudUserBody

Write-Log "🔹 Safe member addition process completed."
