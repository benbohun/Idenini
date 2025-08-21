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
    if (-not $response -or -not $response.Username -or -not $response.Content) { Write-Log "ERROR: Failed to retrieve API credentials from CCP." "Red"; exit 1 }
    Write-Log "Successfully retrieved credentials for user: $($response.Username)" "Green"
} catch { Write-Log "ERROR: CCP credential fetch failed - $_" "Red"; exit 1 }

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
        $okButton.Text = "OK"; $okButton.Width = 100; $okButton.Height = 30; $okButton.Top = 80; $okButton.Left = 360; $okButton.Add_Click({ $form.Tag = $textBox.Text; $form.Close() }); $form.Controls.Add($okButton)
        $cancelButton = New-Object System.Windows.Forms.Button
        $cancelButton.Text = "Cancel"; $cancelButton.Width = 100; $cancelButton.Height = 30; $cancelButton.Top = 80; $cancelButton.Left = 470; $cancelButton.Add_Click({ $form.Tag = $null; $form.Close() }); $form.Controls.Add($cancelButton)
        [void]$form.ShowDialog(); $desc = $form.Tag; $form.Dispose(); if ([string]::IsNullOrWhiteSpace($desc)) { return $null } else { return $desc }
    } catch { return Read-Host "Enter Safe Description (fallback, max 200 chars)" }
}
$Description = Prompt-DescriptionBox

if ([string]::IsNullOrWhiteSpace($SafeName))    { Write-Log "❌ ERROR: Safe Name cannot be empty. Exiting..."; exit }
if ([string]::IsNullOrWhiteSpace($Description)) { Write-Log "❌ ERROR: Safe Description cannot be empty. Exiting..."; exit }

# --- Authentication Variables (from CCP) ---
$IdentityTenantID = "aat4012"        # CyberArk Identity tenant ID (SCIM host too)
$PCloudSubdomain  = "cna-prod"       # Privilege Cloud subdomain (PVWA APIs)
$ClientID         = $response.Username
$ClientSecret     = $response.Content
if ([string]::IsNullOrWhiteSpace($ClientID) -or [string]::IsNullOrWhiteSpace($ClientSecret)) { Write-Log "ERROR: Client ID/Secret missing. Exiting..."; exit }

# --- Request OAuth Token (Identity platform token covers PVWA & SCIM) ---
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

# --- Create Safe (PVWA REST) ---
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
try { Invoke-RestMethod -Uri $APIEndpointSafes -Method Post -Headers $headers_api -Body $SafePayload -ErrorAction Stop | Out-Null; Write-Log "✅ Successfully created Safe: ${SafeName}." }
catch { Write-Log "⚠️ WARNING: Safe may already exist - $($_.Exception.Message)" "Yellow" }

# --- Permission sets (unchanged) ---
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

# ---------- SCIM helpers (target AD group only) ----------
# SCIM base(s). Try Identity first, then PVWA.
$ScimBases = @(
    "https://$IdentityTenantID.id.cyberark.cloud/CyberArk/scim/v2",
    "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/CyberArk/scim/v2"
)

function Invoke-Scim {
    param([string]$Path, [string]$Method, $Body=$null)
    $lastErr = $null
    foreach ($base in $ScimBases) {
        $url = "$base$Path"
        try {
            if ($Body -ne $null) {
                $json = ($Body | ConvertTo-Json -Depth 12)
                return Invoke-RestMethod -Uri $url -Method $Method -Headers $headers_api -Body $json -ErrorAction Stop
            } else {
                return Invoke-RestMethod -Uri $url -Method $Method -Headers $headers_api -ErrorAction Stop
            }
        } catch { $lastErr = $_ }
    }
    throw $lastErr
}

function Get-ScimRightsFromPermissions {
    param($perm)
    # First try UI-friendly labels
    $labels = @()
    if ($perm.listAccounts)            { $labels += "List" }
    if ($perm.viewAuditLog)            { $labels += "View audit log" }
    if ($perm.viewSafeMembers)         { $labels += "View Safe Members" }
    if ($perm.initiateCPMAccountManagementOperations) { $labels += "Initiate CPM change" }
    if ($perm.unlockAccounts)          { $labels += "Unlock accounts" }
    if ($perm.useAccounts)             { $labels += "Use accounts" }
    if ($perm.retrieveAccounts)        { $labels += "Retrieve accounts" }
    if ($perm.addAccounts)             { $labels += "Add" }
    if ($perm.updateAccountContent)    { $labels += "Update content" }
    if ($perm.updateAccountProperties) { $labels += "Update properties" }
    if ($perm.specifyNextAccountContent){ $labels += "Specify next password" }
    if ($perm.renameAccounts)          { $labels += "Rename accounts" }
    if ($perm.deleteAccounts)          { $labels += "Delete accounts" }
    if ($perm.manageSafe)              { $labels += "Manage Safe" }
    if ($perm.manageSafeMembers)       { $labels += "Manage Safe Members" }
    if ($perm.backupSafe)              { $labels += "Backup Safe" }
    if ($perm.accessWithoutConfirmation){ $labels += "Access without confirmation" }
    if ($perm.createFolders)           { $labels += "Create folders" }
    if ($perm.deleteFolders)           { $labels += "Delete folders" }
    if ($perm.moveAccountsAndFolders)  { $labels += "Move accounts and folders" }
    if ($perm.requestsAuthorizationLevel1){ $labels += "Requests authorization level 1" }
    if ($perm.requestsAuthorizationLevel2){ $labels += "Requests authorization level 2" }
    ,$labels
}

function Get-ScimRightsLowerCamel {
    param($perm)
    $lc = @()
    foreach ($k in $perm.Keys) { if ($perm[$k]) { $lc += $k } }
    ,$lc
}

# --- Inputs for target AD group (SCIM requires DN & objectGUID) ---
function Prompt-ValidSam { param([string]$Prompt) do { $v = Read-Host $Prompt } while ($v -notmatch '^[a-zA-Z0-9._-]+$'); return $v }
function Prompt-ValidGuid {
    param([string]$Prompt)
    while ($true) {
        $g = Read-Host $Prompt
        if ([string]::IsNullOrWhiteSpace($g)) { continue }
        $g2 = $g.Trim('{}')
        if ($g2 -match '^[0-9a-fA-F-]{32,36}$') { return $g2.ToUpper() }
        Write-Log "❌ Invalid GUID format. Example: 3F2504E0-4F89-11D3-9A0C-0305E82C3301" "Red"
    }
}
function Prompt-ValidDN {
    param([string]$Prompt)
    while ($true) {
        $dn = Read-Host $Prompt
        if ($dn -match '(?i)CN=.+,.*DC=.+,DC=.+') { return $dn }
        Write-Log "❌ Please paste a valid Distinguished Name (e.g., CN=Group,OU=Groups,DC=cna,DC=com)" "Red"
    }
}

$DirectoryName = "cna.com"  # SCIM 'ldapDirectory' name
$GroupSam      = Prompt-ValidSam -Prompt "Enter the AD Safe Group (sAMAccountName, e.g., ca_bud_ecf_prod)"
$GroupDN       = Prompt-ValidDN  -Prompt "Paste the AD Group Distinguished Name (DN) (e.g., CN=...,OU=...,DC=cna,DC=com)"
$GroupGUID     = Prompt-ValidGuid -Prompt "Paste the AD Group objectGUID (e.g., 3F2504E0-4F89-11D3-9A0C-0305E82C3301)"

# --- Step 1: Ensure External Group exists (SCIM /Groups) ---
function Ensure-ExternalGroup {
    param([string]$DisplayName,[string]$LdapDN,[string]$LdapDirectory,[string]$Description="")
    # Try to find by displayName
    try {
        $filter = [uri]::EscapeDataString("displayName eq `"$DisplayName`"")
        $res = Invoke-Scim -Path "/Groups?filter=$filter" -Method "GET"
        $items = @()
        if ($res -is [System.Array]) { $items = $res }
        elseif ($res.Resources)      { $items = $res.Resources }
        elseif ($res.value)          { $items = $res.value }
        if ($items.Count -gt 0) {
            Write-Log "External group '$DisplayName' already exists in SCIM."; return $items[0]
        }
    } catch { Write-Log "ℹ️ SCIM group search failed or returned none, will attempt to create. $($_.Exception.Message)" "Yellow" }

    # Create
    $body = @{
        displayName = $DisplayName
        "urn:ietf:params:scim:schemas:cyberark:1.0:Group" = @{
            location      = "\\Groups"
            ldapFullDN    = $LdapDN
            ldapDirectory = $LdapDirectory
            description   = $Description
        }
    }
    Write-Log "Creating external group '$DisplayName' in SCIM..."
    $created = Invoke-Scim -Path "/Groups" -Method "POST" -Body $body
    Write-Log "✅ External group ensured: $DisplayName"
    return $created
}

# --- Step 2: Add Container Permission for the group (SCIM /ContainerPermissions) ---
function Grant-ContainerPermission-ToGroup {
    param([string]$Safe,[string]$GroupObjectGuid,$permObj)

    # Attempt 1: human-friendly rights labels
    $rights1 = Get-ScimRightsFromPermissions $permObj
    if ($rights1.Count -eq 0) { $rights1 = @("List") } # minimal
    $payload1 = @{
        schemas  = @("urn:ietf:params:scim:schemas:pam:1.0:ContainerPermissions")
        rights   = $rights1
        container= @{ display=$Safe; name=$Safe }
        member   = @{ value=$GroupObjectGuid; type="Group" }
    }
    Write-Log "Granting SCIM ContainerPermissions (labels) to group GUID=$GroupObjectGuid on safe '$Safe'..."
    try {
        $null = Invoke-Scim -Path "/ContainerPermissions" -Method "POST" -Body $payload1
        Write-Log "✅ SCIM permissions applied (labels)."
        return
    } catch {
        Write-Log "⚠️ Label rights failed, trying lowerCamel rights... $($_.Exception.Message)" "Yellow"
    }

    # Attempt 2: lowerCamel rights (keys)
    $rights2 = Get-ScimRightsLowerCamel $permObj
    if ($rights2.Count -eq 0) { $rights2 = @("listAccounts") }
    $payload2 = @{
        schemas  = @("urn:ietf:params:scim:schemas:pam:1.0:ContainerPermissions")
        rights   = $rights2
        container= @{ display=$Safe; name=$Safe }
        member   = @{ value=$GroupObjectGuid; type="Group" }
    }
    try {
        $null = Invoke-Scim -Path "/ContainerPermissions" -Method "POST" -Body $payload2
        Write-Log "✅ SCIM permissions applied (lowerCamel)."
        return
    } catch {
        Write-Log "⚠️ lowerCamel rights failed, trying minimal 'List' only... $($_.Exception.Message)" "Yellow"
    }

    # Attempt 3: minimal right to establish membership
    $payload3 = @{
        schemas  = @("urn:ietf:params:scim:schemas:pam:1.0:ContainerPermissions")
        rights   = @("List")
        container= @{ display=$Safe; name=$Safe }
        member   = @{ value=$GroupObjectGuid; type="Group" }
    }
    $null = Invoke-Scim -Path "/ContainerPermissions" -Method "POST" -Body $payload3
    Write-Log "✅ SCIM minimal permission applied (List)."
}

# Execute SCIM flow for target AD group
try {
    $null = Ensure-ExternalGroup -DisplayName $GroupSam -LdapDN $GroupDN -LdapDirectory $DirectoryName -Description ""
    Grant-ContainerPermission-ToGroup -Safe $SafeName -GroupObjectGuid $GroupGUID -permObj $LimitedPermissions
} catch {
    Write-Log "❌ SCIM flow failed for target AD group - $($_.Exception.Message)" "Red"
}

# ---------- Add remaining members with PVWA REST (unchanged) ----------
$SafeNameForUrl = [System.Uri]::EscapeDataString($SafeName)
$MembersEndpoint = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/$SafeNameForUrl/Members/"
function Add-MemberRest {
    param([hashtable]$Body)
    $json = $Body | ConvertTo-Json -Depth 10
    try { Invoke-RestMethod -Uri $MembersEndpoint -Method Post -Headers $headers_api -Body $json -ErrorAction Stop | Out-Null; Write-Log "✅ Added $($Body.memberType): $($Body.memberName)."; return $true }
    catch {
        $err = $_.Exception; $msg = $null; try { $msg = $err.Response.Content.ReadAsStringAsync().Result } catch {}; if (-not $msg) { $msg = $_ | Out-String }
        Write-Log "❌ Failed to add '$($Body.memberName)' - $msg" "Red"; return $false
    }
}

# 1) Tenant group (unchanged - already registered)
$tenantGroupBody = @{ memberName="CA_PCloud_Admins@cna.com"; memberType="Group"; permissions=$FullPermissions }
Write-Log "Adding Registered Group 'CA_PCloud_Admins@cna.com' (PVWA REST)..."
$null = Add-MemberRest -Body $tenantGroupBody

# 2) Vault user (unchanged)
$cloudUserBody = @{ memberName="cna_pas_admin@cyberark.cloud.6679"; memberType="User"; searchIn="Vault"; permissions=$FullPermissions }
Write-Log "Adding Vault User 'cna_pas_admin@cyberark.cloud.6679' (PVWA REST)..."
$null = Add-MemberRest -Body $cloudUserBody

Write-Log "🔹 Safe member addition process completed."
