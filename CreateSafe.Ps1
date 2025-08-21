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

function Prompt-DescriptionBox {
    param([string]$Title = "Safe Description", [string]$Prompt = "Enter Safe Description (max 200 chars)")
    try {
        Add-Type -AssemblyName System.Windows.Forms | Out-Null
        [System.Windows.Forms.Application]::EnableVisualStyles()
        $form = New-Object System.Windows.Forms.Form
        $form.Text = $Title; $form.Width = 600; $form.Height = 170; $form.StartPosition = "CenterScreen"; $form.TopMost = $true

        $label = New-Object System.Windows.Forms.Label
        $label.Text = $Prompt; $label.AutoSize = $true; $label.Top = 10; $label.Left = 10
        $form.Controls.Add($label)

        $textBox = New-Object System.Windows.Forms.TextBox
        $textBox.Multiline = $false; $textBox.Width = 560; $textBox.Top = 40; $textBox.Left = 10; $textBox.MaxLength = 200
        $form.Controls.Add($textBox)

        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Text = "OK"; $okButton.Width = 100; $okButton.Height = 30; $okButton.Top = 80; $okButton.Left = 360
        $okButton.Add_Click({ $form.Tag = $textBox.Text; $form.Close() })
        $form.Controls.Add($okButton)

        $cancelButton = New-Object System.Windows.Forms.Button
        $cancelButton.Text = "Cancel"; $cancelButton.Width = 100; $cancelButton.Height = 30; $cancelButton.Top = 80; $cancelButton.Left = 470
        $cancelButton.Add_Click({ $form.Tag = $null; $form.Close() })
        $form.Controls.Add($cancelButton)

        [void]$form.ShowDialog()
        $desc = $form.Tag; $form.Dispose()
        if ([string]::IsNullOrWhiteSpace($desc)) { return $null } else { return $desc }
    } catch {
        return Read-Host "Enter Safe Description (fallback, max 200 chars)"
    }
}
$Description = Prompt-DescriptionBox

if ([string]::IsNullOrWhiteSpace($SafeName))    { Write-Log "❌ ERROR: Safe Name cannot be empty. Exiting..."; exit }
if ([string]::IsNullOrWhiteSpace($Description)) { Write-Log "❌ ERROR: Safe Description cannot be empty. Exiting..."; exit }

# --- Authentication Variables (from CCP) ---
$IdentityTenantID = "aat4012"      # CyberArk Identity tenant ID
$PCloudSubdomain  = "cna-prod"     # CyberArk Privilege Cloud subdomain
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

# --- Helpers ---
$SafeNameForUrl  = [System.Uri]::EscapeDataString($SafeName)
$MembersEndpoint = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/$SafeNameForUrl/Members/"

function Add-MemberRest {
    param([hashtable]$Body)
    $json = $Body | ConvertTo-Json -Depth 10
    try {
        Invoke-RestMethod -Uri $MembersEndpoint -Method Post -Headers $headers_api -Body $json -ErrorAction Stop | Out-Null
        Write-Log "✅ Added $($Body.memberType): $($Body.memberName)."
        return $true
    } catch {
        $err = $_.Exception
        $msg = $null; try { $msg = $err.Response.Content.ReadAsStringAsync().Result } catch {}
        if (-not $msg) { $msg = $_ | Out-String }
        Write-Log "❌ Failed to add '$($Body.memberName)' - $msg" "Red"
        return $false
    }
}

# --- Find directory group in PVWA and get its directoryId (no SCIM; avoids DNS) ---
function Find-PVWA-DirectoryGroup {
    param([string]$Search, [string]$DomainName)

    $bases = @(
        "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Groups",
        "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/API/UserGroups"  # fallback for older routes
    )

    foreach ($base in $bases) {
        try {
            $url = "$base?filter=" + [uri]::EscapeDataString("groupType eq Directory") + "&search=" + [uri]::EscapeDataString($Search)
            $res = Invoke-RestMethod -Uri $url -Headers $headers_api -Method Get -ErrorAction Stop
            $items = @()
            if ($res -is [System.Array]) { $items = $res }
            elseif ($res.value)          { $items = $res.value }
            elseif ($res.Resources)      { $items = $res.Resources }
            elseif ($res.groups)         { $items = $res.groups }
            else                         { $items = @($res) }

            $candidates = $items | Where-Object { $_.groupType -eq "Directory" -and $_.groupName }
            if ($candidates.Count -gt 0) {
                # Prefer exact search match, then *@domain
                $exact   = $candidates | Where-Object { $_.groupName -ieq $Search } | Select-Object -First 1
                $atMatch = $candidates | Where-Object { $_.groupName -match "@$([Regex]::Escape($DomainName))$" } | Select-Object -First 1
                $pick = $exact; if (-not $pick) { $pick = $atMatch }; if (-not $pick) { $pick = $candidates[0] }
                # Try to get directoryId either directly or via details call
                $dirId = $null
                if ($pick.directoryId) { $dirId = [string]$pick.directoryId }
                elseif ($pick.DirectoryId) { $dirId = [string]$pick.DirectoryId }
                elseif ($pick.id) {
                    try {
                        $detailUrl = "$base/$([uri]::EscapeDataString([string]$pick.id))"
                        $det = Invoke-RestMethod -Uri $detailUrl -Headers $headers_api -Method Get -ErrorAction Stop
                        if ($det.directoryId) { $dirId = [string]$det.directoryId }
                        elseif ($det.DirectoryId) { $dirId = [string]$det.DirectoryId }
                    } catch {}
                }
                return [pscustomobject]@{
                    GroupName  = [string]$pick.groupName
                    DirectoryId= $dirId
                }
            }
        } catch {
            Write-Log "ℹ️ PVWA groups query failed on '$base' ($($_.Exception.Message)); trying next..." "Yellow"
        }
    }
    return $null
}

# --- Prompt for target AD group (sAM only, as you requested) ---
function Prompt-ValidADGroupSam {
    param([string]$PromptText)
    while ($true) {
        $group = Read-Host $PromptText
        if ($group -match '^[a-zA-Z0-9_\-\.]+$') { return $group }
        Write-Log "❌ Invalid format. Enter AD group sAMAccountName (e.g., ca_bud_ecf_prod)" "Red"
    }
}
$DirectoryName = "cna.com"
$FallbackDirectoryGuid = "4ac5fb05-f776-4be5-9b7f-9ec01c737fa4"  # your known GUID

$GroupSam = Prompt-ValidADGroupSam -PromptText "Enter the AD Safe Group (sAMAccountName only, e.g., ca_bud_ecf_prod)"
if ([string]::IsNullOrWhiteSpace($GroupSam)) { Write-Log "❌ ERROR: Group Name cannot be empty. Exiting..."; exit }

# --- Resolve AD group via PVWA (no SCIM) ---
Write-Log "Searching PVWA for directory group matching '$GroupSam'..."
$found = Find-PVWA-DirectoryGroup -Search $GroupSam -DomainName $DirectoryName
if (-not $found) {
    # Try sam@domain as a second search term
    $upn = "$GroupSam@$DirectoryName"
    Write-Log "No direct hit. Searching PVWA for '$upn'..."
    $found = Find-PVWA-DirectoryGroup -Search $upn -DomainName $DirectoryName
}

if ($found) {
    $memberNameToUse = $found.GroupName
    $dirGuidToUse    = $found.DirectoryId
    if ([string]::IsNullOrWhiteSpace($dirGuidToUse)) {
        Write-Log "⚠️ PVWA did not return directoryId for '$memberNameToUse'. Using fallback GUID." "Yellow"
        $dirGuidToUse = $FallbackDirectoryGuid
    } else {
        Write-Log "Resolved PVWA Directory Group: '$memberNameToUse' with DirectoryId=$dirGuidToUse"
    }

    $adGroupBody = @{
        memberName  = $memberNameToUse
        memberType  = "Group"
        searchIn    = $dirGuidToUse         # Directory GUID from PVWA (or fallback)
        permissions = $LimitedPermissions
    }
    Write-Log "Adding AD Group '$memberNameToUse' (SearchIn=$dirGuidToUse)..."
    $null = Add-MemberRest -Body $adGroupBody
} else {
    Write-Log "❌ Could not find AD group '$GroupSam' in PVWA directory groups. Skipping AD group add." "Red"
}

# --- Add CA_PCloud_Admins@cna.com (unchanged flow) ---
$tenantGroupBody = @{
    memberName  = "CA_PCloud_Admins@cna.com"
    memberType  = "Group"
    permissions = $FullPermissions
}
Write-Log "Adding Registered Group 'CA_PCloud_Admins@cna.com'..."
$null = Add-MemberRest -Body $tenantGroupBody

# --- Add cloud vault user (unchanged; SearchIn='Vault') ---
$cloudUserBody = @{
    memberName  = "cna_pas_admin@cyberark.cloud.6679"
    memberType  = "User"
    searchIn    = "Vault"
    permissions = $FullPermissions
}
Write-Log "Adding Vault User 'cna_pas_admin@cyberark.cloud.6679'..."
$null = Add-MemberRest -Body $cloudUserBody

Write-Log "🔹 Safe member addition process completed."
