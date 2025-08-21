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
        [void]$form.ShowDialog(); $desc = $form.Tag; $form.Dispose(); if ([string]::IsNullOrWhiteSpace($desc)) { return $null } else { return $desc }
    } catch {
        return Read-Host "Enter Safe Description (fallback, max 200 chars)"
    }
}
$Description = Prompt-DescriptionBox

if ([string]::IsNullOrWhiteSpace($SafeName)) { Write-Log "❌ ERROR: Safe Name cannot be empty. Exiting..."; exit }
if ([string]::IsNullOrWhiteSpace($Description)) { Write-Log "❌ ERROR: Safe Description cannot be empty. Exiting..."; exit }

# --- Authentication Variables (from CCP) ---
$IdentityTenantID = "aat4012"
$PCloudSubdomain  = "cna-prod"
$ClientID         = $response.Username
$ClientSecret     = $response.Content
if ([string]::IsNullOrWhiteSpace($ClientID) -or [string]::IsNullOrWhiteSpace($ClientSecret)) { Write-Log "ERROR: Client ID or Client Secret is missing. Exiting..."; exit }

# --- Request OAuth Token ---
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

# --- Define Headers for API Requests ---
$headers_api = @{ "Authorization" = "Bearer $BearerToken"; "Content-Type" = "application/json" }

# --- Create Safe Using API ---
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
try { Invoke-RestMethod -Uri $APIEndpointSafes -Method Post -Headers $headers_api -Body $SafePayload -ErrorAction Stop | Out-Null
     Write-Log "✅ Successfully created Safe: ${SafeName}." }
catch { Write-Log "⚠️ WARNING: Safe may already exist - $($_.Exception.Message)" "Yellow" }

# --- Permissions (exact per your requirement) ---
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

# --- Resolve Directory GUID for 'cna.com' (for REST path); use name for cmdlets ---
$DirectoryName = "cna.com"
$FallbackDirectoryGuid = "4ac5fb05-f776-4be5-9b7f-9ec01c737fa4"
function Get-DirectoryGuidByName {
    param([string]$Name)
    $dirsEndpoint = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Directories"
    try {
        $dirs = Invoke-RestMethod -Uri $dirsEndpoint -Headers $headers_api -Method Get -ErrorAction Stop
        $match = $dirs | Where-Object { $_.name -and ($_.name -eq $Name -or $_.Name -eq $Name) } | Select-Object -First 1
        if ($match -and $match.id) { Write-Log "Resolved directory '$Name' to GUID: $($match.id)"; return [string]$match.id }
        Write-Log "⚠️ Directory '$Name' not found via API. Using fallback GUID." "Yellow"; return $null
    } catch { Write-Log "⚠️ Failed to query Directories: $($_.Exception.Message). Using fallback GUID." "Yellow"; return $null }
}
$ResolvedDirectoryGuid = Get-DirectoryGuidByName -Name $DirectoryName
if ([string]::IsNullOrWhiteSpace($ResolvedDirectoryGuid)) { $ResolvedDirectoryGuid = $FallbackDirectoryGuid; Write-Log "Using fallback Directory GUID: $ResolvedDirectoryGuid" "Yellow" }

# --- Member Inputs ---
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

# --- Helper: map permissions hash -> cmdlet parameters ---
function Get-PermissionParams {
    param($perm)
    return @{
        UseAccounts                           = [bool]$perm.useAccounts
        RetrieveAccounts                      = [bool]$perm.retrieveAccounts
        ListAccounts                          = [bool]$perm.listAccounts
        AddAccounts                           = [bool]$perm.addAccounts
        UpdateAccountContent                  = [bool]$perm.updateAccountContent
        UpdateAccountProperties               = [bool]$perm.updateAccountProperties
        InitiateCPMAccountManagementOperations= [bool]$perm.initiateCPMAccountManagementOperations
        SpecifyNextAccountContent             = [bool]$perm.specifyNextAccountContent
        RenameAccounts                        = [bool]$perm.renameAccounts
        DeleteAccounts                        = [bool]$perm.deleteAccounts
        UnlockAccounts                        = [bool]$perm.unlockAccounts
        ManageSafe                            = [bool]$perm.manageSafe
        ManageSafeMembers                     = [bool]$perm.manageSafeMembers
        BackupSafe                            = [bool]$perm.backupSafe
        ViewAuditLog                          = [bool]$perm.viewAuditLog
        ViewSafeMembers                       = [bool]$perm.viewSafeMembers
        AccessWithoutConfirmation             = [bool]$perm.accessWithoutConfirmation
        CreateFolders                         = [bool]$perm.createFolders
        DeleteFolders                         = [bool]$perm.deleteFolders
        MoveAccountsAndFolders                = [bool]$perm.moveAccountsAndFolders
        requestsAuthorizationLevel1           = [bool]$perm.requestsAuthorizationLevel1
        requestsAuthorizationLevel2           = [bool]$perm.requestsAuthorizationLevel2
    }
}

# --- Smart add functions (cmdlet first, REST fallback) ---
$SafeNameForUrl = [System.Web.HttpUtility]::UrlEncode($SafeName)
$MembersEndpoint = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/$SafeNameForUrl/Members/"

function Add-DirectoryGroup {
    param([string]$MemberSam, $PermHash)
    $permParams = Get-PermissionParams $PermHash

    if (Get-Command Add-PASSafeMember -ErrorAction SilentlyContinue) {
        Write-Log "Adding Group '$MemberSam' via Add-PASSafeMember (-SearchIn $DirectoryName)..."
        Add-PASSafeMember -SafeName $SafeName -MemberName $MemberSam -SearchIn $DirectoryName -memberType Group @permParams  # uses directory NAME, per doc. :contentReference[oaicite:2]{index=2}
        return
    }
    if (Get-Command Set-SafeMember -ErrorAction SilentlyContinue) {
        Write-Log "Adding Group '$MemberSam' via Set-SafeMember (-memberSearchInLocation $DirectoryName)..."
        Set-SafeMember -safename $SafeName -safeMember $MemberSam -MemberType Group -memberSearchInLocation $DirectoryName @permParams
        return
    }

    # Raw REST fallback (Privilege Cloud requires GUID in searchIn + memberLocation). :contentReference[oaicite:3]{index=3}
    $body = @{
        memberName     = $MemberSam
        memberType     = "Group"
        searchIn       = $ResolvedDirectoryGuid
        memberLocation = @{ type = "Directory"; id = $ResolvedDirectoryGuid; name = $DirectoryName }
        permissions    = $PermHash
    } | ConvertTo-Json -Depth 8
    Write-Log "Adding Group '$MemberSam' via REST (searchIn GUID=$ResolvedDirectoryGuid)..."
    Invoke-RestMethod -Uri $MembersEndpoint -Method Post -Headers $headers_api -Body $body -ErrorAction Stop | Out-Null
}

function Add-RegisteredGroup {
    param([string]$MemberName, $PermHash)
    $permParams = Get-PermissionParams $PermHash
    if (Get-Command Add-PASSafeMember -ErrorAction SilentlyContinue) {
        Write-Log "Adding Registered Group '$MemberName' via Add-PASSafeMember..."
        Add-PASSafeMember -SafeName $SafeName -MemberName $MemberName -memberType Group @permParams
        return
    }
    if (Get-Command Set-SafeMember -ErrorAction SilentlyContinue) {
        Write-Log "Adding Registered Group '$MemberName' via Set-SafeMember..."
        Set-SafeMember -safename $SafeName -safeMember $MemberName -MemberType Group @permParams
        return
    }
    $body = @{ memberName=$MemberName; memberType="Group"; permissions=$PermHash } | ConvertTo-Json -Depth 5
    Write-Log "Adding Registered Group '$MemberName' via REST..."
    Invoke-RestMethod -Uri $MembersEndpoint -Method Post -Headers $headers_api -Body $body -ErrorAction Stop | Out-Null
}

function Add-VaultUser {
    param([string]$UserUpn, $PermHash)
    $permParams = Get-PermissionParams $PermHash
    if (Get-Command Add-PASSafeMember -ErrorAction SilentlyContinue) {
        Write-Log "Adding Vault User '$UserUpn' via Add-PASSafeMember (-SearchIn Vault)..."
        Add-PASSafeMember -SafeName $SafeName -MemberName $UserUpn -SearchIn Vault -memberType User @permParams
        return
    }
    if (Get-Command Set-SafeMember -ErrorAction SilentlyContinue) {
        Write-Log "Adding Vault User '$UserUpn' via Set-SafeMember (-memberSearchInLocation Vault)..."
        Set-SafeMember -safename $SafeName -safeMember $UserUpn -MemberType User -memberSearchInLocation Vault @permParams
        return
    }
    $body = @{ memberName=$UserUpn; memberType="User"; searchIn="Vault"; permissions=$PermHash } | ConvertTo-Json -Depth 5
    Write-Log "Adding Vault User '$UserUpn' via REST..."
    Invoke-RestMethod -Uri $MembersEndpoint -Method Post -Headers $headers_api -Body $body -ErrorAction Stop | Out-Null
}

# --- Add Members (with proper search locations) ---
try {
    Add-DirectoryGroup  -MemberSam $GroupName                   -PermHash $LimitedPermissions
} catch {
    Write-Log "❌ Failed to add '$GroupName' - $($_.Exception.Message)" "Red"
}

try {
    Add-RegisteredGroup -MemberName "CA_PCloud_Admins@cna.com"  -PermHash $FullPermissions
    Write-Log "✅ Added CA_PCloud_Admins@cna.com"
} catch {
    Write-Log "❌ Failed to add 'CA_PCloud_Admins@cna.com' - $($_.Exception.Message)" "Red"
}

try {
    Add-VaultUser -UserUpn "cna_pas_admin@cyberark.cloud.6679"  -PermHash $FullPermissions
    Write-Log "✅ Added cna_pas_admin@cyberark.cloud.6679"
} catch {
    Write-Log "❌ Failed to add 'cna_pas_admin@cyberark.cloud.6679' - $($_.Exception.Message)" "Red"
}

Write-Log "🔹 Safe member addition process completed."
