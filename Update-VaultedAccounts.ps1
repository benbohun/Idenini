<#
.SYNOPSIS
    Updates existing CyberArk vaulted account fields from a CSV file.

.DESCRIPTION
    PAM Team - account field update helper.

    Line of action:
      1. Read the shared .env file and the selected environment file under .\env.
      2. Build the Identity token URL, PVWA API base URL, and proxy settings from those files.
      3. Prompt for CyberArk Identity service-user credentials at run time. No password is stored in the script.
      4. Request an ISPSS OAuth token from /oauth2/platformtoken.
      5. Keep the usable bearer token only in memory, and write only a short SHA256 fingerprint to the log.
      6. Import the CSV and make sure every row has an AccountID value.
      7. Load the CyberArk regular platform inventory once, then reuse it for every row.
      8. For every CSV row, read the current account before deciding what should change.
      9. Validate platform changes before update. Target platform must exist, be active, be regular,
         and have the same CyberArk system/device type as the source platform.
     10. Validate Target Safe access and platform AllowedSafes before any safe-change operation.
     11. For same-Safe updates, send a PATCH request only for fields that actually changed.
     12. For Safe changes, create a replacement account in the target Safe only when the explicit
         safe-move switches are supplied. Source deletion remains blocked unless separately confirmed.
     13. Write a result row for every CSV row to the report CSV, including success, preview, skipped,
         failed, or partial status.

.NOTES
    Tested for Windows PowerShell 5.1 syntax.
    Do not place passwords, tokens, or retrieved secrets in CSV/log files.

.EXAMPLE
    .\Update-VaultedAccounts.ps1 -CsvFile .\samples\account-update-template.csv -Environment dev -Preview

.EXAMPLE
    .\Update-VaultedAccounts.ps1 -CsvFile .\input\prod-update.csv -Environment prod

.EXAMPLE
    .\Update-VaultedAccounts.ps1 -CsvFile .\input\safe-move.csv -Environment prod `
        -AllowSafeMove -AllowSecretRetrievalForSafeMove -SafeMoveReason "CHG123456 approved safe migration"

.EXAMPLE
    .\Update-VaultedAccounts.ps1 -CsvFile .\input\safe-move.csv -Environment prod `
        -AllowSafeMove -AllowSecretRetrievalForSafeMove -DeleteSourceAfterSafeMove -ConfirmDeleteSourceAfterMove YES
#>

#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CsvFile,

    [ValidateSet('dev','prod')]
    [string]$Environment = 'dev',

    [string]$EnvFolder = (Join-Path $PSScriptRoot 'env'),

    [switch]$Preview,

    [switch]$AllowSafeMove,

    [switch]$AllowSecretRetrievalForSafeMove,

    [string]$SafeMoveReason = 'Approved account safe migration',

    [switch]$DeleteSourceAfterSafeMove,

    [ValidateSet('NO','YES')]
    [string]$ConfirmDeleteSourceAfterMove = 'NO',

    [switch]$AllowUnknownPlatformProperties,

    [switch]$ProxyUseDefaultCredentials,

    [string]$ReportFolder = (Join-Path $PSScriptRoot 'reports'),

    [string]$LogFolder = (Join-Path $PSScriptRoot 'logs'),

    [string]$LogId = ''
)

# Stop immediately inside each try/catch block so failures are handled by the script instead of being silently ignored.
$ErrorActionPreference = 'Stop'
# Force TLS 1.2 for older Windows PowerShell hosts that may otherwise negotiate weaker protocols.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Script-scoped variables are used by helper functions after the initial configuration is loaded.
$script:LogFile = $null
$script:ReportFile = $null
$script:Config = $null
$script:PlatformCache = @{}

<#
    Returns true when a value is empty or still contains a placeholder. This keeps placeholder env values from being treated as real configuration.
#>
function Test-BlankValue {
    param([object]$Value)

    if ($null -eq $Value) { return $true }
    $text = $Value.ToString().Trim()
    if ($text.Length -eq 0) { return $true }
    if ($text -match '^(Placehold|Placeholder|YOUR-|<.*>|CHANGEME)$') { return $true }
    return $false
}

<#
    Creates the logs and reports folders when needed, then starts a new timestamped log and report file for this run.
#>
function New-RunLog {
    if (-not (Test-Path $LogFolder)) { New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null }
    if (-not (Test-Path $ReportFolder)) { New-Item -Path $ReportFolder -ItemType Directory -Force | Out-Null }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $suffix = if (Test-BlankValue $LogId) { '' } else { "_$LogId" }

    $script:LogFile = Join-Path $LogFolder "Update-VaultedAccounts_$stamp$suffix.log"
    $script:ReportFile = Join-Path $ReportFolder "Update-VaultedAccounts_Report_$stamp$suffix.csv"

    Set-Content -Path $script:LogFile -Value "$(Get-Date -Format s) source=New-RunLog [INFO] Starting run"
}

<#
    Writes a consistent log entry to the log file and mirrors it to the console with warning/error highlighting.
#>
function Write-RunLog {
    param(
        [string]$Source,
        [string]$Message,
        [ValidateSet('DEBUG','INFO','WARN','ERROR')]
        [string]$Level = 'INFO'
    )

    $line = "$(Get-Date -Format s) source=$Source [$Level] $Message"
    Add-Content -Path $script:LogFile -Value $line

    if ($Level -eq 'ERROR') {
        Write-Host $line -ForegroundColor Red
    }
    elseif ($Level -eq 'WARN') {
        Write-Host $line -ForegroundColor Yellow
    }
    else {
        Write-Host $line
    }
}

<#
    Reads simple KEY=VALUE entries from an env file. Blank lines and comments are ignored, and surrounding quotes are removed.
#>
function Read-DotEnvFile {
    param([string]$Path)

    $result = @{}
    if (-not (Test-Path $Path)) { return $result }

    $lines = Get-Content -Path $Path -ErrorAction Stop
    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ($trimmed.Length -eq 0) { continue }
        if ($trimmed.StartsWith('#')) { continue }
        if ($trimmed -notmatch '=') { continue }

        $parts = $trimmed.Split('=', 2)
        $key = $parts[0].Trim()
        $value = $parts[1].Trim()

        if ($value.Length -ge 2) {
            if (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) {
                $value = $value.Substring(1, $value.Length - 2)
            }
        }

        if (-not (Test-BlankValue $key)) {
            $result[$key] = $value
        }
    }

    return $result
}

<#
    Merges multiple env maps. Later files win, so dev.env/prod.env can override shared .env values.
#>
function Join-EnvValues {
    param([hashtable[]]$Maps)

    $merged = @{}
    foreach ($map in $Maps) {
        foreach ($key in $map.Keys) {
            $merged[$key] = $map[$key]
        }
    }
    return $merged
}

<#
    Normalizes whatever PVWA value is supplied so all later REST calls can append PasswordVault/API paths consistently.
#>
function Normalize-PvwaApiBase {
    param([string]$PvwaValue)

    $base = $PvwaValue.Trim().TrimEnd('/')
    $base = $base -replace '/PrivilegeCloud$', ''

    if ($base -match '/PasswordVault/API$') { return $base }
    if ($base -match '/PasswordVault$') { return "$base/API" }

    return "$base/PasswordVault/API"
}

<#
    Turns TENANT_ID into a full CyberArk Identity base URL. Accepts either tenant short name or full URL.
#>
function Resolve-IdentityBase {
    param([hashtable]$Settings)

    $tenant = $Settings['TENANT_ID']
    if (Test-BlankValue $tenant) {
        throw 'TENANT_ID is missing in .env. Example: TENANT_ID=aak4521 or TENANT_ID=https://aak4521.id.cyberark.cloud'
    }

    $tenant = $tenant.Trim().TrimEnd('/')
    if ($tenant -match '^https?://') { return $tenant }
    if ($tenant -match '\.id\.cyberark\.cloud$') { return "https://$tenant" }
    if ($tenant -match '\.') { return "https://$tenant" }

    return "https://$tenant.id.cyberark.cloud"
}

<#
    Builds the proxy URL from PROXY or PROXY_ADDRESS/PROXY_PORT values. Also supports the ROXY_ADDRESS typo from the original sample.
#>
function Get-ProxyFromSettings {
    param([hashtable]$Settings)

    $proxy = $Settings['PROXY']
    if (-not (Test-BlankValue $proxy)) { return $proxy.Trim() }

    # The sample had ROXY_ADDRESS once. Keep support for it so a typo does not break a run.
    $proxyAddress = $Settings['PROXY_ADDRESS']
    if (Test-BlankValue $proxyAddress) { $proxyAddress = $Settings['ROXY_ADDRESS'] }

    $proxyPort = $Settings['PROXY_PORT']
    if ((Test-BlankValue $proxyAddress) -or (Test-BlankValue $proxyPort)) { return $null }

    $proxyAddress = $proxyAddress.Trim().TrimEnd('/')
    if ($proxyAddress -notmatch '^https?://') { $proxyAddress = "http://$proxyAddress" }

    return "$proxyAddress`:$($proxyPort.Trim())"
}

<#
    Loads shared and environment-specific settings, builds runtime URLs, applies proxy settings, and stores configuration in script scope.
#>
function Import-RunConfig {
    # Resolve the shared env file and the selected dev/prod env file.
    $baseFile = Join-Path $PSScriptRoot '.env'
    $envFile1 = Join-Path $EnvFolder "$Environment.env"
    $envFile2 = Join-Path $PSScriptRoot "$Environment.env"

    $base = Read-DotEnvFile -Path $baseFile
    $envSpecific = @{}

    if (Test-Path $envFile1) {
        $envSpecific = Read-DotEnvFile -Path $envFile1
    }
    elseif (Test-Path $envFile2) {
        $envSpecific = Read-DotEnvFile -Path $envFile2
    }
    else {
        throw "Could not find environment file for '$Environment'. Expected $envFile1 or $envFile2"
    }

    # Merge shared and environment-specific settings. Values in dev.env/prod.env override .env.
    $settings = Join-EnvValues -Maps @($base, $envSpecific)

    if (Test-BlankValue $settings['PVWA']) {
        if (Test-BlankValue $settings['SUB_DOMAIN']) {
            throw 'PVWA is missing and SUB_DOMAIN is not set. Set PVWA in dev.env/prod.env or SUB_DOMAIN in .env.'
        }
        $settings['PVWA'] = "https://$($settings['SUB_DOMAIN']).privilegecloud.cyberark.cloud"
    }

    # Convert flexible config values into exact URLs used by REST calls.
    $identityBase = Resolve-IdentityBase -Settings $settings
    $apiBase = Normalize-PvwaApiBase -PvwaValue $settings['PVWA']
    $proxy = Get-ProxyFromSettings -Settings $settings

    if (-not (Test-BlankValue $proxy)) {
        $webProxy = New-Object System.Net.WebProxy($proxy)
        if ($ProxyUseDefaultCredentials) { $webProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials }
        [System.Net.WebRequest]::DefaultWebProxy = $webProxy
    }

    $script:Config = [pscustomobject]@{
        Environment = $Environment
        IdentityBase = $identityBase
        TokenUrl = "$identityBase/oauth2/platformtoken"
        ApiBase = $apiBase
        Proxy = $proxy
    }

    Write-RunLog 'Import-RunConfig' "Environment=$Environment IdentityBase=$identityBase ApiBase=$apiBase ProxyConfigured=$([bool]$proxy)" 'INFO'
}

<#
    Converts a hashtable into application/x-www-form-urlencoded text for the Identity token request.
#>
function ConvertTo-FormBody {
    param([hashtable]$Body)

    $pairs = @()
    foreach ($key in $Body.Keys) {
        $k = [System.Uri]::EscapeDataString([string]$key)
        $v = [System.Uri]::EscapeDataString([string]$Body[$key])
        $pairs += "$k=$v"
    }
    return ($pairs -join '&')
}

<#
    Creates a SHA256 hash of the bearer token for logging. This is for traceability only and cannot be used to authenticate.
#>
function Get-Sha256Fingerprint {
    param([string]$Text)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        $hash = $sha.ComputeHash($bytes)
        return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally {
        $sha.Dispose()
    }
}

<#
    Extracts useful response-body text from failed REST calls so API errors are easier to troubleshoot.
#>
function Get-WebErrorText {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)

    $msg = $ErrorRecord.Exception.Message
    $response = $ErrorRecord.Exception.Response

    if ($null -ne $response) {
        try {
            $stream = $response.GetResponseStream()
            if ($null -ne $stream) {
                $reader = New-Object System.IO.StreamReader($stream)
                $body = $reader.ReadToEnd()
                if (-not (Test-BlankValue $body)) { $msg = "$msg | Response: $body" }
            }
        }
        catch { }
    }

    return $msg
}

<#
    Prompts for the service-user credential, requests the Identity bearer token, and logs only a fingerprint of the token.
#>
function Get-IdentityBearerToken {
    Write-RunLog 'Get-IdentityBearerToken' 'Prompting for CyberArk Identity service-user credentials' 'INFO'
    # Prompt at run time so secrets are not stored in the script, CSV, env file, or Git repo.
    $credential = Get-Credential -Message 'Enter CyberArk Identity service-user credentials'

    # CyberArk Identity platform-token endpoint expects a form-urlencoded client_credentials request.
    $body = ConvertTo-FormBody -Body @{
        grant_type = 'client_credentials'
        client_id = $credential.UserName
        client_secret = $credential.GetNetworkCredential().Password
    }

    $params = @{
        Method = 'Post'
        Uri = $script:Config.TokenUrl
        Body = $body
        ContentType = 'application/x-www-form-urlencoded'
        Headers = @{ Accept = 'application/json' }
        ErrorAction = 'Stop'
    }

    if (-not (Test-BlankValue $script:Config.Proxy)) { $params['Proxy'] = $script:Config.Proxy }
    if ($ProxyUseDefaultCredentials) { $params['ProxyUseDefaultCredentials'] = $true }

    try {
        $response = Invoke-RestMethod @params
    }
    catch {
        throw "Identity token request failed. $(Get-WebErrorText -ErrorRecord $_)"
    }

    if ($null -eq $response.access_token) {
        throw 'Identity token response did not include access_token.'
    }

    # Keep the real token in memory only. Log only a fingerprint for troubleshooting correlation.
    $token = [string]$response.access_token
    $fingerprint = Get-Sha256Fingerprint -Text $token
    Write-RunLog 'Get-IdentityBearerToken' "Token acquired. SHA256 fingerprint=$($fingerprint.Substring(0,16))... ExpiresIn=$($response.expires_in)" 'INFO'

    return $token
}

<#
    Central wrapper for CyberArk REST calls. It builds the URL, adds the bearer token, serializes JSON, applies proxy settings, and normalizes errors.
#>
function Invoke-CyberArkRest {
    param(
        [ValidateSet('GET','POST','PATCH','DELETE')]
        [string]$Method,

        [string]$Path,

        [string]$Token,

        [object]$Body = $null,

        [string]$ContentType = 'application/json'
    )

    # Accept either a full URL or a relative PasswordVault/API path.
    if ($Path -match '^https?://') {
        $uri = $Path
    }
    else {
        $uri = "$($script:Config.ApiBase)/$($Path.TrimStart('/'))"
    }

    # Add the bearer token to every CyberArk API call.
    $params = @{
        Method = $Method
        Uri = $uri
        Headers = @{ Authorization = "Bearer $Token" }
        ErrorAction = 'Stop'
    }

    if ($Method -ne 'GET' -and $Method -ne 'DELETE') { $params['ContentType'] = $ContentType }

    # Convert object bodies to JSON. String bodies are already serialized or form encoded.
    if ($null -ne $Body) {
        if ($Body -is [string]) { $params['Body'] = $Body }
        else { $params['Body'] = ($Body | ConvertTo-Json -Depth 30 -Compress) }
    }

    if (-not (Test-BlankValue $script:Config.Proxy)) { $params['Proxy'] = $script:Config.Proxy }
    if ($ProxyUseDefaultCredentials) { $params['ProxyUseDefaultCredentials'] = $true }

    try {
        return Invoke-RestMethod @params
    }
    catch {
        throw "REST call failed. Method=$Method Uri=$uri $(Get-WebErrorText -ErrorRecord $_)"
    }
}

<#
    Validates the CSV file, removes empty rows, confirms an AccountID column is present, and returns all rows for processing.
#>
function Get-CsvRows {
    if (-not (Test-Path $CsvFile)) { throw "CSV file not found: $CsvFile" }
    if ((Get-Item $CsvFile).Length -eq 0) { throw "CSV file is empty: $CsvFile" }

    # Import the CSV and drop fully blank rows so accidental empty lines do not cause failures.
    $rows = Import-Csv -Path $CsvFile | Where-Object {
        ($_.PSObject.Properties.Value | Where-Object { $null -ne $_ -and $_.ToString().Trim().Length -gt 0 }).Count -gt 0
    }

    if ($null -eq $rows -or $rows.Count -eq 0) { throw "CSV contains no data rows: $CsvFile" }

    $first = @($rows)[0]
    $hasAccountId = $false
    foreach ($name in @('AccountID','Account ID','id','ID')) {
        if ($first.PSObject.Properties[$name]) { $hasAccountId = $true }
    }
    if (-not $hasAccountId) { throw 'CSV is missing required AccountID column. Accepted aliases: AccountID, Account ID, id, ID.' }

    Write-RunLog 'Get-CsvRows' "Imported $(@($rows).Count) row(s) from $CsvFile" 'INFO'
    return @($rows)
}

<#
    Reads a value from a CSV row using several accepted column aliases so the CSV remains flexible.
#>
function Get-RowValue {
    param(
        [pscustomobject]$Row,
        [string[]]$Names
    )

    foreach ($name in $Names) {
        $p = $Row.PSObject.Properties[$name]
        if ($null -ne $p -and -not (Test-BlankValue $p.Value)) {
            return $p.Value.ToString().Trim()
        }
    }
    return $null
}

<#
    Converts friendly CSV values such as yes/no, true/false, or 1/0 into real Boolean values.
#>
function ConvertTo-BooleanValue {
    param([string]$Value)

    if (Test-BlankValue $Value) { return $null }
    switch -Regex ($Value.Trim()) {
        '^(true|t|yes|y|1)$' { return $true }
        '^(false|f|no|n|0)$' { return $false }
        default { throw "Invalid boolean value '$Value'. Use true/false, yes/no, or 1/0." }
    }
}

<#
    Collects platform account properties from CSV columns named Prop:<name>, Property:<name>, or PlatformProperty:<name>.
#>
function Get-RowPlatformProperties {
    param([pscustomobject]$Row)

    $props = @{}
    foreach ($p in $Row.PSObject.Properties) {
        if ($p.Name -match '^(Prop|Property|PlatformProperty):(.+)$') {
            $propName = $Matches[2].Trim()
            if (-not (Test-BlankValue $propName) -and -not (Test-BlankValue $p.Value)) {
                $props[$propName] = $p.Value.ToString().Trim()
            }
        }
    }
    return $props
}

<#
    Loads regular CyberArk platforms once at the beginning of the run so every account row can be validated locally.
#>
function Get-PlatformInventory {
    param([string]$Token)

    Write-RunLog 'Get-PlatformInventory' 'Loading platform inventory' 'INFO'
    # Only regular platforms are loaded because this script updates vaulted account platforms, not group or dependent platform types.
    $response = Invoke-CyberArkRest -Method GET -Path 'Platforms?PlatformType=Regular' -Token $Token
    $map = @{}

    foreach ($platform in @($response.Platforms)) {
        if ($null -eq $platform.general -or (Test-BlankValue $platform.general.id)) { continue }
        $map[$platform.general.id] = $platform
    }

    if ($map.Count -eq 0) { throw 'No regular platforms were returned. Check the API user permissions.' }
    $script:PlatformCache = $map
    Write-RunLog 'Get-PlatformInventory' "Loaded $($map.Count) regular platform(s)" 'INFO'
}

<#
    Looks up a platform from the cached inventory using exact or case-insensitive matching.
#>
function Get-PlatformById {
    param([string]$PlatformId)

    if (Test-BlankValue $PlatformId) { return $null }
    if ($script:PlatformCache.ContainsKey($PlatformId)) { return $script:PlatformCache[$PlatformId] }

    foreach ($key in $script:PlatformCache.Keys) {
        if ($key -ieq $PlatformId) { return $script:PlatformCache[$key] }
    }

    return $null
}

<#
    Builds the allowed platform-property name list from the target platform required and optional property definitions.
#>
function Get-PlatformPropertyNames {
    param([object]$Platform)

    $names = @{}
    foreach ($item in @($Platform.properties.required)) {
        if (-not (Test-BlankValue $item.name)) { $names[$item.name] = $true }
    }
    foreach ($item in @($Platform.properties.optional)) {
        if (-not (Test-BlankValue $item.name)) { $names[$item.name] = $true }
    }
    return $names
}

<#
    Stops the row when the CSV attempts to update a platform property that is not defined on the selected platform.
#>
function Assert-PlatformPropertiesAllowed {
    param(
        [hashtable]$Properties,
        [object]$Platform
    )

    if ($Properties.Count -eq 0 -or $AllowUnknownPlatformProperties) { return }

    $allowed = Get-PlatformPropertyNames -Platform $Platform
    $bad = @()
    foreach ($key in $Properties.Keys) {
        if (-not $allowed.ContainsKey($key)) { $bad += $key }
    }

    if ($bad.Count -gt 0) {
        throw "CSV includes platform propert$(if($bad.Count -eq 1){'y'}else{'ies'}) not defined on platform '$($Platform.general.id)': $($bad -join ', ')"
    }
}

<#
    Checks whether a target Safe is allowed by the platform AllowedSafes pattern.
#>
function Test-SafeAllowedByPlatform {
    param(
        [object]$Platform,
        [string]$SafeName
    )

    # CyberArk platforms may restrict which Safes can hold accounts for that platform.
    $allowedSafes = $null
    if ($null -ne $Platform.credentialsManagement) { $allowedSafes = $Platform.credentialsManagement.allowedSafes }

    if (Test-BlankValue $allowedSafes) { return $true }
    if ($allowedSafes.Trim() -eq '.*') { return $true }

    foreach ($raw in ($allowedSafes -split ',')) {
        $pattern = $raw.Trim()
        if (Test-BlankValue $pattern) { continue }

        try {
            if ($SafeName -match $pattern) { return $true }
        }
        catch {
            if ($SafeName -ieq $pattern) { return $true }
        }
    }

    return $false
}

<#
    Checks that the target Safe exists and that the API user can access it before creating an account there.
#>
function Test-SafeExists {
    param(
        [string]$SafeName,
        [string]$Token
    )

    $safeUrlId = [System.Uri]::EscapeDataString($SafeName)
    try {
        Invoke-CyberArkRest -Method GET -Path "Safes/$safeUrlId" -Token $Token | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

<#
    Performs the core platform validation: source/target platform exist, target is active/regular, device type matches, and target Safe is allowed.
#>
function Assert-PlatformChangeAllowed {
    param(
        [object]$CurrentPlatform,
        [object]$TargetPlatform,
        [string]$TargetSafe
    )

    if ($null -eq $CurrentPlatform) { throw 'Current platform could not be found in platform inventory.' }
    if ($null -eq $TargetPlatform) { throw 'Target platform could not be found in platform inventory.' }

    # Do not move or patch an account into an inactive platform.
    if ($TargetPlatform.general.active -ne $true) {
        throw "Target platform '$($TargetPlatform.general.id)' is not active."
    }

    if ($TargetPlatform.general.platformType -and $TargetPlatform.general.platformType -ine 'regular') {
        throw "Target platform '$($TargetPlatform.general.id)' is not a regular account platform."
    }

    # Platform changes are allowed only when CyberArk reports the same system/device type.
    $currentType = [string]$CurrentPlatform.general.systemType
    $targetType = [string]$TargetPlatform.general.systemType
    if ($currentType -ne $targetType) {
        throw "Platform device/system type mismatch. Current '$($CurrentPlatform.general.id)'=$currentType, Target '$($TargetPlatform.general.id)'=$targetType."
    }

    if (-not (Test-SafeAllowedByPlatform -Platform $TargetPlatform -SafeName $TargetSafe)) {
        throw "Target Safe '$TargetSafe' is not allowed by platform '$($TargetPlatform.general.id)' AllowedSafes='$($TargetPlatform.credentialsManagement.allowedSafes)'."
    }
}

<#
    Reads the current CyberArk account record before deciding what the CSV row should update.
#>
function Get-AccountById {
    param(
        [string]$AccountId,
        [string]$Token
    )

    $id = [System.Uri]::EscapeDataString($AccountId)
    return Invoke-CyberArkRest -Method GET -Path "Accounts/$id/" -Token $Token
}

<#
    Retrieves the current account secret when a Safe-change clone is explicitly approved.
#>
function Get-AccountSecretValue {
    param(
        [string]$AccountId,
        [string]$Token
    )

    $id = [System.Uri]::EscapeDataString($AccountId)
    $body = @{ reason = $SafeMoveReason }
    $response = Invoke-CyberArkRest -Method POST -Path "Accounts/$id/Password/Retrieve/" -Token $Token -Body $body

    if ($response -is [string]) { return $response }
    if ($null -ne $response.Content) { return [string]$response.Content }
    if ($null -ne $response.Password) { return [string]$response.Password }
    if ($null -ne $response.Value) { return [string]$response.Value }

    return [string]$response
}

<#
    Combines current platform account properties with CSV-supplied properties. CSV values override current values.
#>
function Merge-PlatformProperties {
    param(
        [object]$CurrentProperties,
        [hashtable]$CsvProperties
    )

    $merged = @{}

    if ($null -ne $CurrentProperties) {
        foreach ($p in $CurrentProperties.PSObject.Properties) {
            if (-not (Test-BlankValue $p.Name) -and $null -ne $p.Value) { $merged[$p.Name] = $p.Value }
        }
    }

    foreach ($key in $CsvProperties.Keys) { $merged[$key] = $CsvProperties[$key] }
    return $merged
}

<#
    Builds the JSON Patch operation array for same-Safe updates, adding only fields that actually need to change.
#>
function New-PatchBody {
    param(
        [object]$CurrentAccount,
        [string]$TargetName,
        [string]$TargetAddress,
        [string]$TargetUserName,
        [string]$TargetPlatformId,
        [Nullable[bool]]$AutomaticManagement,
        [string]$ManualManagementReason,
        [hashtable]$PlatformProperties
    )

    # Build a JSON Patch array. Each entry represents one field update sent to PATCH /Accounts/{id}/.
    $ops = @()

    if (-not (Test-BlankValue $TargetName) -and $TargetName -ne $CurrentAccount.name) {
        $ops += @{ op = 'replace'; path = '/name'; value = $TargetName }
    }

    if (-not (Test-BlankValue $TargetAddress) -and $TargetAddress -ne $CurrentAccount.address) {
        $ops += @{ op = 'replace'; path = '/address'; value = $TargetAddress }
    }

    if (-not (Test-BlankValue $TargetUserName) -and $TargetUserName -ne $CurrentAccount.userName) {
        $ops += @{ op = 'replace'; path = '/userName'; value = $TargetUserName }
    }

    if (-not (Test-BlankValue $TargetPlatformId) -and $TargetPlatformId -ne $CurrentAccount.platformId) {
        $ops += @{ op = 'replace'; path = '/platformId'; value = $TargetPlatformId }
    }

    # Platform properties are sent as one object. Existing properties not included here remain unchanged by CyberArk.
    if ($PlatformProperties.Count -gt 0) {
        $ops += @{ op = 'add'; path = '/platformAccountProperties'; value = $PlatformProperties }
    }

    if ($null -ne $AutomaticManagement) {
        $ops += @{ op = 'replace'; path = '/secretManagement/automaticManagementEnabled'; value = [bool]$AutomaticManagement }
    }

    if (-not (Test-BlankValue $ManualManagementReason)) {
        $ops += @{ op = 'replace'; path = '/secretManagement/manualManagementReason'; value = $ManualManagementReason }
    }
    elseif ($null -ne $AutomaticManagement -and [bool]$AutomaticManagement -eq $true) {
        $ops += @{ op = 'replace'; path = '/secretManagement/manualManagementReason'; value = '' }
    }

    return $ops
}

<#
    Builds the POST body used to create the replacement account in the target Safe during safe-change handling.
#>
function New-AccountCreateBody {
    param(
        [object]$CurrentAccount,
        [string]$TargetSafe,
        [string]$TargetName,
        [string]$TargetAddress,
        [string]$TargetUserName,
        [string]$TargetPlatformId,
        [string]$Secret,
        [Nullable[bool]]$AutomaticManagement,
        [string]$ManualManagementReason,
        [hashtable]$PlatformProperties
    )

    # For target Safe creation, keep current values unless the CSV supplied replacement values.
    $name = if (Test-BlankValue $TargetName) { $CurrentAccount.name } else { $TargetName }
    $address = if (Test-BlankValue $TargetAddress) { $CurrentAccount.address } else { $TargetAddress }
    $userName = if (Test-BlankValue $TargetUserName) { $CurrentAccount.userName } else { $TargetUserName }
    $platformId = if (Test-BlankValue $TargetPlatformId) { $CurrentAccount.platformId } else { $TargetPlatformId }
    $secretType = if (Test-BlankValue $CurrentAccount.secretType) { 'Password' } else { $CurrentAccount.secretType }
    $mergedProps = Merge-PlatformProperties -CurrentProperties $CurrentAccount.platformAccountProperties -CsvProperties $PlatformProperties

    $autoMgmt = $true
    if ($null -ne $CurrentAccount.secretManagement -and $null -ne $CurrentAccount.secretManagement.automaticManagementEnabled) {
        $autoMgmt = [bool]$CurrentAccount.secretManagement.automaticManagementEnabled
    }
    if ($null -ne $AutomaticManagement) { $autoMgmt = [bool]$AutomaticManagement }

    $manualReason = $null
    if ($null -ne $CurrentAccount.secretManagement) { $manualReason = $CurrentAccount.secretManagement.manualManagementReason }
    if (-not (Test-BlankValue $ManualManagementReason)) { $manualReason = $ManualManagementReason }
    if ($autoMgmt -eq $true) { $manualReason = '' }

    # New-account create body. The secret is required because the public REST API creates a new account rather than performing the UI move operation.
    $body = [ordered]@{
        name = $name
        address = $address
        userName = $userName
        platformId = $platformId
        safeName = $TargetSafe
        secretType = $secretType
        secret = $Secret
        platformAccountProperties = $mergedProps
        secretManagement = @{
            automaticManagementEnabled = $autoMgmt
            manualManagementReason = $manualReason
        }
    }

    if ($null -ne $CurrentAccount.remoteMachinesAccess) {
        $body['remoteMachinesAccess'] = $CurrentAccount.remoteMachinesAccess
    }

    return $body
}

<#
    Appends the outcome for a processed CSV row to the report CSV.
#>
function Add-ReportRow {
    param([pscustomobject]$Row)

    if (-not (Test-Path $script:ReportFile)) {
        $Row | Export-Csv -Path $script:ReportFile -NoTypeInformation
    }
    else {
        $Row | Export-Csv -Path $script:ReportFile -NoTypeInformation -Append
    }
}

<#
    Sends the PATCH request for normal updates when there is at least one operation to send.
#>
function Invoke-AccountPatch {
    param(
        [string]$AccountId,
        [array]$PatchOps,
        [string]$Token
    )

    if ($PatchOps.Count -eq 0) { return $null }
    $id = [System.Uri]::EscapeDataString($AccountId)
    return Invoke-CyberArkRest -Method PATCH -Path "Accounts/$id/" -Token $Token -Body $PatchOps
}

<#
    Handles the create side of a Safe change. It retrieves the secret, builds the new account body, and creates the target account.
#>
function Invoke-SafeMoveCreate {
    param(
        [object]$CurrentAccount,
        [string]$TargetSafe,
        [string]$TargetName,
        [string]$TargetAddress,
        [string]$TargetUserName,
        [string]$TargetPlatformId,
        [Nullable[bool]]$AutomaticManagement,
        [string]$ManualManagementReason,
        [hashtable]$PlatformProperties,
        [string]$Token
    )

    # Safe change is intentionally gated because this path retrieves the current secret to create the target account.
    if (-not $AllowSecretRetrievalForSafeMove) {
        throw 'Safe change requires -AllowSecretRetrievalForSafeMove because REST-based clone/create needs the current secret value. Use UI move if secret retrieval is not approved.'
    }

    # Retrieve the existing secret only after the user supplied the explicit safe-move approval switch.
    $secret = Get-AccountSecretValue -AccountId $CurrentAccount.id -Token $Token
    if (Test-BlankValue $secret) { throw 'Retrieved secret was empty. New account was not created.' }

    $body = New-AccountCreateBody -CurrentAccount $CurrentAccount `
        -TargetSafe $TargetSafe `
        -TargetName $TargetName `
        -TargetAddress $TargetAddress `
        -TargetUserName $TargetUserName `
        -TargetPlatformId $TargetPlatformId `
        -Secret $secret `
        -AutomaticManagement $AutomaticManagement `
        -ManualManagementReason $ManualManagementReason `
        -PlatformProperties $PlatformProperties

    return Invoke-CyberArkRest -Method POST -Path 'Accounts?AllowAccountDuplications=false' -Token $Token -Body $body
}

<#
    Optionally deletes the source account after target creation, but only when both delete-confirmation switches are supplied.
#>
function Remove-SourceAccountAfterMove {
    param(
        [string]$AccountId,
        [string]$Token
    )

    # Keep the source account by default so safe-change testing does not remove the original record.
    if (-not $DeleteSourceAfterSafeMove) { return 'Source account kept. DeleteSourceAfterSafeMove was not supplied.' }
    if ($ConfirmDeleteSourceAfterMove -ne 'YES') { return 'Source account kept. ConfirmDeleteSourceAfterMove was not YES.' }

    $id = [System.Uri]::EscapeDataString($AccountId)
    Invoke-CyberArkRest -Method DELETE -Path "Accounts/$id/" -Token $Token | Out-Null
    return 'Source account deleted after target account creation.'
}

<#
    Processes one CSV row end to end: read account, validate target platform/Safe, choose patch versus safe-change create, and return result.
#>
function Invoke-RowUpdate {
    param(
        [pscustomobject]$CsvRow,
        [int]$RowNumber,
        [string]$Token
    )

    # Read all supported CSV aliases for the fields this script can update.
    $accountId = Get-RowValue -Row $CsvRow -Names @('AccountID','Account ID','id','ID')
    $targetSafe = Get-RowValue -Row $CsvRow -Names @('TargetSafeName','Target Safe','Migrated Safe','New Safe','SafeName')
    $targetPlatformId = Get-RowValue -Row $CsvRow -Names @('TargetPlatformID','Target Platform ID','Migrated Platform ID','New Platform ID','PlatformID')
    $targetName = Get-RowValue -Row $CsvRow -Names @('TargetName','Target Name','Migrated Name','New Name','Name')
    $targetAddress = Get-RowValue -Row $CsvRow -Names @('TargetAddress','Target Address','Migrated Target system address','New Address','Address')
    $targetUserName = Get-RowValue -Row $CsvRow -Names @('TargetUserName','Target UserName','Target Username','Migrated Target system user name','New UserName','UserName')
    $enableMgmtRaw = Get-RowValue -Row $CsvRow -Names @('AutomaticManagementEnabled','Automatic Management Enabled')
    $disableMgmtRaw = Get-RowValue -Row $CsvRow -Names @('DisableAutomaticManagement','Disable Automatic Management')
    $manualReason = Get-RowValue -Row $CsvRow -Names @('ManualManagementReason','Manual Management Reason')
    $csvProps = Get-RowPlatformProperties -Row $CsvRow

    # Prepare a standard report row before doing any update. This guarantees every CSV row gets a result.
    $result = [ordered]@{
        Row = $RowNumber
        AccountID = $accountId
        SourceSafe = ''
        TargetSafe = ''
        SourcePlatform = ''
        TargetPlatform = ''
        Action = ''
        Result = ''
        NewAccountID = ''
        Message = ''
    }

    try {
        if (Test-BlankValue $accountId) { throw 'AccountID is blank.' }

        # Always read the current account first so validation compares CSV targets to the real vaulted state.
        $current = Get-AccountById -AccountId $accountId -Token $Token
        $result.SourceSafe = $current.safeName
        $result.SourcePlatform = $current.platformId

        # When Target Safe or Target Platform is blank, use the current account value to avoid accidental changes.
        if (Test-BlankValue $targetSafe) { $targetSafe = $current.safeName }
        if (Test-BlankValue $targetPlatformId) { $targetPlatformId = $current.platformId }

        $result.TargetSafe = $targetSafe
        $result.TargetPlatform = $targetPlatformId

        $currentPlatform = Get-PlatformById -PlatformId $current.platformId
        $targetPlatform = Get-PlatformById -PlatformId $targetPlatformId

        # Validate platform/device type and AllowedSafes before building any update request.
        Assert-PlatformChangeAllowed -CurrentPlatform $currentPlatform -TargetPlatform $targetPlatform -TargetSafe $targetSafe
        Assert-PlatformPropertiesAllowed -Properties $csvProps -Platform $targetPlatform

        # AutomaticManagementEnabled and DisableAutomaticManagement are optional. Null means leave current CPM management setting unchanged.
        $automaticManagement = $null
        if (-not (Test-BlankValue $disableMgmtRaw)) {
            $automaticManagement = -not (ConvertTo-BooleanValue -Value $disableMgmtRaw)
        }
        elseif (-not (Test-BlankValue $enableMgmtRaw)) {
            $automaticManagement = ConvertTo-BooleanValue -Value $enableMgmtRaw
        }

        # A different Target Safe changes the path from PATCH to create-target-account workflow.
        $isSafeChange = ($targetSafe -ne $current.safeName)
        if ($isSafeChange) {
            $result.Action = 'SafeMoveCreate'

            if (-not $AllowSafeMove) {
                throw "Target Safe '$targetSafe' differs from current Safe '$($current.safeName)', but -AllowSafeMove was not supplied."
            }

            if (-not (Test-SafeExists -SafeName $targetSafe -Token $Token)) {
                throw "Target Safe '$targetSafe' was not found or API user cannot access it."
            }

            # Preview validates the row and reports what would happen without creating, patching, or deleting anything.
            if ($Preview) {
                $result.Result = 'PREVIEW'
                $result.Message = 'Safe change validated. No account created because -Preview was supplied.'
                return [pscustomobject]$result
            }

            $newAccount = Invoke-SafeMoveCreate -CurrentAccount $current `
                -TargetSafe $targetSafe `
                -TargetName $targetName `
                -TargetAddress $targetAddress `
                -TargetUserName $targetUserName `
                -TargetPlatformId $targetPlatformId `
                -AutomaticManagement $automaticManagement `
                -ManualManagementReason $manualReason `
                -PlatformProperties $csvProps `
                -Token $Token

            $result.NewAccountID = $newAccount.id
            try {
                $deleteNote = Remove-SourceAccountAfterMove -AccountId $current.id -Token $Token
                $result.Result = 'SUCCESS'
                $result.Message = "Created target Safe account. $deleteNote"
            }
            catch {
                $result.Result = 'PARTIAL'
                $result.Message = "Created target Safe account, but source cleanup failed. NewAccountID=$($newAccount.id). $($_.Exception.Message)"
            }
            return [pscustomobject]$result
        }

        # Same-Safe changes use PATCH and include only values that changed.
        $patchOps = New-PatchBody -CurrentAccount $current `
            -TargetName $targetName `
            -TargetAddress $targetAddress `
            -TargetUserName $targetUserName `
            -TargetPlatformId $targetPlatformId `
            -AutomaticManagement $automaticManagement `
            -ManualManagementReason $manualReason `
            -PlatformProperties $csvProps

        if ($patchOps.Count -eq 0) {
            $result.Action = 'NoChange'
            $result.Result = 'SKIPPED'
            $result.Message = 'No changed values were supplied in the CSV row.'
            return [pscustomobject]$result
        }

        $result.Action = 'PatchAccount'
        if ($Preview) {
            $result.Result = 'PREVIEW'
            $result.Message = "Patch validated. Operation count=$($patchOps.Count). No update sent because -Preview was supplied."
            return [pscustomobject]$result
        }

        Invoke-AccountPatch -AccountId $accountId -PatchOps $patchOps -Token $Token | Out-Null
        $result.Result = 'SUCCESS'
        $result.Message = "Patched account. Operation count=$($patchOps.Count)."
        return [pscustomobject]$result
    }
    catch {
        $result.Result = 'FAILED'
        $result.Message = $_.Exception.Message
        return [pscustomobject]$result
    }
}

<#
    Main execution block. Initializes logging/config, authenticates, loads platforms, processes each CSV row, and writes final log/report paths.
#>
function Start-AccountUpdateRun {
    # Step 1: create log/report files, then load runtime configuration from .env and env/<environment>.env.
    New-RunLog
    Import-RunConfig

    if ($DeleteSourceAfterSafeMove -and $ConfirmDeleteSourceAfterMove -ne 'YES') {
        Write-RunLog 'Start-AccountUpdateRun' 'DeleteSourceAfterSafeMove supplied without ConfirmDeleteSourceAfterMove YES. Source accounts will be kept.' 'WARN'
    }

    if ($Preview) { Write-RunLog 'Start-AccountUpdateRun' 'Preview mode enabled. No account update/create/delete calls will be sent.' 'WARN' }

    # Step 2: import CSV, authenticate to Identity, then cache platform inventory for validation.
    $rows = Get-CsvRows
    $token = Get-IdentityBearerToken
    Get-PlatformInventory -Token $token

    $rowNumber = 1
    # Step 3: process each CSV row independently so one failed account does not stop the full batch.
    foreach ($row in $rows) {
        Write-RunLog 'Start-AccountUpdateRun' "Processing CSV row $rowNumber" 'INFO'
        $outcome = Invoke-RowUpdate -CsvRow $row -RowNumber $rowNumber -Token $token
        # Step 4: write the row result immediately so progress is preserved even if a later row fails.
        Add-ReportRow -Row $outcome

        if ($outcome.Result -eq 'FAILED') {
            Write-RunLog 'Start-AccountUpdateRun' "Row $rowNumber failed. AccountID=$($outcome.AccountID) Message=$($outcome.Message)" 'ERROR'
        }
        else {
            Write-RunLog 'Start-AccountUpdateRun' "Row $rowNumber $($outcome.Result). AccountID=$($outcome.AccountID) Action=$($outcome.Action)" 'INFO'
        }

        $rowNumber++
    }

    Write-RunLog 'Start-AccountUpdateRun' "Run completed. Report=$script:ReportFile Log=$script:LogFile" 'INFO'
}

# Start the controlled update workflow.
Start-AccountUpdateRun
