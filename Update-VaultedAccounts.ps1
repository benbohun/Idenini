<#
.SYNOPSIS
    Updates existing CyberArk vaulted account fields from a CSV file.

.DESCRIPTION
    PAM Team - account field update helper.

    Line of action:
      1. Read .env and env-specific file.
      2. Prompt for CyberArk Identity service-user credentials.
      3. Request an ISPSS OAuth token from /oauth2/platformtoken.
      4. Log only a SHA256 fingerprint of the token. The real token stays in memory.
      5. Read the CSV and validate account/platform/safe changes before touching the account.
      6. PATCH normal field changes in place.
      7. If a target Safe is supplied, create a replacement account in the target Safe.
         Source deletion is optional and must be explicitly confirmed.

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

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$script:LogFile = $null
$script:ReportFile = $null
$script:Config = $null
$script:PlatformCache = @{}

function Test-BlankValue {
    param([object]$Value)

    if ($null -eq $Value) { return $true }
    $text = $Value.ToString().Trim()
    if ($text.Length -eq 0) { return $true }
    if ($text -match '^(Placehold|Placeholder|YOUR-|<.*>|CHANGEME)$') { return $true }
    return $false
}

function New-RunLog {
    if (-not (Test-Path $LogFolder)) { New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null }
    if (-not (Test-Path $ReportFolder)) { New-Item -Path $ReportFolder -ItemType Directory -Force | Out-Null }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $suffix = if (Test-BlankValue $LogId) { '' } else { "_$LogId" }

    $script:LogFile = Join-Path $LogFolder "Update-VaultedAccounts_$stamp$suffix.log"
    $script:ReportFile = Join-Path $ReportFolder "Update-VaultedAccounts_Report_$stamp$suffix.csv"

    Set-Content -Path $script:LogFile -Value "$(Get-Date -Format s) source=New-RunLog [INFO] Starting run"
}

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

function Normalize-PvwaApiBase {
    param([string]$PvwaValue)

    $base = $PvwaValue.Trim().TrimEnd('/')
    $base = $base -replace '/PrivilegeCloud$', ''

    if ($base -match '/PasswordVault/API$') { return $base }
    if ($base -match '/PasswordVault$') { return "$base/API" }

    return "$base/PasswordVault/API"
}

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

function Import-RunConfig {
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

    $settings = Join-EnvValues -Maps @($base, $envSpecific)

    if (Test-BlankValue $settings['PVWA']) {
        if (Test-BlankValue $settings['SUB_DOMAIN']) {
            throw 'PVWA is missing and SUB_DOMAIN is not set. Set PVWA in dev.env/prod.env or SUB_DOMAIN in .env.'
        }
        $settings['PVWA'] = "https://$($settings['SUB_DOMAIN']).privilegecloud.cyberark.cloud"
    }

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

function Get-IdentityBearerToken {
    Write-RunLog 'Get-IdentityBearerToken' 'Prompting for CyberArk Identity service-user credentials' 'INFO'
    $credential = Get-Credential -Message 'Enter CyberArk Identity service-user credentials'

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

    $token = [string]$response.access_token
    $fingerprint = Get-Sha256Fingerprint -Text $token
    Write-RunLog 'Get-IdentityBearerToken' "Token acquired. SHA256 fingerprint=$($fingerprint.Substring(0,16))... ExpiresIn=$($response.expires_in)" 'INFO'

    return $token
}

function Invoke-CyberArkRest {
    param(
        [ValidateSet('GET','POST','PATCH','DELETE')]
        [string]$Method,

        [string]$Path,

        [string]$Token,

        [object]$Body = $null,

        [string]$ContentType = 'application/json'
    )

    if ($Path -match '^https?://') {
        $uri = $Path
    }
    else {
        $uri = "$($script:Config.ApiBase)/$($Path.TrimStart('/'))"
    }

    $params = @{
        Method = $Method
        Uri = $uri
        Headers = @{ Authorization = "Bearer $Token" }
        ErrorAction = 'Stop'
    }

    if ($Method -ne 'GET' -and $Method -ne 'DELETE') { $params['ContentType'] = $ContentType }

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

function Get-CsvRows {
    if (-not (Test-Path $CsvFile)) { throw "CSV file not found: $CsvFile" }
    if ((Get-Item $CsvFile).Length -eq 0) { throw "CSV file is empty: $CsvFile" }

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

function ConvertTo-BooleanValue {
    param([string]$Value)

    if (Test-BlankValue $Value) { return $null }
    switch -Regex ($Value.Trim()) {
        '^(true|t|yes|y|1)$' { return $true }
        '^(false|f|no|n|0)$' { return $false }
        default { throw "Invalid boolean value '$Value'. Use true/false, yes/no, or 1/0." }
    }
}

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

function Get-PlatformInventory {
    param([string]$Token)

    Write-RunLog 'Get-PlatformInventory' 'Loading platform inventory' 'INFO'
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

function Get-PlatformById {
    param([string]$PlatformId)

    if (Test-BlankValue $PlatformId) { return $null }
    if ($script:PlatformCache.ContainsKey($PlatformId)) { return $script:PlatformCache[$PlatformId] }

    foreach ($key in $script:PlatformCache.Keys) {
        if ($key -ieq $PlatformId) { return $script:PlatformCache[$key] }
    }

    return $null
}

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

function Test-SafeAllowedByPlatform {
    param(
        [object]$Platform,
        [string]$SafeName
    )

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

function Assert-PlatformChangeAllowed {
    param(
        [object]$CurrentPlatform,
        [object]$TargetPlatform,
        [string]$TargetSafe
    )

    if ($null -eq $CurrentPlatform) { throw 'Current platform could not be found in platform inventory.' }
    if ($null -eq $TargetPlatform) { throw 'Target platform could not be found in platform inventory.' }

    if ($TargetPlatform.general.active -ne $true) {
        throw "Target platform '$($TargetPlatform.general.id)' is not active."
    }

    if ($TargetPlatform.general.platformType -and $TargetPlatform.general.platformType -ine 'regular') {
        throw "Target platform '$($TargetPlatform.general.id)' is not a regular account platform."
    }

    $currentType = [string]$CurrentPlatform.general.systemType
    $targetType = [string]$TargetPlatform.general.systemType
    if ($currentType -ne $targetType) {
        throw "Platform device/system type mismatch. Current '$($CurrentPlatform.general.id)'=$currentType, Target '$($TargetPlatform.general.id)'=$targetType."
    }

    if (-not (Test-SafeAllowedByPlatform -Platform $TargetPlatform -SafeName $TargetSafe)) {
        throw "Target Safe '$TargetSafe' is not allowed by platform '$($TargetPlatform.general.id)' AllowedSafes='$($TargetPlatform.credentialsManagement.allowedSafes)'."
    }
}

function Get-AccountById {
    param(
        [string]$AccountId,
        [string]$Token
    )

    $id = [System.Uri]::EscapeDataString($AccountId)
    return Invoke-CyberArkRest -Method GET -Path "Accounts/$id/" -Token $Token
}

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

function Add-ReportRow {
    param([pscustomobject]$Row)

    if (-not (Test-Path $script:ReportFile)) {
        $Row | Export-Csv -Path $script:ReportFile -NoTypeInformation
    }
    else {
        $Row | Export-Csv -Path $script:ReportFile -NoTypeInformation -Append
    }
}

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

    if (-not $AllowSecretRetrievalForSafeMove) {
        throw 'Safe change requires -AllowSecretRetrievalForSafeMove because REST-based clone/create needs the current secret value. Use UI move if secret retrieval is not approved.'
    }

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

function Remove-SourceAccountAfterMove {
    param(
        [string]$AccountId,
        [string]$Token
    )

    if (-not $DeleteSourceAfterSafeMove) { return 'Source account kept. DeleteSourceAfterSafeMove was not supplied.' }
    if ($ConfirmDeleteSourceAfterMove -ne 'YES') { return 'Source account kept. ConfirmDeleteSourceAfterMove was not YES.' }

    $id = [System.Uri]::EscapeDataString($AccountId)
    Invoke-CyberArkRest -Method DELETE -Path "Accounts/$id/" -Token $Token | Out-Null
    return 'Source account deleted after target account creation.'
}

function Invoke-RowUpdate {
    param(
        [pscustomobject]$CsvRow,
        [int]$RowNumber,
        [string]$Token
    )

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

        $current = Get-AccountById -AccountId $accountId -Token $Token
        $result.SourceSafe = $current.safeName
        $result.SourcePlatform = $current.platformId

        if (Test-BlankValue $targetSafe) { $targetSafe = $current.safeName }
        if (Test-BlankValue $targetPlatformId) { $targetPlatformId = $current.platformId }

        $result.TargetSafe = $targetSafe
        $result.TargetPlatform = $targetPlatformId

        $currentPlatform = Get-PlatformById -PlatformId $current.platformId
        $targetPlatform = Get-PlatformById -PlatformId $targetPlatformId

        Assert-PlatformChangeAllowed -CurrentPlatform $currentPlatform -TargetPlatform $targetPlatform -TargetSafe $targetSafe
        Assert-PlatformPropertiesAllowed -Properties $csvProps -Platform $targetPlatform

        $automaticManagement = $null
        if (-not (Test-BlankValue $disableMgmtRaw)) {
            $automaticManagement = -not (ConvertTo-BooleanValue -Value $disableMgmtRaw)
        }
        elseif (-not (Test-BlankValue $enableMgmtRaw)) {
            $automaticManagement = ConvertTo-BooleanValue -Value $enableMgmtRaw
        }

        $isSafeChange = ($targetSafe -ne $current.safeName)
        if ($isSafeChange) {
            $result.Action = 'SafeMoveCreate'

            if (-not $AllowSafeMove) {
                throw "Target Safe '$targetSafe' differs from current Safe '$($current.safeName)', but -AllowSafeMove was not supplied."
            }

            if (-not (Test-SafeExists -SafeName $targetSafe -Token $Token)) {
                throw "Target Safe '$targetSafe' was not found or API user cannot access it."
            }

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

function Start-AccountUpdateRun {
    New-RunLog
    Import-RunConfig

    if ($DeleteSourceAfterSafeMove -and $ConfirmDeleteSourceAfterMove -ne 'YES') {
        Write-RunLog 'Start-AccountUpdateRun' 'DeleteSourceAfterSafeMove supplied without ConfirmDeleteSourceAfterMove YES. Source accounts will be kept.' 'WARN'
    }

    if ($Preview) { Write-RunLog 'Start-AccountUpdateRun' 'Preview mode enabled. No account update/create/delete calls will be sent.' 'WARN' }

    $rows = Get-CsvRows
    $token = Get-IdentityBearerToken
    Get-PlatformInventory -Token $token

    $rowNumber = 1
    foreach ($row in $rows) {
        Write-RunLog 'Start-AccountUpdateRun' "Processing CSV row $rowNumber" 'INFO'
        $outcome = Invoke-RowUpdate -CsvRow $row -RowNumber $rowNumber -Token $token
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

Start-AccountUpdateRun
