<#
.SYNOPSIS
  Bulk unlock / release CyberArk vaulted accounts by AccountID.

.DESCRIPTION
  This script releases CyberArk account object locks using:
    POST /PasswordVault/API/Accounts/{AccountID}/Unlock/

  This is NOT an Active Directory unlock script.
  It does NOT unlock AD users.
  It does NOT retrieve passwords.
  It only releases the CyberArk account lock/check-out state.

.CSV FORMAT
  AccountID
  2883_3
  2889_9

.EXAMPLES
  Dry run:
    .\Bulk-CyberArk-Unlock-Accounts.ps1 `
      -CsvFile .\accountids.csv `
      -ApiBase "https://mtbank.privilegecloud.cyberark.cloud/PasswordVault/API" `
      -DebugHttp

  Live run:
    .\Bulk-CyberArk-Unlock-Accounts.ps1 `
      -CsvFile .\accountids.csv `
      -ApiBase "https://mtbank.privilegecloud.cyberark.cloud/PasswordVault/API" `
      -LiveRun `
      -DebugHttp

  With proxy:
    .\Bulk-CyberArk-Unlock-Accounts.ps1 `
      -CsvFile .\accountids.csv `
      -ApiBase "https://mtbank.privilegecloud.cyberark.cloud/PasswordVault/API" `
      -Proxy "http://proxy.company.com:8080" `
      -ProxyUseDefaultCredentials `
      -LiveRun `
      -DebugHttp
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$CsvFile,

    [Parameter(Mandatory = $false)]
    [string]$ApiBase,

    [Parameter(Mandatory = $false)]
    [ValidateSet("CyberArk", "LDAP", "RADIUS", "Windows")]
    [string]$AuthType = "CyberArk",

    [Parameter(Mandatory = $false)]
    [string]$ReportFolder = ".\reports",

    [Parameter(Mandatory = $false)]
    [switch]$LiveRun,

    [Parameter(Mandatory = $false)]
    [switch]$SkipAccountDetails,

    [Parameter(Mandatory = $false)]
    [switch]$SkipCertificateCheck,

    [Parameter(Mandatory = $false)]
    [int]$TimeoutSec = 45,

    [Parameter(Mandatory = $false)]
    [string]$Proxy,

    [Parameter(Mandatory = $false)]
    [switch]$ProxyUseDefaultCredentials,

    [Parameter(Mandatory = $false)]
    [switch]$DebugHttp
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "$timestamp [$Level] $Message"
}

function Ensure-Folder {
    param([string]$Path)

    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Enable-Tls12 {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        [System.Net.ServicePointManager]::Expect100Continue = $false
    }
    catch {
        Write-Log "Unable to force TLS 1.2. Error=$($_.Exception.Message)" "WARN"
    }
}

function Enable-SkipCertificateCheck {
    if ($SkipCertificateCheck) {
        Write-Log "SkipCertificateCheck is enabled. Use only for lab/testing." "WARN"

        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
            param($sender, $certificate, $chain, $sslPolicyErrors)
            return $true
        }
    }
}

function Normalize-ApiBase {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    $base = $Value.Trim().TrimEnd("/")

    if ($base -match "/PasswordVault/API$") {
        return $base
    }

    if ($base -match "/PasswordVault$") {
        return "$base/API"
    }

    return "$base/PasswordVault/API"
}

function ConvertTo-PlainText {
    param([Security.SecureString]$SecureString)

    if ($null -eq $SecureString) {
        return $null
    }

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)

    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Get-HttpErrorBody {
    param($ErrorRecord)

    try {
        $response = $ErrorRecord.Exception.Response

        if ($null -eq $response) {
            return $ErrorRecord.Exception.Message
        }

        $stream = $response.GetResponseStream()

        if ($null -eq $stream) {
            return $ErrorRecord.Exception.Message
        }

        $reader = New-Object System.IO.StreamReader($stream)
        $body = $reader.ReadToEnd()

        if ([string]::IsNullOrWhiteSpace($body)) {
            return $ErrorRecord.Exception.Message
        }

        return $body
    }
    catch {
        return $ErrorRecord.Exception.Message
    }
}

function Get-RestParams {
    param(
        [ValidateSet("GET", "POST", "DELETE")]
        [string]$Method,

        [string]$Uri,

        [hashtable]$Headers,

        [object]$Body = $null
    )

    $params = @{
        Method      = $Method
        Uri         = $Uri
        Headers     = $Headers
        TimeoutSec  = $TimeoutSec
        ErrorAction = "Stop"
    }

    if ($Method -ne "GET") {
        $params["ContentType"] = "application/json"
    }

    if ($null -ne $Body) {
        $params["Body"] = ($Body | ConvertTo-Json -Depth 20)
    }

    if (-not [string]::IsNullOrWhiteSpace($Proxy)) {
        $params["Proxy"] = $Proxy

        if ($ProxyUseDefaultCredentials) {
            $params["ProxyUseDefaultCredentials"] = $true
        }
    }

    return $params
}

function Invoke-CyberArkRest {
    param(
        [ValidateSet("GET", "POST", "DELETE")]
        [string]$Method,

        [string]$Uri,

        [hashtable]$Headers,

        [object]$Body = $null,

        [string]$Purpose = "CyberArk REST call"
    )

    if ($DebugHttp) {
        Write-Log "$Purpose"
        Write-Log "HTTP Method: $Method"
        Write-Log "HTTP URI: $Uri"

        if (-not [string]::IsNullOrWhiteSpace($Proxy)) {
            Write-Log "Proxy: $Proxy"
        }

        Write-Log "TimeoutSec: $TimeoutSec"
    }

    try {
        $params = Get-RestParams `
            -Method $Method `
            -Uri $Uri `
            -Headers $Headers `
            -Body $Body

        return Invoke-RestMethod @params
    }
    catch {
        $body = Get-HttpErrorBody -ErrorRecord $_
        throw "$Purpose failed. Method=$Method Uri=$Uri Error=$body"
    }
}

function Test-CyberArkConnectivity {
    param([string]$ApiBase)

    try {
        $uriObj = [Uri]$ApiBase
        $hostName = $uriObj.Host

        Write-Log "Testing TCP connectivity to $hostName on port 443..."

        $test = Test-NetConnection -ComputerName $hostName -Port 443 -WarningAction SilentlyContinue

        if ($test.TcpTestSucceeded -eq $true) {
            Write-Log "TCP 443 connectivity successful to $hostName."
        }
        else {
            Write-Log "TCP 443 connectivity failed to $hostName. Check firewall, DNS, proxy, or route." "WARN"
        }
    }
    catch {
        Write-Log "Connectivity test failed. Error=$($_.Exception.Message)" "WARN"
    }
}

function Connect-CyberArk {
    param(
        [string]$ApiBase,
        [string]$AuthType
    )

    $username = Read-Host "Enter CyberArk username"
    $securePassword = Read-Host "Enter CyberArk password" -AsSecureString
    $plainPassword = ConvertTo-PlainText -SecureString $securePassword

    try {
        $logonUri = "$ApiBase/Auth/$AuthType/Logon"

        Write-Log "CyberArk logon URL: $logonUri"
        Write-Log "Attempting CyberArk API logon with AuthType=$AuthType"

        $body = @{
            username          = $username
            password          = $plainPassword
            concurrentSession = $true
        }

        $headers = @{
            "Content-Type" = "application/json"
        }

        $response = Invoke-CyberArkRest `
            -Method POST `
            -Uri $logonUri `
            -Headers $headers `
            -Body $body `
            -Purpose "CyberArk logon"

        $token = $null

        if ($response -is [string]) {
            $token = $response
        }
        elseif ($response.PSObject.Properties.Name -contains "CyberArkLogonResult") {
            $token = $response.CyberArkLogonResult
        }
        elseif ($response.PSObject.Properties.Name -contains "token") {
            $token = $response.token
        }
        elseif ($response.PSObject.Properties.Name -contains "access_token") {
            $token = $response.access_token
        }

        if ([string]::IsNullOrWhiteSpace($token)) {
            throw "CyberArk logon response did not contain a token."
        }

        Write-Log "CyberArk API logon successful."

        return $token
    }
    finally {
        if (-not [string]::IsNullOrEmpty($plainPassword)) {
            $plainPassword = $null
        }
    }
}

function Disconnect-CyberArk {
    param(
        [string]$ApiBase,
        [hashtable]$Headers
    )

    try {
        $logoffUri = "$ApiBase/Auth/Logoff"

        Invoke-CyberArkRest `
            -Method POST `
            -Uri $logoffUri `
            -Headers $Headers `
            -Body @{} `
            -Purpose "CyberArk logoff" | Out-Null

        Write-Log "CyberArk API session logged off."
    }
    catch {
        Write-Log "CyberArk logoff failed or session already expired. $($_.Exception.Message)" "WARN"
    }
}

function Get-CyberArkAccountDetails {
    param(
        [string]$ApiBase,
        [hashtable]$Headers,
        [string]$AccountID
    )

    $escapedId = [Uri]::EscapeDataString($AccountID)
    $uri = "$ApiBase/Accounts/$escapedId/"

    return Invoke-CyberArkRest `
        -Method GET `
        -Uri $uri `
        -Headers $Headers `
        -Purpose "Get CyberArk account details for AccountID=$AccountID"
}

function Unlock-CyberArkAccount {
    param(
        [string]$ApiBase,
        [hashtable]$Headers,
        [string]$AccountID
    )

    $escapedId = [Uri]::EscapeDataString($AccountID)
    $uri = "$ApiBase/Accounts/$escapedId/Unlock/"

    return Invoke-CyberArkRest `
        -Method POST `
        -Uri $uri `
        -Headers $Headers `
        -Body @{} `
        -Purpose "Unlock CyberArk account AccountID=$AccountID"
}

function Get-ObjectPropertyValue {
    param(
        [object]$Object,
        [string[]]$Names
    )

    if ($null -eq $Object) {
        return $null
    }

    foreach ($name in $Names) {
        if ($Object.PSObject.Properties.Name -contains $name) {
            $value = $Object.$name

            if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
                return ([string]$value).Trim()
            }
        }
    }

    return $null
}

# ---------------- MAIN ----------------

Write-Log "Bulk CyberArk account unlock/release starting."

Enable-Tls12
Enable-SkipCertificateCheck

if ([string]::IsNullOrWhiteSpace($CsvFile)) {
    $CsvFile = Read-Host "Enter full path to CSV file containing AccountID"
}

if (-not (Test-Path -Path $CsvFile)) {
    throw "CSV file not found: $CsvFile"
}

if ([string]::IsNullOrWhiteSpace($ApiBase)) {
    $ApiBase = Read-Host "Enter CyberArk API base URL, example: https://tenant.privilegecloud.cyberark.cloud/PasswordVault/API"
}

$ApiBase = Normalize-ApiBase -Value $ApiBase

if ([string]::IsNullOrWhiteSpace($ApiBase)) {
    throw "CyberArk API base URL is required."
}

Write-Log "Using CyberArk API base: $ApiBase"

Test-CyberArkConnectivity -ApiBase $ApiBase

Ensure-Folder -Path $ReportFolder

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportPath = Join-Path $ReportFolder "Bulk_CyberArk_Account_Unlock_$timestamp.csv"

$rows = @(Import-Csv -Path $CsvFile)

if ($rows.Count -eq 0) {
    throw "CSV file is empty: $CsvFile"
}

if (-not ($rows[0].PSObject.Properties.Name -contains "AccountID")) {
    throw "CSV must contain a column named AccountID."
}

if ($LiveRun) {
    Write-Log "LiveRun is TRUE. CyberArk account locks will be released." "WARN"
}
else {
    Write-Log "DryRun mode is active. No CyberArk accounts will be unlocked. Use -LiveRun to release locks." "WARN"
}

if ($SkipAccountDetails) {
    Write-Log "SkipAccountDetails enabled. Script will not call GET account details before unlock." "WARN"
}

$token = $null
$headers = $null

try {
    $token = Connect-CyberArk -ApiBase $ApiBase -AuthType $AuthType

    $headers = @{
        "Authorization" = $token
        "Content-Type"  = "application/json"
    }

    $results = New-Object System.Collections.Generic.List[object]

    $total = 0
    $wouldUnlock = 0
    $unlocked = 0
    $errors = 0
    $skipped = 0

    foreach ($row in $rows) {
        $total++

        $accountId = ([string]$row.AccountID).Trim()

        if ([string]::IsNullOrWhiteSpace($accountId)) {
            $skipped++

            $results.Add([PSCustomObject]@{
                AccountID = $accountId
                SafeName  = $null
                UserName  = $null
                Address   = $null
                PlatformID = $null
                Action    = "Skipped"
                Result    = "Missing AccountID"
                Error     = $null
                TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            })

            Write-Log "[$total/$($rows.Count)] Skipped blank AccountID." "WARN"
            continue
        }

        $safeName = $null
        $userName = $null
        $address = $null
        $platformId = $null

        try {
            Write-Log "[$total/$($rows.Count)] Processing AccountID=$accountId"

            if (-not $SkipAccountDetails) {
                try {
                    $account = Get-CyberArkAccountDetails `
                        -ApiBase $ApiBase `
                        -Headers $headers `
                        -AccountID $accountId

                    $safeName   = Get-ObjectPropertyValue -Object $account -Names @("safeName", "SafeName")
                    $userName   = Get-ObjectPropertyValue -Object $account -Names @("userName", "username", "UserName")
                    $address    = Get-ObjectPropertyValue -Object $account -Names @("address", "Address")
                    $platformId = Get-ObjectPropertyValue -Object $account -Names @("platformId", "PlatformID", "PlatformId")
                }
                catch {
                    Write-Log "Could not read details for AccountID=$accountId. Unlock may still work if permissions allow. Error=$($_.Exception.Message)" "WARN"
                }
            }

            if ($LiveRun) {
                Unlock-CyberArkAccount `
                    -ApiBase $ApiBase `
                    -Headers $headers `
                    -AccountID $accountId | Out-Null

                $unlocked++

                $results.Add([PSCustomObject]@{
                    AccountID = $accountId
                    SafeName  = $safeName
                    UserName  = $userName
                    Address   = $address
                    PlatformID = $platformId
                    Action    = "Unlocked"
                    Result    = "CyberArk account unlock/release API call completed"
                    Error     = $null
                    TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                })

                Write-Log "[$total/$($rows.Count)] Released CyberArk lock for AccountID=$accountId" "INFO"
            }
            else {
                $wouldUnlock++

                $results.Add([PSCustomObject]@{
                    AccountID = $accountId
                    SafeName  = $safeName
                    UserName  = $userName
                    Address   = $address
                    PlatformID = $platformId
                    Action    = "WouldUnlock"
                    Result    = "DryRun only. Use -LiveRun to release CyberArk lock."
                    Error     = $null
                    TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                })

                Write-Log "[$total/$($rows.Count)] Would release CyberArk lock for AccountID=$accountId" "WARN"
            }
        }
        catch {
            $errors++

            $results.Add([PSCustomObject]@{
                AccountID = $accountId
                SafeName  = $safeName
                UserName  = $userName
                Address   = $address
                PlatformID = $platformId
                Action    = "Error"
                Result    = "Failed"
                Error     = $_.Exception.Message
                TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            })

            Write-Log "[$total/$($rows.Count)] Failed AccountID=$accountId. $($_.Exception.Message)" "ERROR"
        }
    }

    $results | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

    Write-Log "Bulk CyberArk unlock/release completed."
    Write-Log "Total rows: $total"
    Write-Log "Unlocked: $unlocked"
    Write-Log "Would unlock: $wouldUnlock"
    Write-Log "Skipped: $skipped"
    Write-Log "Errors: $errors"
    Write-Log "Report exported to: $reportPath"
}
finally {
    if ($null -ne $headers -and -not [string]::IsNullOrWhiteSpace($ApiBase)) {
        Disconnect-CyberArk -ApiBase $ApiBase -Headers $headers
    }
}
