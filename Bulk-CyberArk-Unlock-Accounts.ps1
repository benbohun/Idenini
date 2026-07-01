# Bulk_Release_CyberArk_Locked_Accounts.ps1
# Purpose: Release/unlock CyberArk accounts by AccountID using psPAS.
# Input file: account_ids.txt, one AccountID per line.

$ErrorActionPreference = "Stop"

# ---------------- CONFIG ----------------

$TenantSubdomain = "mtbank"
$AccountIdFile   = "account_ids.txt"
$ReportFile      = ".\CyberArk_Unlock_Report_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss")

# Proxy
[System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy("http://proxy.prod.mtb.com:8080")
[System.Net.WebRequest]::DefaultWebProxy.UseDefaultCredentials = $true

# Optional behavior
$TryCheckInFallback = $true
$ReEnableAutomaticManagementAfterUnlock = $false

# ---------------- FUNCTIONS ----------------

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "$ts [$Level] $Message"
}

function Add-Result {
    param(
        [System.Collections.Generic.List[object]]$Results,
        [string]$AccountID,
        [string]$Action,
        [string]$Status,
        [string]$Message
    )

    $Results.Add([PSCustomObject]@{
        TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        AccountID = $AccountID
        Action    = $Action
        Status    = $Status
        Message   = $Message
    })
}

# ---------------- MAIN ----------------

Write-Log "CyberArk bulk account release script starting."

if (-not (Get-Command New-PASSession -ErrorAction SilentlyContinue)) {
    throw "psPAS module is not loaded or installed. Run: Import-Module psPAS"
}

if (-not (Test-Path $AccountIdFile)) {
    throw "Account ID file not found: $AccountIdFile"
}

$accountIds = Get-Content $AccountIdFile | ForEach-Object {
    $_.Trim()
} | Where-Object {
    -not [string]::IsNullOrWhiteSpace($_)
} | Select-Object -Unique

if ($accountIds.Count -eq 0) {
    throw "No AccountIDs found in $AccountIdFile"
}

Write-Log "Loaded $($accountIds.Count) unique AccountID(s)."

$cred = Get-Credential -Message "Enter API account username and password"

try {
    Write-Log "Connecting to CyberArk Privilege Cloud tenant: $TenantSubdomain"
    New-PASSession -Credential $cred -TenantSubdomain $TenantSubdomain -ServiceUser
    Write-Log "Connected to CyberArk."

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($id in $accountIds) {
        Write-Log "Processing AccountID: $id"

        $released = $false

        try {
            # This is the actual CyberArk release/unlock action.
            Unlock-PASAccount -AccountID $id -Unlock -ErrorAction Stop

            Write-Log "SUCCESS: Released/unlocked AccountID $id" "SUCCESS"
            Add-Result -Results $results -AccountID $id -Action "Unlock" -Status "Success" -Message "Account released/unlocked successfully."

            $released = $true
        }
        catch {
            $unlockError = $_.Exception.Message
            Write-Log "Unlock failed for AccountID $id. Error: $unlockError" "WARN"

            if ($TryCheckInFallback) {
                try {
                    # Fallback for exclusive-access / checked-out accounts.
                    # Default Unlock-PASAccount behavior checks in the account.
                    Unlock-PASAccount -AccountID $id -ErrorAction Stop

                    Write-Log "SUCCESS: Check-in fallback completed for AccountID $id" "SUCCESS"
                    Add-Result -Results $results -AccountID $id -Action "CheckInFallback" -Status "Success" -Message "Unlock failed, but check-in fallback succeeded. Original unlock error: $unlockError"

                    $released = $true
                }
                catch {
                    $checkInError = $_.Exception.Message
                    Write-Log "FAILED: AccountID $id. Unlock and CheckIn both failed. Error: $checkInError" "ERROR"
                    Add-Result -Results $results -AccountID $id -Action "UnlockAndCheckIn" -Status "Failed" -Message "Unlock error: $unlockError | CheckIn error: $checkInError"
                }
            }
            else {
                Add-Result -Results $results -AccountID $id -Action "Unlock" -Status "Failed" -Message $unlockError
            }
        }

        if ($released -and $ReEnableAutomaticManagementAfterUnlock) {
            try {
                [array]$operations = @(
                    @{
                        op    = "replace"
                        path  = "/secretManagement/automaticManagementEnabled"
                        value = $true
                    },
                    @{
                        op    = "replace"
                        path  = "/secretManagement/manualManagementReason"
                        value = ""
                    }
                )

                Set-PASAccount -ID $id -operations $operations -ErrorAction Stop

                Write-Log "Automatic management re-enabled for AccountID $id" "INFO"
                Add-Result -Results $results -AccountID $id -Action "ReEnableAutomaticManagement" -Status "Success" -Message "automaticManagementEnabled set to true."
            }
            catch {
                Write-Log "Failed to re-enable automatic management for AccountID $id. Error: $($_.Exception.Message)" "WARN"
                Add-Result -Results $results -AccountID $id -Action "ReEnableAutomaticManagement" -Status "Failed" -Message $_.Exception.Message
            }
        }
    }

    $results | Export-Csv -Path $ReportFile -NoTypeInformation -Encoding UTF8
    Write-Log "Report exported to: $ReportFile"
}
finally {
    try {
        Close-PASSession
        Write-Log "CyberArk session closed."
    }
    catch {
        Write-Log "Close-PASSession failed or session was already closed. $($_.Exception.Message)" "WARN"
    }
}

Write-Log "Script completed."
