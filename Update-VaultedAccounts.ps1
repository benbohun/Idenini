Error shows below, this is what we are trying to solve, some updates will require moving to a different device type
kindly suggest best approach or changes

PS D:\script

s\wpa\AcountFieldUpdated> .\Update-VaultedAccounts.ps1 -CsvFile .\samples\account-update-template.csv -Environment dev
2026-06-04T14:49:05 source=Import-RunConfig [INFO] Environment=dev IdentityBase=https://abq4291.id.cyberark.cloud ApiBase=https://mtbanktest.privilegecloud.cyberark.cloud/PasswordVault/API ProxyConfigured=True
2026-06-04T14:49:05 source=Get-CsvRows [INFO] Imported 1 row(s) from .\samples\account-update-template.csv
2026-06-04T14:49:05 source=Get-IdentityBearerToken [INFO] Prompting for CyberArk Identity service-user credentials
2026-06-04T14:49:19 source=Get-IdentityBearerToken [INFO] Token acquired. SHA256 fingerprint=92e1fa7dcd38014b... ExpiresIn=7200
2026-06-04T14:49:19 source=Get-PlatformInventory [INFO] Loading platform inventory
2026-06-04T14:49:21 source=Get-PlatformInventory [INFO] Loaded 93 regular platform(s)
2026-06-04T14:49:21 source=Start-AccountUpdateRun [INFO] Processing CSV row 1
2026-06-04T14:49:21 source=Start-AccountUpdateRun [ERROR] Row 1 failed. AccountID=254_3 Message=Platform device/system type mismatch. Current 'GEN-E-PR0PL0PC0NENR'=Website, Target 'WIN-DOMAIN-E-PR90NR'=Windows.
2026-06-04T14:49:21 source=Start-AccountUpdateRun [INFO] Run completed. Report=D:\scripts\wpa\AcountFieldUpdated\reports\Update-VaultedAccounts_Report_20260604-144905.csv Log=D:\scripts\wpa\AcountFieldUpdated\logs\Update-VaultedAccounts_20260604-144905.log
