PS D:\scripts\wpa\AcountFieldUpdated> .\Update-VaultedAccounts.ps1 -CsvFile .\samples\account-update-template.csv -Environment dev -Preview
2026-06-04T14:39:08 source=Import-RunConfig [INFO] Environment=dev IdentityBase=https://abq4291.id.cyberark.cloud ApiBase=https://mtbanktest.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts/PasswordVault/API ProxyConfigured=True
2026-06-04T14:39:08 source=Start-AccountUpdateRun [WARN] Preview mode enabled. No account update/create/delete calls will be sent.
2026-06-04T14:39:08 source=Get-CsvRows [INFO] Imported 1 row(s) from .\samples\account-update-template.csv
2026-06-04T14:39:08 source=Get-IdentityBearerToken [INFO] Prompting for CyberArk Identity service-user credentials
2026-06-04T14:39:22 source=Get-IdentityBearerToken [INFO] Token acquired. SHA256 fingerprint=5499d7550254a59e... ExpiresIn=7200
2026-06-04T14:39:22 source=Get-PlatformInventory [INFO] Loading platform inventory
REST call failed. Method=GET Uri=https://mtbanktest.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts/PasswordVault/API/Platforms?PlatformType=Regular The remote server returned an error: (404) Not Found.
At D:\scripts\wpa\AcountFieldUpdated\Update-VaultedAccounts.ps1:589 char:9
+         throw "REST call failed. Method=$Method Uri=$uri $(Get-WebErr ...
+         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : OperationStopped: (REST call faile...404) Not Found.:String) [], RuntimeException
    + FullyQualifiedErrorId : REST call failed. Method=GET Uri=https://mtbanktest.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts/PasswordVault/API/Platforms?PlatformType=Regular The remote server returned an error: (404) Not Found.
