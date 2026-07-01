[System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy("http://proxy.prod.mtb.com:8080") # proxy
$cred = Get-Credential -Message "Enter api account username and password" # Your ISPSS identity or service user credentials
New-PASSession -Credential $cred -TenantSubdomain "mtbank" -ServiceUser

$fd = "account_ids.txt" #list of account IDs
$data = (Get-Content -Raw $fd).Trim() -split "`n" 
$data | % {
    [array]$operations = @{"op"="replace";"path"="/secretManagement/automaticManagementEnabled";"value"=$true}
    [array]$operations += @{"op"="replace";"path"="/secretManagement/manualmanagementreason"; value=""}
    Set-PASAccount -ID $_ -operations $operations
}
Close-PASSession
