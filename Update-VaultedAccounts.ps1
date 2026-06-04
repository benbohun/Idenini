# Create the proxy object
$proxyUri = "Placehold"
$proxy = New-Object System.Net.WebProxy($proxyUri, $true)  # $true bypasses proxy for local addresses
 
# Assign it as the default for WebRequest
[System.Net.WebRequest]::DefaultWebProxy = $proxy
 
# Optional: Verify the setting
[System.Net.WebRequest]::DefaultWebProxy.Address
