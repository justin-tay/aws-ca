$DeviceUid = (Get-WmiObject -Class Win32_ComputerSystemProduct).UUID
$Endpoint = "https://xyz.execute-api.ap-southeast-1.amazonaws.com/dev/"
$CsrPath = "$DeviceUid.csr"
$CertPath = "$DeviceUid.p7b"

curl.exe --location --request POST $Endpoint'simpleenroll' --header 'Authorization: Basic NUNVQUNRVVZI' --header 'Content-Type: application/pkcs10' --data-binary "@$CsrPath" --output $CertPath