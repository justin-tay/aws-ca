$DeviceUid = (Get-WmiObject -Class Win32_ComputerSystemProduct).UUID
if ($env:ENDPOINT) {
    $Endpoint = $env:ENDPOINT
} else {
    $Endpoint = "https://xyz.execute-api.ap-southeast-1.amazonaws.com/dev/"
}
if ($env:USER_NAME) {
    $Username = $env:USER_NAME
} else {
    $Username = "user"
}
if ($env:PASSWORD) {
    $Password = $env:PASSWORD
} else {
    $Password = "Password1#"
}
$CsrPath = "$DeviceUid.csr"
$CertPath = "$DeviceUid.p7b"

curl.exe --location --request POST $Endpoint'simpleenroll' --user $Username':'$Password --header 'Content-Type: application/pkcs10' --data-binary "@$CsrPath" --output $CertPath
