param([switch]$Elevated)

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ((Test-Admin) -eq $false)  {
    if ($elevated) {
        # tried to elevate, did not work, aborting
    } else {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    }
    exit
}

$DeviceUid = (Get-WmiObject -Class Win32_ComputerSystemProduct).UUID
$CertificateFolder = "."

$CsrPath = "$CertificateFolder\$($DeviceUid).csr"
$InfPath = "$CertificateFolder\$($DeviceUid).inf"

$Signature = '$Windows NT$' 

$Inf =
@"
[Version]
Signature= "$Signature" 
 
[NewRequest]
Subject = "CN=$DeviceUid"
KeySpec = AT_KEYEXCHANGE
KeyLength = 2048
Exportable = false
MachineKeySet = true
SMIME = false
PrivateKeyArchive = false
UserProtected = false
UseExistingKeySet = false
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0
HashAlgorithm = SHA256
SuppressDefaults = true
 
[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.2

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=UDID=$DeviceUid&"
"@

if (!(Test-Path $CsrPath)) {
    Write-Host "Generating Certificate Request for $DeviceUid"
    $Inf | out-file -filepath $InfPath -force
    certreq -new $InfPath $CsrPath
    Write-Host "Written Certificate Request to $CsrPath"
} else {
    Write-Host "Certificate Request for $DeviceUid already exists"
}