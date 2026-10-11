# Enrolling from Windows 11 (manual checklist)

Checks that a real Windows client can enroll over EST and bind the certificate
to a CNG key. Run it against a deployed stack after changes to the EST handler
or the certificate profiles. Needs a user in the `est-client` group (create one
with `aws cognito-idp admin-create-user`, `admin-set-user-password --permanent`
and `admin-add-user-to-group`) and the `EstEndpoint` stack output.

1. Trust the root. Fetch the chain and import the root into the current user's
   Trusted Root store (a prompt appears; this changes the trust store, so do it
   on a test machine and remove the root afterwards):

   ```powershell
   $est = '<EstEndpoint>/issuing'
   Invoke-WebRequest "$est/cacerts" -OutFile cacerts.b64
   certutil -decode cacerts.b64 cacerts.p7b
   certutil -user -addstore Root cacerts.p7b   # review what is added first
   ```

2. Create the request with a CNG key (the subject CN must be the user name; the
   server replaces everything else):

   ```ini
   ; request.inf
   [NewRequest]
   Subject = "CN=<user>"
   KeyAlgorithm = ECDSA_P256
   KeyLength = 256
   ProviderName = "Microsoft Software Key Storage Provider"
   MachineKeySet = FALSE
   Exportable = FALSE
   RequestType = PKCS10
   ```

   ```powershell
   certreq -new request.inf request.req
   ```

3. Enroll. EST takes base64 DER, with or without the PEM armor:

   ```powershell
   curl.exe -u "<user>:<password>" -H "Content-Type: application/pkcs10" `
     --data-binary "@request.req" "$est/simpleenroll" -o response.b64
   ```

4. Bind the certificate to the key and check it:

   ```powershell
   certutil -decode response.b64 response.p7b
   certreq -accept response.p7b
   certutil -user -store My   # the certificate, with "Provider = Microsoft Software Key Storage Provider"
   ```

Expected: step 3 returns 200, step 4 finds the private key, and the chain builds
to the root without errors. Also try a wrong password (401) and a different CN
(403).

Clean-up: remove the root from the Trusted Root store and the certificate from
`My`.

## With PSCertificateEnrollment (SCEP and EST, verified)

[PSCertificateEnrollment](https://www.powershellgallery.com/packages/PSCertificateEnrollment/)
(Uwe Gradenegger, tested with 1.0.12) drives Windows' own enrollment APIs, so it
is a faithful stand-in for what a Windows client does. Use `-Scope CurrentUser`
or import it from a folder; it needs no trust store changes, but it **does** leave
a certificate in `Cert:CurrentUserMy` and private keys in your profile, so
remove them afterwards (`certutil -user -csp "Microsoft Software Key Storage
Provider" -key` lists the keys; `-delkey <name>` removes one).

SCEP, with the challenge from the `ScepChallengeParameter` output (the module
adds `/pkiclient.exe` itself):

```powershell
$challenge = aws ssm get-parameter --name <ScepChallengeParameter> --with-decryption `
  --query Parameter.Value --output text
Get-SCEPCertificate -ComputerName <function-url-host> -UseSSL -Suffix 'scep/issuing' `
  -ChallengePassword $challenge -Subject 'CN=my-device' -KeyAlgorithm RSA -KeyLength 2048
# Renewal needs no challenge: sign with the certificate you were issued.
Get-SCEPCertificate -ComputerName <host> -UseSSL -Suffix 'scep/issuing' `
  -SigningCert (Get-Item Cert:CurrentUserMy<thumbprint>) -KeyAlgorithm RSA -KeyLength 2048
```

With dynamic challenges (`scep.challenge: 'dynamic'` or `'both'`), fetch a
single-use challenge from the NDES-style page as a user in the `scep-admin`
group, then enroll with it:

```powershell
$mdm = Get-Credential   # a Cognito user in scep-admin
$otp = Get-NDESOTP -ComputerName <host> -Suffix 'scep/issuing/certsrv/mscep_admin' `
  -Credential $mdm -BasicAuthentication
Get-SCEPCertificate -ComputerName <host> -UseSSL -Suffix 'scep/issuing' `
  -ChallengePassword $otp -Subject 'CN=my-device' -KeyAlgorithm RSA -KeyLength 2048
```

The challenge works once. `Get-NDESOTP` reads the first 16 hex digits (its default
`-PasswordLength 8`), which is the default length here (`lengthBytes: 8`); if you
configure more, pass `-PasswordLength <lengthBytes>`.

### ECDSA keys

`Get-SCEPCertificate -KeyAlgorithm ECDSA_P256` (or `ECDSA_P384`) enrolls: Windows signs the CMS
message with a throwaway RSA key under `CN=SCEP Protocol Certificate`, so the answer can be
encrypted to it. (Verified against a local server on Windows 11 with PSCertificateEnrollment 1.0.12.)

**Renewing an ECDSA certificate with `-SigningCert` does not work from Windows' client.** The server
accepts the request (it reads ECDSA signers, including the `id-ecPublicKey` signature algorithm
Windows states) and answers with ECDH key agreement, which OpenSSL opens. Windows then fails in
`ProcessResponseMessage` with `NTE_PERM` (`0x80090010`). The likely cause is that a CNG key of
algorithm ECDSA can sign but cannot take part in key agreement, so Windows cannot open an answer
addressed to it; this was not confirmed beyond the error. To replace an ECDSA certificate from
Windows, enroll again with a new challenge; an RSA certificate renews with `-SigningCert` as above.

EST, with a Cognito user in the `est-client` group (the CN must be the user name):

```powershell
$credential = Get-Credential   # the Cognito user name and password
$csr = New-CertificateRequest -Subject 'CN=<user>' -KeyAlgorithm ECDSA_P256
Get-ESTCertificate -CertificateRequest $csr -ComputerName <function-url-host> -Credential $credential
```

This returns the certificate and its issuing CA; install it with
`Install-IssuedCertificate` if you want it bound to the key. EST re-enrollment
with a client certificate needs mTLS, which the `function-url` front door does not offer.
