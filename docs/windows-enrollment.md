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
