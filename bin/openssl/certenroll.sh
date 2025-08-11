export DeviceUid=$(ioreg -d2 -c IOPlatformExpertDevice | awk -F\" '/IOPlatformUUID/{print $(NF-1)}')

if [[ -z "$Endpoint" ]]; then
  export Endpoint="https://xyz.execute-api.ap-southeast-1.amazonaws.com/dev/"
fi

if [[ -z "$Username" ]]; then
  export Username="user"
fi

if [[ -z "$Password" ]]; then
  export Password="Password1#"
fi

export CsrPath=client.csr
export CertPath=${DeviceUid}.p7b

curl --location --request POST ${Endpoint}'simpleenroll' --user ${Username}':'${Password} --header 'Content-Type: application/pkcs10' --data-binary "@$CsrPath" --output $CertPath

openssl pkcs7 -print_certs -in $CertPath -out clientcert.pem
