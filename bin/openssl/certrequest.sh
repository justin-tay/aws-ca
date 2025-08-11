export DeviceUid=$(ioreg -d2 -c IOPlatformExpertDevice | awk -F\" '/IOPlatformUUID/{print $(NF-1)}')

echo "Generating Private Key for $DeviceUid to clientkey.pem"
openssl genrsa -aes256 -out clientkey.pem 2048

echo "Generating Certificate Request for $DeviceUid"
openssl req -new -key clientkey.pem -out client.csr -config csr.cnf

openssl req -in client.csr -text
