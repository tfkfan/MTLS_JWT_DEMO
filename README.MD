# Mutable TLS + JWT authentication spring boot example

## Keys generation

Because MTLS is bi-directional secured communication 
we need to generate keypairs for client and server both as well to encrypt each other's data

### Server keypair, keystore, truststore generation

    keytool -v -genkeypair -dname "CN=Refactorizando,OU=Madrid,O=Refactorizando,C=SP" -keystore keystore.jks -storepass secret -keypass secret -keyalg RSA -keysize 2048 -alias server -validity 3650 -deststoretype pkcs12 -ext KeyUsage=digitalSignature,dataEncipherment,keyEncipherment,keyAgreement -ext ExtendedKeyUsage=serverAuth,clientAuth -ext SubjectAlternativeName:c=DNS:localhost,IP:127.0.0.1

    keytool -v -exportcert -file server.cer -alias server -keystore keystore.jks -storepass secret -rfc

    keytool -v -importcert -file server.cer -alias server -keystore truststore.jks -storepass secret -noprompt

### Client keypair, keystore, truststore generation 

    keytool -v -genkeypair -dname "CN=Refactorizando,OU=Madrid,O=Refactorizando,C=SP" -keystore keystore.jks -storepass secret -keypass secret -keyalg RSA -keysize 2048 -alias client -validity 3650 -deststoretype pkcs12 -ext KeyUsage=digitalSignature,dataEncipherment,keyEncipherment,keyAgreement -ext ExtendedKeyUsage=serverAuth,clientAuth -ext SubjectAlternativeName:c=DNS:localhost,IP:127.0.0.1

    keytool -v -exportcert -file client.cer -alias client -keystore keystore.jks -storepass secret -rfc

    keytool -v -importcert -file client.cer -alias client -keystore truststore.jks -storepass secret -noprompt

### Private client cert extraction from jks 

To start, we need transform jks keystore to p12 format:

    keytool -importkeystore \
    -srckeystore keystore.jks \
    -destkeystore keystore.p12 \
    -deststoretype PKCS12 \
    -srcalias client \
    -deststorepass secret \
    -destkeypass secret

Now we can extract private client's key as pem:

    openssl pkcs12 -in keystore.p12 -nodes -nocerts -out client_private_key.pem

## Spring boot application settings

Use /config/application.yml with already defined settings for your app
Put already generated keystore.jks and truststore.jks into src/main/resources

Run from project root

    mvn clean package
    java -jar ./target/MTLS_JWT_DEMO-1.0-SNAPSHOT.jar


## Requests

First of all, we need to authenticate via JWT controller over HTTPs/MTLS and get bearer token:

    curl -v --cert client.cer --key client_private_key.pem --cacert server.cer --header "Content-Type: application/json" --request POST https://localhost:8081/authenticate --data '{ "username":"user1", "password":"password"}'  

Then you receive JWT token like
    
    {"token":"eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ1c2VyMSIsImlhdCI6MTcwMTE5MDExMCwiZXhwIjoxNzAxMjA4MTEwfQ.3VOYkN5JbaxX7sxY5WV0L0wiaWhdIaXvY8BIV6dIdxnOMmh9R0UDFUIXXu10rIPyTfZmbCIdNYd3b5aWNyGL-g"}


You should put this token as bearer header to other further requests

Now you can run test method

    curl -v --cert client.cer --key client_private_key.pem --cacert server.cer --header "Content-Type: application/json" --header "Authorization: Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ1c2VyMSIsImlhdCI6MTcwMTE5MDI0OSwiZXhwIjoxNzAxMjA4MjQ5fQ.Nx-ZUTRaVMbonc_PrJro11Qi3Ab4PGmttbmfYA9baoQC67te07-j-iH7PjYbTV9JpaW2lw0C7_dI2PXBhoNvrA" --request  GET https://localhost:8081/api/test 
