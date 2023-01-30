# About the repository

This repository is created based on Dan Vega's tutorial: https://www.danvega.dev/blog/2022/09/06/spring-security-jwt/

Github: https://github.com/danvega/jwt-username-password

## Steps to generate the asymmetric keys with OpenSSL

*Source*: https://www.danvega.dev/blog/2022/09/06/spring-security-jwt/

__NOTE:__ Normally you could get away with running the first 2 commands. The reason for the 3rd command is that the private key needs to be in PEM-encoded PKCS#8 format. Switch to that certs directory and run each of the following commands separately.

```
# create rsa key pair
openssl genrsa -out keypair.pem 2048
 
# extract public key
openssl rsa -in keypair.pem -pubout -out public.pem
 
# create private key in PKCS#8 format
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out private.pem
 
```