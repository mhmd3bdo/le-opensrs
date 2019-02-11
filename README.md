# le-opensrs

let's encrypt client to automate issuing and reissuing wildcard [Let's Encrypt] (https://letsencrypt.org/)
certificates with opensrs API DNS , this scipt will retreive challenge from Let's Encrypt and will update 
it , in opensrs DNS , and the will ask Let's Encrypt to verify the challenge.


### note
for this script to work , you have to use opensrs nameservers

## How to use this script

First you have to generate a private key to use it as 
account key for ACME using openssl

```openssl genrsa 4096 > le-opensrs/account.key```

make modification to crt.cnf that fits your needs
```
[ req ]
default_bits       = 2048
distinguished_name = req_distinguished_name
req_extensions     = req_ext
prompt             = no
[ req_distinguished_name ]
countryName                 = SD
stateOrProvinceName         = KH
localityName               = KH
organizationName           = Organization
commonName                 = example.com
[ req_ext ]
subjectAltName = @alt_names
[alt_names]
DNS.1   = example.com
DNS.2   = *.example.com
```

then you have to genrate the CSR for you desired domain

```openssl req -out le-opensrs/domain.csr -newkey rsa:2048 -nodes -keyout le-opensrs/domain.key -config le-opensrs/crt.cnf```

edit config file with your settings

```
Contacts = mailto:yourmail@yourdomain.com
[opensrs]
#your opensrs reseller username
reseller_username = example

#remember to whitelist the public ip to acess the API
# connection configuration for opensrs .. default is live connection parameter
api_key = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
api_host_port = https://rr-n1-tor.opensrs.net:55443
```

Finally run the main script in le-opensrs
```./le-opensrs.py ```

This will generate the certificate in PEM format 

* Tip:   Use cronjob to run the script periodcly for certs renewal
