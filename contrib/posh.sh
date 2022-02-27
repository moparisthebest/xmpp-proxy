#!/bin/sh

# these are just examples for how to grab and hash certificates for POSH
# adapted from https://curl.se/libcurl/c/CURLOPT_PINNEDPUBLICKEY.html

# this is for any direct TLS port like xmpps or https
openssl s_client -servername posh.badxmpp.eu -connect posh.badxmpp.eu:443 < /dev/null | sed -n "/-----BEGIN/,/-----END/p" > posh.badxmpp.eu.pem
openssl asn1parse -noout -inform pem -in posh.badxmpp.eu.pem -out posh.badxmpp.eu.der
openssl dgst -sha256 -binary posh.badxmpp.eu.der | openssl base64 | tr -d '\n' > posh.badxmpp.eu.der.sha256
openssl dgst -sha512 -binary posh.badxmpp.eu.der | openssl base64 | tr -d '\n' > posh.badxmpp.eu.der.sha512

openssl base64 < posh.badxmpp.eu.der | tr -d '\n' > posh.badxmpp.eu.der.base64

# this is for any starttls xmpp port
openssl s_client -starttls xmpp -name posh.badxmpp.eu -servername posh.badxmpp.eu -connect snikket2.prosody.im:5222 < /dev/null | sed -n "/-----BEGIN/,/-----END/p" > posh.badxmpp.eu.5222.pem
openssl asn1parse -noout -inform pem -in posh.badxmpp.eu.5222.pem -out posh.badxmpp.eu.5222.der
openssl dgst -sha256 -binary posh.badxmpp.eu.5222.der | openssl base64 | tr -d '\n' > posh.badxmpp.eu.5222.der.sha256
openssl dgst -sha512 -binary posh.badxmpp.eu.5222.der | openssl base64 | tr -d '\n' > posh.badxmpp.eu.5222.der.sha512

openssl base64 < posh.badxmpp.eu.5222.der | tr -d '\n' > posh.badxmpp.eu.5222.der.base64

wget https://posh.badxmpp.eu/.well-known/posh/xmpp-server.json https://posh.badxmpp.eu/.well-known/posh/xmpp-client.json

grep . *.sha*
