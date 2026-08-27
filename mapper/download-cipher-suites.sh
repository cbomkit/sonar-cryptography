#!/bin/sh

url=https://ciphersuite.info/api/cs/
status_code=$(curl -s -o /dev/null -w "%{http_code}" "$url")

if [ "$status_code" -eq 200 ]; then
    curl "$url" -o ciphersuites.json
    python3 -m json.tool --indent 2 ciphersuites.json ciphersuites.json.tmp
    mv ciphersuites.json.tmp ciphersuites.json
    echo "Successfully processed $url"
    python3 creatCipherSuiteClass.py
else
    echo "Failed to process $url (Status code: $status_code)"
fi