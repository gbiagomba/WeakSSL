# Weak SSL Scanner
This script scans servers for SSL misconfigurations (e.g., weak ciphers, weak encryption protocols, etc) using nmap, sslscan, sslyze, testssl and openssl. I use multiple tools because I want to cross reference and validate all findings without having to manually run additional tools.

## Requirements
YOu will need nmap, sslscan, sslyze, and testssl installed
- apt install sslyze sslscan testssl.sh

## Usage
### Weak.sh
Weak.sh needs to be fixed, just so you know!
```
./Weak.sh
```
### Weak-lite.sh
This is a stable release and it works
```
./tls_sweeper.sh target-filename.txt
```


## Footnote
I am still writing the script, I been improving it over the past couple weeks, and I am going to convert it to a python script.
