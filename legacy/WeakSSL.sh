#!/bin/bash
#Author: Gilles Biagomba
#Program: WeakCiphers.sh
#Description: This script was design to check for weak SSL ciphers.\n

PORT=443
for IPs in $(cat targets);do
/home/gilbia01/Scripts/ssltest.pl $IPs
echo "----------------------------------------------------------"
echo "----------------------------------------------------------"
#sslyze --regular $IPs:$PORT > $IPs_sslyze.txt
echo "----------------------------------------------------------"
echo "----------------------------------------------------------"
#nmap --script ssl-enum-ciphers -p 443 $IPs -oN $IPs_Nmap.txt
done

