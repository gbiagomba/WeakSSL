#Author: Gilles Biagomba
#Program: WeakSSL2.sh
#Description: This script was design to check for weak SSL ciphers.\n
#Convert XML files to HTML
#xsltproc <nmap-output.xml> -o <nmap-output.html> 

#Requesting target file name
echo "What is the name of the targets file?"
read targets

#Creating workspace
echo "--------------------------------------------------"
echo "Creating the workspace"
echo "--------------------------------------------------"
mkdir -p Nmap SSLScan SSLyze Cipherscan
mkdir -p TestSSL WeakSSL Reports
pth=$(pwd)
echo "Done creating workspace"

#Nmap Scan
echo "--------------------------------------------------"
echo "Performing the SSL scan using Nmap"
echo "--------------------------------------------------"
nmap -sS -sV --script=ssh2-enum-algos,ssl-enum-ciphers,rdp-enum-encryption,vulners -R -iL $targets -p 22,25,443,567,593,808,1433,3389,4443,4848,7103,7201,8443,8888 -oA Nmap/nmap_output
xsltproc Nmap/nmap_output.xml -o Reports/Nmap_SSL_Output.html
echo "Done scanning with nmap"

#SSL Scan - Needs troubleshooting
echo "--------------------------------------------------"
echo "Performing the SSL scan using sslscan"
echo "--------------------------------------------------"
for IP in $(cat $pth/$targets); do
    for PORTS in $(cat $pth/Ports);do
	    sslscan --xml=SSLScan/sslscan_output.xml $IP:$PORTS | aha -t "SSLScan Output" >> Reports/sslscan_output.html
    done
done
echo "Done scanning with sslscan"

#SSLyze Scan
echo "--------------------------------------------------"
echo "Performing the SSL scan using sslyze"
echo "--------------------------------------------------"
for IP in $(cat $pth/$targets); do
    for PORTS in $(cat $pth/Ports);do
	    sslyze --xml_out=SSLyze/SSLyze.xml --regular $IP:$PORTS | aha -t "SSLyze Output"  >> Reports/sslyze_output.html
    done
done
echo "Done scanning with sslyze"

#TestSSL Scan
echo "--------------------------------------------------"
echo "Performing the SSL scan using testssl"
echo "--------------------------------------------------"
cd TestSSL #You step into the folder because the testssl command uses the --log & --csv flags
for IP in $(cat $pth/$targets); do
    for PORTS in $(cat $pth/Ports);do
	    testssl --log --csv $IP:$PORTS | aha -t "TestSSL output"  >> ../Reports/testssl_output.html
    done
done
cd ..
echo "Done scanning with testssl"

#Mozilla Cipherscan
echo "--------------------------------------------------"
echo "Performing the SSL scan using cipherscan"
echo "--------------------------------------------------"
cd /tmp/
git clone https://github.com/mozilla/cipherscan
cd cipherscan/
for IP in $(cat $pth/$targets); do
    for PORTS in $(cat $pth/Ports);do
	    echo "You are scanning $IP:$PORTS"
        bash cipherscan $IP:$PORTS | aha -t "Cipherscan output"  > $pth/Cipherscan/$IP-$PORTS-Cipherscan_detailed_output.html
        python2 analyze -t $IP:$PORTS | aha -t "Cipherscan output"  >> $pth/Reports/CipherScan_output.html
    done
done
cd $pth
echo "Done scanning with cipherscan"

#OpenSSL - Manually checking weak ciphers (Needs to be fixed)
#./Birthday_test.sh | aha > WeakSSL.html
# echo "--------------------------------------------------"
# echo "Validating results using OpenSSL"
# echo "--------------------------------------------------"
# for c in $(cat $targets); do
#  for i in $(cat WeakCiphers.txt); do
#   echo "---------------------------------------------TLSv1---------------------------------------------------------"
#   echo "Address: $c"
#   echo "Cipher: $i"
#   openssl s_client -connect $c:443 -tls1 -cipher $i | aha >> WeakSSL/$c-WeakCiphers.html
#   echo "---------------------------------------------TLSv1.1-------------------------------------------------------"
#   echo "Address: $c"
#   echo "Cipher: $i"
#   openssl s_client -connect $c:443 -tls1_1 -cipher $i | aha >> WeakSSL/$c-WeakCiphers.html
#   echo "---------------------------------------------TLSv1.2-------------------------------------------------------"
#   echo "Address: $c"
#   echo "Cipher: $i"
#   openssl s_client -connect $c:443 -tls1_2 -cipher $i | aha >> WeakSSL/$c-WeakCiphers.html
#   echo "--------------------------------------------------"
#  done
# done

echo "Done validating ciphers & We are done scanning everything!"

#Open reports in Firefox
echo "--------------------------------------------------"
echo "Opening the results now"
echo "--------------------------------------------------"
firefox --new-tab $pth/Reports/*.html

#De-initialize all variables & set them to NULL
unset pth
unset IP
unset PORTS
unset targets
set -u