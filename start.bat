@echo off
REM all-in-one DNS hijack + web capture + log console
REM 53 dns / 80 http / 443 https / 8080 log console
REM   web content -> lan_dns_web\webroot      logs -> lan_dns_web\logs
cd /d "%~dp0"
python -u app.py --ip 192.168.1.146 --webroot "%~dp0webroot" %*
REM handy extras (uncomment one at a time):
REM   --dhcp                          hand out our DNS to the whole LAN via DHCP
REM   --forward-all --upstream 8.8.8.8,1.1.1.1    relay + log instead of hijacking
REM   --legacy-tls                    allow TLS 1.0/1.1 for old console browsers
REM   --firewall                      add inbound netsh rules (needs an admin shell)
pause
