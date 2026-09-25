@echo off
netsh advfirewall firewall delete rule name="SOC-ISOLATE-OUT" >nul 2>&1
netsh advfirewall firewall delete rule name="SOC-ISOLATE-IN" >nul 2>&1
netsh advfirewall firewall add rule name="SOC-ISOLATE-OUT" dir=out action=allow remoteip=192.168.50.50
netsh advfirewall firewall add rule name="SOC-ISOLATE-IN" dir=in action=allow remoteip=192.168.50.50
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
echo %date% %time% HOST ISOLATED>> "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
