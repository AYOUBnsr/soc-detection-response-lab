@echo off
netsh advfirewall firewall delete rule name="SOC-ISOLATE-OUT" >nul 2>&1
netsh advfirewall firewall delete rule name="SOC-ISOLATE-IN" >nul 2>&1
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
echo %date% %time% HOST RELEASED>> "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
