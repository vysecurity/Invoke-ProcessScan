Disclaimer
==========
As always, do not use anything for malicious intent.

Code written by Vincent Yiu of ActiveBreach by MDSec Consulting Ltd (www.mdsec.co.uk)

Credits
=======
Credit to EQGRP for the list

Feel free to submit PR or improvements. You can even take the code and invent your own things, just give a small link back to this repo.

Description
===========

This script uses a list from the Equation Group leak from the shadow brokers to provide context to executeables that are running on a system.

Usage
=====

List all processes but do not save:

```
List all processes, do not save.

PS C:\> Invoke-ProcessScan -SecurityOnly $False
[*] Starting AV Scan

ProcessName               Description                                               
-----------               -----------                                               
cmdagent.exe              !!! Comodo Firewall Pro !!!                               
system.exe                !!! LanAgent Monitoring !!!                               
csrss.exe                 Client-Server Runtime Server Subsystem                    
csrss.exe                 Client-Server Runtime Server Subsystem                    
rundll32.exe              Control Panel Helper                                      
RegSrvc.exe               Intel Communications Service                              
evteng.exe                Intel EvtEng Module                                       
lsass.exe                 Local Security Authority Server Subsystem                 
PresentationFontCache.exe Microsoft .NET Framework                                  
conhost.exe               Microsoft Console Windows Host                            
conhost.exe               Microsoft Console Windows Host                            
dllhost.exe               Microsoft DCOM DLL Host Process                           
spoolsv.exe               Microsoft Printer Spooler Service                         
searchindexer.exe         Microsoft search indexer                                  
svchost.exe               Microsoft Service Host Process (Check path in processdeep)
svchost.exe               Microsoft Service Host Process (Check path in processdeep)
svchost.exe               Microsoft Service Host Process (Check path in processdeep)
svchost.exe               Microsoft Service Host Process (Check path in processdeep)
svchost.exe               Microsoft Service Host Process (Check path in processdeep)
svchost.exe               Microsoft Service Host Process (Check path in processdeep)
svchost.exe               Microsoft Service Host Process (Check path in processdeep)
svchost.exe               Microsoft Service Host Process (Check path in processdeep)
svchost.exe               Microsoft Service Host Process (Check path in processdeep)
svchost.exe               Microsoft Service Host Process (Check path in processdeep)
svchost.exe               Microsoft Service Host Process (Check path in processdeep)
svchost.exe               Microsoft Service Host Process (Check path in processdeep)
svchost.exe               Microsoft Service Host Process (Check path in processdeep)
svchost.exe               Microsoft Service Host Process (Check path in processdeep)
svchost.exe               Microsoft Service Host Process (Check path in processdeep)
svchost.exe               Microsoft Service Host Process (Check path in processdeep)
sqlwriter.exe             Microsoft SQL Server                                      
tabtip.exe                Microsoft Tablet PC Module                                
winlogon.exe              Microsoft Windows Logon Process                           
wmiprvse.exe              Microsoft Windows Management Instrumentation              
wmiprvse.exe              Microsoft Windows Management Instrumentation              
unsecapp.exe              Microsoft Windows Management Instrumentation              
unsecapp.exe              Microsoft Windows Management Instrumentation              
smss.exe                  Session Manager Subsystem                                 
wininit.exe               Vista background service launcher                         
dwm.exe                   Vista Desktop Window Manager                              
vmnetdhcp.exe             VMnet DHCP service                                        
vmware-authd.exe          VMWare Authentication Module                              
vmnat.exe                 VMware NAT Service                                        
WUDFHost.exe              Windows Driver Foundation                                 
WUDFHost.exe              Windows Driver Foundation                                 
explorer.exe              Windows Explorer Shell                                    
services.exe              Windows Service Controller                                
wlanext.exe               Windows Wireless LAN Framework                            

[*] Module Complete
```

List only security related processes and save them to a file

```
PS C:\> Invoke-ProcessScan -Path security.csv
[*] Starting AV Scan

ProcessName  Description                
-----------  -----------                
cmdagent.exe !!! Comodo Firewall Pro !!!
system.exe   !!! LanAgent Monitoring !!!

[*] Data exported to security.csv
[*] Module Complete
```