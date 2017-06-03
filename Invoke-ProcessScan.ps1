function Invoke-ProcessScan
{
<#
.SYNOPSIS

Performs a series of lookups against a known database of descriptions for process executeable names that the EQGRP leaked.


Author: Vincent Yiu (@vysecurity)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Invoke-ProcessScan scans the list of running processes on the system and matches it back to a description as specified by the EQGRP Leak.
 
.PARAMETER SecurityOnly

Scan only for security related processes

.PARAMETER Path

Export a CSV to the following file path and name. (eg. C:\test.csv, local.csv)
 
.EXAMPLE

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

.Example

List only security related processes and save them to a file

PS C:\> Invoke-ProcessScan -Path security.csv
[*] Starting AV Scan

ProcessName  Description                
-----------  -----------                
cmdagent.exe !!! Comodo Firewall Pro !!!
system.exe   !!! LanAgent Monitoring !!!

[*] Data exported to security.csv
[*] Module Complete

  
.LINK

http://www.mdsec.co.uk

#>

    Param (
        [Parameter(Position = 0)]
        [Boolean]
        $SecurityOnly = $True,

        [Parameter(Position = 1)]
        [String]
        $Path = $null
    )


    
    Write-Output "[*] Starting Process Scan"

    if ($SecurityOnly){
        Write-Output "[*] Scanning for Security related processes only"
    }

    $processlist = Get-Process

    $processlist = $processlist | Select -Property ProcessName

    $badprocs = "-1269619923.exe:						??? Backdoor.W32.Bionet ???
0.exe:						??? Trojan.W32.MyTob ???
000stthk.exe:						Toshiba Hotkey Configuration
004.exe:						??? Trojan.W32.Randsom ???
005.exe:						??? Trojan.W32.Randsom ???
006.exe:						??? Trojan.W32.Randsom ???
007.exe:						??? Trojan.W32.Randsom ???
007ssinstall.exe:						007 Spy Software
008.exe:						??? Trojan.W32.Randsom ???
009.exe:						??? Trojan.W32.Randsom ???
00thotkey.exe:						Toshiba Keyboard Helper
01dopewars_update.exe:						??? Adware.W32.Cydoor ???
01logo.exe:						??? Downloader.W32.Swizzor ???
1.exe:						??? Trojan.W32.Tooso ???
1004270.exe:						??? Download.Adware ???
1054571.exe:						??? Downloader.W32.Intexp ???
123bar.exe:						??? Spyware.W32.123bar ???
123dl.exe:						??? Spyware.W32.123bar ???
123downloadsuk[1].exe:						123Mania Hijacker
123hiddensender.exe:						??? 123 Hidden Sender Spyware ???
12nail.exe:						??? ABetterInternet Spyware ???
12popup.exe:						12Ghosts Popup-Killer
13.exe:						??? Backdoor.W32.Prorat ???
153.exe:						??? Dialer.W32.153 ???
180.exe:						??? 180SearchAssistant Spyware ???
180ax.exe:						??? TROJ.ISTZONE.H Virus Trojan ???
180pack6480.exe:						??? 180Solutions Spyware ???
180sa.exe:						??? 180SearchAssistant Spyware ???
180sainstaller.exe:						??? 180SearchAssistant Spyware ???
180sainstalleradperform.exe:						180Solutions Zango
180sainstallernusac.exe:						180SearchAssistant
180sainstallersca.exe:						??? 180Solutions Spyware ???
180sainstallersilsais1.exe:						??? 180SearchAssistant Spyware ???
180stuninstaller.exe:						??? 180Solutions Spyware ???
1950.exe:						??? Adware.W32.SpySheriff ???
1cv7.exe:						Billing database software
1cv7s.exe:						1C v7 Enterprise Software
1cv8.exe:						1C v8 Enterprise Software
1xconfig.exe:						SCM MicroSystems Helper
2.exe:						??? Trojan.W32.Lineage ???
2.sfx.exe.exe:						??? Trojan.W32.Lineage ???
2005.exe:						??? Backdoor.W32.2005-exe ???
202_app13.exe:						??? Adware.W32.PacerD ???
2eq.exe:						??? Downloader.W32.Swizzor ???
2GISTrayNotifier.exe:						2GIS Tray Icon (Russian telecom mapping software)
2portalmon.exe:						2wSysTray
2search.exe:						??? 2Search Spyware ???
3.exe:						??? Downloader.W32.Agent ???
30.exe:						??? 180Solutions Spyware ???
33.exe:						??? Adware.W32.WinTools ???
34yf28fg.exe:						??? 180Solutions Spyware ???
360Amigo.exe:						360Amigo System Speedup
360leakfixer.exe:						!!! 360_Safe !!!
360rp.exe:						!!! 360 Antivirus !!!
360RP.exe:						!!! 360 Antivirus !!!
360rp.exe:						!!! 360 Antivirus !!!
360RP.exe:						!!! 360 Antivirus !!!
360Safe.exe:						!!! 360_Safe !!!
360safe.exe:						!!! 360_Safe !!!
360SD.exe:						!!! 360 Antivirus !!!
360sd.exe:						!!! 360 Antivirus !!!
360tray.exe:						!!! 360_Safe !!!
38.exe:						75175 Port Changer Port Changer
3capplnk.exe:						3capplnk
3cdminic.exe:						3cdminic
3cmcnkw.exe:						??? Unknown ???
3cmlnkw.exe:						3cmlnkw
3dClip.exe:						3D Clipboard
3deepctl.exe:						3Deep e-colour
3dfxman.exe:						??? Unknown ???
3dldemon.exe:						3DLabsHelperDemon
3dlman.exe:						3Dlabs Taskbar Display Manager
3dm2.exe:						3DM 2 Web Interface
3dxsrv.exe:						3DxWare Driver
3p_1.exe:						??? Spyware.W32.DyFuCA ???
44088711.exe:						??? Adware.W32.VirtualBouncer ???
470760544.jpg.exe:						??? Backdoor.W32.AimBot ???
4C0F.tmp:						??? W32/Sdbot.worm.gen.y ???
4C0F.tmp:						??? W32/Sdbot.worm.gen.y ???
50cent.exe:						??? Backdoor.W32.Rbot ???
5mrtg.exe:						MRTG Launcher
6010RMT.exe:						TV Card Remote Control Device Monitor
63mm.exe:						??? Adware.W32.DelFin ???
666.exe:						??? Trojan.W32.MyTob ???
713962.exe:						??? Adware.W32.ESyndicate ???
74BE16.EXE:						??? W32/Autorun.worm.ev ???
7a3ce975.exe:						??? Trojan.W32.AIMVision ???
7i24IISMonitor.exe:						IIS Monitor
7nail.exe:						??? ABetterInternet Spyware ???
7uqj7z9a.exe:						??? Adtomi Spyware ???
7WAY.EXE:						7Way Email Checker
8169DIAG.exe:						Realtek Diagnostics Utility
8nail.exe:						??? ABetterInternet Spyware ???
959AC.com:						??? W32/Sality.y - malware ???
[system process]:						System Idle Process
_avpm.exe:						Anti virus?
_koss.exe:						SIEMENS
_simpcmon.exe:						Siemens Simatic Net process
a.exe:						??? Potential Malware ???
a0011142.exe:						??? Adware.W32.VirtualBouncer ???
a006.exe:						??? Adware.W32.Claria ???
a0067423.exe:						??? Adware.W32.Claria ???
a0067428.exe:						??? Adware.W32.Claria ???
a4proxy.exe:						A4Proxy
a64sddd.exe:						??? Adware.W32.Network1 ???
a65d.exe:						??? Downloader.W32.Intexp ???
aagnmsvc.exe:						SIEMENS
AASUpdates.exe:						Alfa Active Services
aawservice.exe:						!!! Lavasoft Ad-Aware !!!
ab.exe:						Argentum Backup
abbyynewsreader.exe:						ABBYY Community Agent
abg-aceh.exe:						??? Trojan.W32.Boetac ???
aboard.exe:						Activboard Application
abonent.exe:						InterSystems MSM Workstation
abox.exe:						??? Spyware.W32.Abox ???
abrir_cartao.exe:						??? Dialer.W32.Downloader ???
abs.exe:						??? Trojan.Esteems.E ???
AbsoluteFTP.EXE:						Absolute FTP
absr.exe:						??? Backdoor.Autoupder Virus Virus Trojan ???
abyssws.exe:						AbyssWebServer
ACAAS.exe:						!!! AhnLab !!!
acad.exe:						AutoCAD 2009
ACAEGMgr.exe:						!!! AhnLab !!!
acaif.exe:						!!! AhnLab !!!
ACAIS.exe:						!!! AhnLab !!!
acbtnmgr_xxx.exe:						AcBtnMgr_Xxx
accagnt.exe:						AOL Computer Check-Up
accelerate.exe:						Accelerate
accelerometerST.exe:						HP Systemtray
access members area.exe:						??? Dialer.W32.GBDialer ???
access.exe:						??? Adware.InstantAccess Spyware ???
accoca.exe:						ActiveIdentity, credential Mngr
Account.exe:						Payvast Accounting System
accrdsub.exe:						ActiveIdentity, credential Mngr
acctmgr.exe:						!!! Symantec !!!
AcctMgr.exe:						!!! Symantec !!!
accwiz.exe:						Microsoft Accessibility Wizard Module
ACDSee11.exe:						ACDSee 11.0
ACDSee32.exe:						ACDSee Image Management Software
acespy331t.exe:						??? Ace Spy Spyware ???
acevents.exe:						ActiveIdentity, credential Mngr
aclient.exe:						!!! Altiris remote login client !!!
AClntUsr.EXE:						!!! Altiris Client !!!
aclservice.exe:						??? Trojan.Gurepirls ???
acmonitor_xxx.exe:						Jetsoft for Lexmark
acombo3d.exe:						Acombo3dmouse
aconti.exe:						??? aconti trojan ???
aconti.exe:						??? aconti trojan ???
acprfmgrsvc.exe:						Ac Profile Manager Service
acroaum.exe:						Adobe Acrobat Updater
acrobat elements.exe:						Adobe Acrobat Elements
Acrobat.exe:						Adobe Acrobat
acrobat.exe:						Adobe Acrobat
acrobat_sl.exe:						Adobe Acrobat Speed Launcher
acrodist.exe:						Adobe Acrobat Distiller
AcroRd32.exe:						Adobe Acroread
acrord32.exe:						Acrobat Reader
AcroRd32Info.exe:						Adobe Reader
acrotray.exe:						Acrobat Assistant
AcroTray.exe:						Adobe Acrobat Helper
ACS.exe:						??? Unknown ???
acs.exe:						Atheros Wireless LAN
ACS_ACSC_Logmaint.exe:						AP/ACS Switch Control
ACS_ALH_Exec.exe:						AP/ACS Switch Control
acs_alog_bufman.exe:						AP/ACS Switch Control
acs_alog_main.exe:						AP/ACS Switch Control
acs_alog_seclog.exe:						AP/ACS Switch Control
acs_alog_sysmon.exe:						AP/ACS Switch Control
ACS_CHB_ClockSyncService.exe:						AP/ACS Switch Control
ACS_CHB_HeartBeat.exe:						AP/ACS Switch Control
ACS_CHB_HeartBeatChild.exe:						AP/ACS Switch Control
acs_dsdaemon.exe:						AP/ACS Switch Control
acs_emf_server.exe:						AP/ACS Switch Control
ACS_FCH_Server.exe:						AP/ACS Switch Control
ACS_FCR_Server.exe:						AP/ACS Switch Control
ACS_MSD_service.exe:						AP/ACS Switch Control
ACS_MSD_service.exe:						AP/ACS Switch Control
acs_nsf_server.exe:						AP/ACS Switch Control
ACS_PRC_ClusterControl.exe:						AP/ACS Switch Control
ACS_PRC_EventAnalyser.exe:						AP/ACS Switch Control
ACS_PRC_IspService.exe:						AP/ACS Switch Control
ACS_RTR_service.exe:						AP/ACS Switch Control
ACS_SFC_Recovery.exe:						AP/ACS Switch Control
ACS_SSU_Monitor.exe:						AP/ACS Switch Control
acs_ssu_monitor.exe:						AP/ACS Switch Control
ACS_USA_SyslogAnalyser.exe:						AP/ACS Switch Control
acsd.exe:						Aol Connectivity Service
ACSPostUnitSrv.exe:						Access Supervisory Controller
acsvc.exe:						Access Connections Main Service
act.exe:						Microsoft Application Center Test
actalert.exe:						??? DYFUCA.H Spyware ???
actionagent.exe:						Dell OpenManage Client Instrumentation
activation.exe:						activation
activeds.exe:						??? Adsrve Spyware ???
activeeyes.exe:						ActiveEyes
activemenu.exe:						??? ActiveMenu Spyware ???
activeplus.exe:						??? ActivePlus Spyware ???
activex_300_it.exe:						??? Downloader.W32.Small ???
activitydisk.exe:						SmartSoft ActivityDisk
actmovie.exe:						Microsoft Active Movie
actray.exe:						ThinkVantage access connections status icon
actserv.exe:						Radmin Activation Server
actualspy.exe:						??? spyware.w32.ActualSpy ???
actx1.exe:						??? Adware.W32.AdClicker ???
acu.exe:						Atheros Client Utility
acwlicon.exe:						ThinkVantage wireless status icon
ad-aware.exe:						??? Ad-aware Anti-Spyware ???
Ad-Aware2007.exe:						!!! Lavasoft Ad-Aware !!!
ad-watch.exe:						Ad-watch
Ad-Watch.exe:						Lavasoft Ad-Aware
ad.exe:						??? Adware.W32.sqwire ???
ad2kclient.exe:						AD2KClient
AD_Sync.exe:						Active Directory Synch
adaware.exe:						??? foobin lptt01 ???
adblck.exe:						??? BrowserPal Spyware ???
adblock.exe:						PC Power Suite
adblocker.exe:						3B Ad Blocker Pro
adbltzun.exe:						??? ABetterInternet Spyware ???
adc.exe:						XemiCo Active desktop calendar
addestroyer.exe:						??? AddDestroyer Spyware ???
addestroyerinner.exe:						??? Adware.W32.PacerD ???
addictivetech.exe:						??? Dialer.W32.Downloader ???
addrbook.exe:						addrbook
AddressExport.exe:						!!! 360_Safe !!!
adg.exe:						ADG
adgjdet.exe:						ADGJdet
adiras.exe:						ADSL USB Modem Helper
adl_dh.exe:						??? Adware.W32.DealHelper ???
adl_mteststub.exe:						??? Adware.W32.DelFin ???
adlinstallwin32.exe:						??? Adware.W32.AdLogix ???
admanctl.exe:						Admanager Controller
AdManCtl.exe:						??? Admanager Controller Spyware ???
admillikeep.exe:						??? Admilli Service Adware Spyware ???
admilliserv.exe:						??? Admilli Service Adware Spyware ???
admin.exe:						Microsoft Mail Admin Program
ADMIN.EXE:						Microsoft Mail Admin Program
Administrator.exe:						!!! Entensys UserGate 5 !!!
AdminServer.exe:						!!! Panda !!!
AdminW.exe:						CCMail Admin Program
admlib32.exe:						??? ADM Library Loader ???
admunch.exe:						Ad-Muncher
adobe gamma loader.exe:						Adobe Gamma Loader
Adobe_Updater.exe:						Adobe Updater
AdobeARM.exe:						Adobe ARM 1.0
adobedownloadmanager.exe:						Adobe Download Manager
adobelm_cleanup.0001:						Adobe Acrobat Cleanup Agent
adobelmsvc.exe:						Adobe System Level Service Utility
adobes.exe:						??? AdobeA ???
AdobeUpdateManager.exe:						Adobe Update Manager
adobeupdatemanager.exe:						Adobe Update Manager
adp.exe:						??? adp Spyware ???
adp8035.exe:						??? Adware.W32.BargainBuddy ???
adperform180safull.exe:						??? 180Solutions Spyware ???
adservice.exe:						Active Disk Service
adsetup.silent.1.13.exe:						??? Spyware.W32.BHO ???
adsgone.exe:						AdsGone
AdskCleanup.0001:						AutoCAD 2009
adskscsrv.exe:						Autodesk Licensing Service
adsl autoconnect.exe:						ADSL Autoconnect
adss.exe:						ADSS
adstatkeep.exe:						??? AdStatus Service Spyware ???
adstatserv.exe:						??? Adstat Internet Explorer Hijacker Spyware ???
adsub.exe:						AdSubtract
AdtAgent.exe:						Microsoft Audit Collection services
adtech2005.exe:						??? Adware.W32.Adtech ???
adtech2006.exe:						??? Trojan-Clicker.Win32.VB.kc ???
adtray.exe:						ADQuickAccess
ADTVScheduleAgent.exe:						TV Expert Publisher Schedule Agent
ADTVScheduleAgent.exe:						TV Expert Publisher Schedule Agent
adupdater.exe:						??? Adware.W32.AdLogix ???
adusermon.exe:						Active Disk User Monitor
adv.exe:						??? Adware.W32.BargainBuddy ???
Advanced-CPU-Load.exe:						Solarwinds tool
advapi.exe:						??? Advapi ???
advchk.exe:						Advanced Tools Check
adx.exe:						??? Adware.W32.BargainBuddy ???
AEADISRV.EXE:						Andrea Filters APO Access Service
aelaunch.exe:						AELaunch
aes_afp_server.exe:						AP/AES Switch Control
aes_cdh_server.exe:						AP/AES Switch Control
aes_dbo_server.exe:						AP/AES Switch Control
AESecurityService.exe:						MS Content Management Service
aestsrv.exe:						Andrea Filters APO Access Service
AeXAgentUIHost.exe:						!!! Altiris Agent !!!
aexnsagent.exe:						!!! Altiris Agent !!!
AeXNSAgent.exe:						!!! Altiris Agent !!!
AeXNSRcvSvc.exe:						!!! Altiris !!!
aexplore.exe:						AOL Explorer
aexsvc.exe:						!!! Altiris !!!
aexswdusr.exe:						!!! Altiris Express NS Client Manager !!!
afaagent.exe:						adaptec raid controller
afaagent.exe:						Adaptec SMBE Raid Controller
afcdpsrv.exe:						Acronis CDP
aflogvw.exe:						!!! AhnLab Spy Zero !!!
afwServ.exe:						!!! Avast Firewall Service !!!
agdbserver.exe:						HP OpenView
agent.exe:						Dell Agent
agentsrv.exe:						Replica Remote Server Files
AgentSVC.exe:						Citrix VM Server
agentsvr.exe:						Microsoft Agent Server
AGENTSVR.EXE:						Microsoft Agent Server
agfaclnk.exe:						AgfaCLnk
agntsrvc.exe:						Oracle process
agntsvc.exe:						Oracle process
agquickp.exe:						ActivCard Gold
agrsmmsg.exe:						Agere Systems Software Modem Driver
AGRSMMSG.exe:						Agere Systems Software Modem Driver
agrsmsvc.exe:						Agere Soft Modem Call Progress Service
agsatellite.exe:						AGSatellite
agtnt.exe:						Axent Intruder Alert?
agtrep.exe:						HP OpenView
agtserv.exe:						Atomica Online Service
AgtServ.exe:						Atomica Online Service
ahadp.exe:						??? Adware.W32.BargainBuddy ???
ahfp.exe:						Advanced Hide Folders
ahnrpt.exe:						!!! AhnLab Spy Zero !!!
ahnsd.exe:						!!! AhnLab !!!
ahnsdsv.exe:						!!! AhnLab !!!
ahqinit.exe:						Soundblaster AHQInit
Ahqtb.exe:						SoundBlaster Audio HQ
AHQTB.EXE:						SoundBlaster Audio HQ
ahqtb.exe:						AudioHQ
aiepk.exe:						Another Internet Explorer Popup Killer
aiepk2.exe:						Another IE Popup Killer
AIM.EXE:						AOL Instant Messenger
aim.exe:						AOL Instant Messenger
aim6.exe:						AOL Service Libraries
aim95.exe:						AOL Instant Messenger
aimaol.exe:						??? aimaol lptt01 ???
aimingclick.exe:						AimingClick
AIMS_M~1.EXE:						ArcIMS Monitor
AIMS_T~1.EXE:						ArcIMS Monitor
airgcfg.exe:						d-link airplus g
airplus.exe:						WLAN Adapter Utility
airpluscfg.exe:						D-Link AirPlus Xtreme G Wireless LAN Monitor
airsvcu.exe:						Media Manager Indexer
ait:						AIT Advanced Intelligent Tape)
ajrpbi.exe:						??? Adware.W32.DealHelper ???
AKELPAD.EXE:						Total Commander
akiller.exe:						AKiller
al_ads~1.exe:						Active Defense Shield
alarm.app.exe:						Alarm Manager
AlarmApp.exe:						Alarmapp
alarmapp.exe:						Palm Desktop Alarm Application
alarmgen.exe:						HP OpenView
alarmhost.exe:						IS3 Satcom/Telecom Software
alarmwatcher.exe:						Synaptics cPad
alaunch.exe:						Acer Launch Tool
alcfdrtm.exe:						Realtek Audio Module
alchem.exe:						??? Adware.ClickAlchemy ???
Alchem.exe:						??? Adware.ClickAlchemy Spyware ???
alcmtr.exe:						Realtek Event Monitor
alcwzrd.exe:						RealTek Audio Driver Component
ALCWZRD.EXE:						RealTek Audio Driver Component
alcxmntr.exe:						AlcxMonitor
aldaemon.exe:						Avance Daemon Application
ALERT.EXE:						!!! CA eTrust Integrated Threat Management 8.1/CA Jinchen Kill !!!
alerter:						Windows Alerter Service
AlertingEngine.exe:						SolarWinds Orion
alertServer.exe:						Backup Exec 8.x Alert Server
alertserver.exe:						Backup Exec 7.x/8.x Alert Server
AlertSvc.exe:						!!! Symantec !!!
ALERTSVC.EXE:						!!! Symantec !!!
alertsvc.exe:						!!! Symantec !!!
alevir.exe:						??? Opaserv-A Worm ???
AlfaActiveServices.exe:						Alfa Active Services
alg.exe:						Application Layer Gateway Service
alg32.exe:						*** DISABLEVALOR ***
almappx.exe:						Siemens License Manager run script siemens.eps)
ALMon.exe:						!!! Sophos Anti-Virus !!!
almsrvx.exe:						Siemens Step7 process
almsrvx.exe:						Siemens WinCC process
AlmXpmgr.exe:						Siemens WinCC process
almxptray.exe:						almxptray
alogserv.exe:						!!! McAfee VirusScan Activity Log Server !!!
AlogServ.exe:						!!! McAfee VirusScan Activity Log Server !!!
alp2plib.exe:						??? Adware.W32.DelFin ???
alsvc.exe:						!!! Sophos Anti-Virus AutoUpdate !!!
ALsvc.exe:						!!! Sophos Anti-Virus AutoUpdate !!!
alt.exe:						ProcView
ALUNotify.exe:						!!! Symantec !!!
alunotify.exe:						!!! Symantec !!!
ALUpdate.exe:						!!! Sophos Anti-Virus AutoUpdate !!!
aluschedulersvc.exe:						!!! Symantec !!!
AluSchedulerSvc.exe:						!!! Symantec !!!
am32.exe:						Action Manager 32
ambroker.exe:						MCI GUI or Employer eServices
AMGRSRVC.EXE:						NAI Alert Manager
amgrsrvc.exe:						NAI Alert Manager
AmIMaple.exe:						Keyboard Layout Switcher
amoumain.exe:						Wireless mouse driver
amovie.ocx:						ActiveMovie Control
amp2pl.exe:						??? Adware.W32.P2PNetworking ???
amqhasmn.exe:						GTS diplomatic comms system
amqmsrvn.exe:						GTS diplomatic comms system
amqmtbrn.exe:						GTS diplomatic comms system
amqpcsea.exe:						GTS diplomatic comms system
amqrmppa.exe:						IBM WebSphere MQ
amqrrmfa.exe:						GTS diplomatic comms system
amqsvc.exe:						GTS diplomatic comms system
amqxssvn.exe:						GTS diplomatic comms system
amqzdmaa.exe:						IBM WebSphere MQ
amqzfuma.exe:						GTS diplomatic comms system
amqzlaa0.exe:						GTS diplomatic comms system
amqzllp0.exe:						GTS diplomatic comms system
amqzxma0.exe:						GTS diplomatic comms system
AMService.exe:						Force Computers GmbH AM Services
AmService.exe:						Force Computers GmbH AGM18 Cloner
amswmagt:						!!! CA eTrust Integrated Threat Management 8.1 !!!
anbmserv.exe:						Acer Empowering Manager
angelex.exe:						??? Adware.W32.BargainBuddy ???
anonantispyware.exe:						??? Anonymizer Anti-Spyware ???
anote.exe:						ActiveNote
ANS.exe:						SC Alarm Notification Service
ANSProxyServer.:						SC ANS Proxy Server
ANSProxyServer.exe:						Switch Commander Application
answers.exe:						1-Click Answers Client
anti_troj.exe:						??? Trojan.W32.Lodear ???
antiarp.exe:						!!! 360_Safe !!!
antiav.exe:						??? Rusty\@m Worm ???
antiav_exe.exe:						??? Trojan.Lodav.A/B Trojan ???
AntigenIMC.exe:						Microsoft Antigen for Exchange
AntigenInternet.exe:						Microsoft Antigen for Exchange
AntigenMonitor.exe:						Microsoft Antigen for Exchange
AntigenRealtime.exe:						Microsoft Antigen for Exchange
AntigenService.exe:						Microsoft Antigen for Exchange
AntigenStore.exe:						Microsoft Antigen for Exchange
antirelay.exe:						AntiRelay antispam program
antispy.exe:						??? Adware.W32.VirtualBouncer ???
antivirus update.exe:						??? W32.Erkez.G\@mm Worm ???
antivirus32.exe:						??? Trojan.W32.Opanki ???
antivirusgold.exe:						??? Adware.W32.AntivirusGold ???
AntStatsServ.exe:						Microsoft Antigen for Exchange
AnVir.exe:						!!! AnVir.exe !!!
anvshell.exe:						ASUS Display Driver
anydvd.exe:						SlySoft AnyDVD
aocbhm.exe:						??? Adware.W32.DealHelper ???
aol.exe:						AOL.EXE Hoax
AOLacsd.exe:						AOL Connection Driver
aolacsd.exe:						AOL Connection Driver
aoldial.exe:						AOL Unassisted Dialler
AOLDial.exe:						AOL Unassisted Dialler
aolhos~1.exe:						AOL Host Manager
Aolnsrvr.exe:						Intel Server Manager
AOLServiceHost.exe:						AOL Service Host
aolservicehost.exe:						AOL Service Host
aolsoftware.exe:						AOL Service Libraries
aolsp scheduler.exe:						AOLSP Scheduler
aolspscheduler.exe:						??? AOL Spyware Protection ???
aolssc.exe:						AOL Service Libraries
aoltbServer.exe:						AOL toolbar
aoltpspd.exe:						AOL TopSpeed
aoltray.exe:						Aoltray
aoltsmon.exe:						AOL TopSpeed Component
aom.exe:						Adobe WebUpdater
aornum.exe:						??? Aornum Spyware ???
ap0.exe:						??? Backdoor.W32.bifrose ???
ap2.exe:						??? Backdoor.W32.bifrose ???
ap9h4qmo.exe:						??? ShopAtHomeSelect Spyware ???
AP_Mgr.exe:						Infosec Continent Client VPN
Apache.exe:						Apache Webserver
apache.exe:						Apache Webserver
apachemonitor.exe:						Apache HTTP Server
apcht2kw.exe:						Apache Web Server
apclclient.exe:						SC AutoPatch process
apclservice.exe:						SC AutoPatch Notification Service
apcommunication:						SC AutoPatch process
apcommunication.exe:						Switch Commander Application
apcsystray.exe:						APC PowerChute
apd123.exe:						??? Adware.W32.PacerD ???
apdproxy.exe:						Adobe Photoshop Album
apev.exe:						??? Adware.W32.Cashback ???
aphost.exe:						!!! TrendMicro Infrastructure !!!
api.exe:						Novell Groupwise?
apmediumscan.ex:						SC AutoPatch Medium Scan
apntex.exe:						Alps Pointing-device Driver
apoint.exe:						Alps Pointing-device Driver
app.exe:						??? Adware.W32.RapidBlaster ???
AppleMobileDeviceService.exe:						Apple Mobile Device Service
ApplicationUpdater.exe:						Application Updater
appmgr.exe:						Microsoft Application Manager
appservices.exe:						Appservices
appsetup.exe:						??? Downloader.W32.Small ???
APPSR1.EXE:						R-Style Application Server1
APPSRV.EXE:						R-Style Applicatin Server?
AppSvc32.exe:						!!! Symantec !!!
aps.exe:						!!! Outpost Security !!!
apsubjectcontro:						SC AutoPatch process
apsubjectcontrol.exe:						Switch Commander Application
apsvcae.exe:						BMC Remedy Action Request System
aptaskhandler.e:						SC AutoPatch Task Handler
aptaskhandler.exe:						Switch Commander Application
aptezbp.exe:						Aptezbp
apvxdwin.exe:						!!! Panda Internet Security !!!
aq3setupstandard.exe:						??? Adware.W32.Claria ???
aqadcup.exe:						??? Backdoor.Agent.bg ???
aqagent.exe:						Adaptec Application Quiesce Agent
aquariumdesktop.exe:						Stardock Aquarium Desktop
AquariumDesktop.exe:						Stardock Aquarium Desktop
aradmin.exe:						AR Remedy Ticket
ARCGIS.EXE:						ArcGIS Mapping Software
archive.exe:						??? BW-based Spyware ???
ArchService.exe:						IS3 Satcom/Telecom Software
arcmdbd.exe:						BMC Remedy Action Request System
arcpd.exe:						Adaptec SMBE Raid Controller
arcsas.exe:						SAS Raid Driver
aremaild.exe:						AR Remedy Ticket
ares.exe:						Ares Peer-to-peer File Sharing
arflashd.exe:						Remedy AR System (HelpDesk)
ARGUS.EXE:						Argus FIDONet Mailer?
armon32.exe:						Access Ramp Monitor
armon32a.exe:						AccessRamp Monitor
armonitor.exe:						BMC Remedy Action Request System
ARP.EXE:						ARP.EXE Adress resolution command
arplugin.exe:						BMC Remedy Action Request System
arpwrmsg.exe:						AlwaysReady Power Message APP
arr.exe:						??? Dialer.Lohan ???
arr.exe:						??? Dialer.Lohan ???
arr.exe:						??? Dialer.Lohan ???
arrecond.exe:						BMC Remedy Action Request System
arserver.exe:						Remedy ARServer
arservice.exe:						Media Center Away Mode Service
arsvcdsp.exe:						BMC Remedy Action Request System
arupdate.exe:						??? Adware.W32.AdRoar ???
ARUpdate.exe:						??? Adroar Spyware ???
arupld32.exe:						??? Arupld32 Spyware ???
aruser.exe:						Remedy AR System (HelpDesk)
as.exe:						Ascentive ActiveSpeed
ASA.exe:						Avaya Site Administration
AsAlert.exe:						BrightStor ARCserve Backup
ASC.EXE:						Access Supervisory Controller
ASCDBAgentSrv.exe:						Access Supervisory Controller
ASCPassSrv.exe:						Access Supervisory Controller
ASCPassTemplate.exe:						Access Supervisory Controller
ASCPhotoEditorS.exe:						Access Supervisory Controller
ASCReaderSrv.exe:						Access Supervisory Controller
ASCService.exe:						Access Supervisory Controller
ASCTieCheckerSr.exe:						Access Supervisory Controller
ASCWiperSrv.exe:						Access Supervisory Controller
asd.exe:						SC process
asdscsvc.exe:						ARCserveIT Discovery Service
ASDscSvc.exe:						ARCserveIT Discovery Service
asfagent.exe:						Intel Alert Standard Format Console
ASFAgent.exe:						Dell OpenManage software
asfpprov.exe:						Intel Server Manager
asfproxy.exe:						Intel Server Manager
asghost.exe:						Cognizance Identity and Access Management
ashAvast.exe:						!!! Avast !!!
ashBug.exe:						!!! Avast !!!
ashChest.exe:						!!! Avast !!!
ashCmd.exe:						!!! Avast !!!
ashdisp.exe:						!!! Avast !!!
ashDisp.exe:						!!! Avast !!!
ashDisp.exe:						!!! Avast !!!
ashEnhcd.exe:						!!! Avast !!!
ashLogV.exe:						!!! Avast !!!
ashmaisv.exe:						!!! Avast !!!
ashMaiSv.exe:						!!! Avast !!!
ashPopWz.exe:						!!! Avast !!!
ashQuick.exe:						!!! Avast !!!
ashserv.exe:						!!! Avast !!!
ashServ.exe:						!!! Avast !!!
ashSimp2.exe:						!!! Avast !!!
ashSimpl.exe:						!!! Avast !!!
ashSkPcc.exe:						!!! Avast !!!
ashSkPck.exe:						!!! Avast !!!
ashUpd.exe:						!!! Avast !!!
ashwebsv.exe:						!!! Avast !!!
ashWebSv.exe:						!!! Avast !!!
askernel.exe:						Aluria AntiVirus
asm.exe:						??? AltNet Spyware ???
ASMGR.exe:						ARCserve
asmonitor.exe:						??? Spyware.w32.ActualSpy ???
asmproserver.exe:						Adaptec Storage Manager Pro Server
ASMProServer.exe:						Adaptec Storage Manager Pro Server
aspi_me.exe:						Adaptec ASPI Driver
aspnet_admin.exe:						Microsoft ASP.NET Admin Service
aspnet_state.exe:						ASP State Service
aspnet_wp.exe:						Microsoft asp.net
ASPNET_WP.exe:						Microsoft asp.net
AsrSrvc.Exe:						AsrSrvc
asrsrvc.exe:						AsrSrvc
ASS.exe:						SC Alarm Storage Service
astart.exe:						ASUS TweakEnable
asupport.exe:						!!! TrendMicro !!!
asuskbservice.exe:						ASUS Keyboard Service
asusprob.exe:						ASUS Motherboard Probe
aswDisp.exe:						!!! Avast !!!
aswRegSvr.exe:						!!! Avast !!!
aswServ.exe:						!!! Avast !!!
aswupdsv.exe:						!!! Avast !!!
aswUpdsv.exe:						!!! Avast !!!
aswUpdSv.exe:						!!! Avast !!!
aswWebSv.exe:						!!! Avast !!!
ASYNC.EXE:						Microsoft Mail Connector?
at.exe:						AT.EXE NT Scheduling Command
atchk.exe:						Intel Management Technology Status Messages
atchksrv.exe:						Intel Management Technology System Status Service
Athan.exe:						Islamasoft Prayer Time Calculator and Reminder
athoc.exe:						\@hoc Browsing
ati2cwad.exe:						ATI Display Adapter Assistant
ati2cwxx.exe:						ATI Display Adapter Assistant
ati2evxx.exe:						ATI External Event Utility EXE Module
ati2mdxx.exe:						ATI Technologies Process
ati2plab.exe:						Ati2plab
ati2plxx.exe:						ATI Display Adapter Assistant
ati2ptxx.exe:						ATI Display Adapter Assistant
ati2s9ag.exe:						ATI Display Adapter Assistant
ati2sgag.exe:						ATI Display Adapter Assistant
aticwd32.exe:						Aticwd32
atidtct.exe:						ATI Device Detection Application
atieclxx.exe:						ATI Graphics Control Panel
atiesrxx.exe:						AMD External Events Utility
atievxx.exe:						ATI External Event Utility
ATIevxx.exe:						ATI External Event Utility
atipta.exe:						??? W32/Antinny-G Virus ???
atiptaab.exe:						ATI Utilitiy
atiptaxx.exe:						ATI Video Control Software
atirw.exe:						ATI Remote Wonder
atisched.exe:						ATI Video Player
atitask.exe:						ATI utility
atiupdate.exe:						??? Adtomi Spyware ???
atix10.exe:						ATI Remote Wonder Helper
atkkbservice.exe:						ASUS Keyboard Service
atkosd.exe:						ASUS ACPI Control Driver
atlcustom.exe:						??? Adware.W32.GoGoTools ???
atmclk.exe:						??? Adware.W32.SpyFalcon ???
atrack.exe:						Alert Tracker task
AtrsHost.exe:						!!! Altiris !!!
AtService.exe:						Fingerpint
AtSvc.Exe:						NT Scheduling Service
ATSVC.EXE:						NT Scheduling Service
atsvc.exe:						NT Scheduling Service
atwsctsk.exe:						!!! AhnLab V3 Internet Security !!!
atwtusb.exe:						Aiptek Graphics Tablet USB)
audevicemgr.exe:						Sony Ericsson Phone Connection Monitor
AudiDllHost.exe:						SC process
audiodg.exe:						Vista audio device graph isolation
audition.exe:						Adobe Audition
aufile~1.exe:						Teleca File Manager Server
aupdate.exe:						Automatic LiveUpdate
aupdate_uninstall.exe:						??? Adware.W32.RapidBlaster ???
aupdrun.exe:						!!! Agnirum Outpost Firewall !!!
aurareco.exe:						??? ABetterInternet Spyware ???
aurora(1).exe:						ABetterInternet Spyware
aurora-wise1.exe:						??? ABetterInternet Spyware ???
aurora.exe:						??? Aurora Spyware ???
aurora1).exe:						??? ABetterInternet Spyware ???
aus.exe:						!!! Outpost Security !!!
ause3-decoded.exe:						??? Spyware.W32.ClientMan ???
ause3.exe:						??? Spyware.W32.ClientMan ???
ausvc.exe:						??? Backdoor.Autoupder virus. Virus Trojan ???
Auth8021x.exe:						!!! CA Jinchen KILL / eTrust Antivirus !!!
authfw.exe:						Authentium Firewall SDK
authsrv.exe:						Internet Authentication Service IAS)
AUTHSRV.EXE:						Internet Authentication Service IAS)
autobar.exe:						HP Digital Imaging Helper
AutoCfg.exe:						Eudora AutoCfg Service
autochk.exe:						Autochk
autodown.exe:						AntiVirus AutoUpdater
autoexec.exe:						??? Downloader.W32.Haxdoor ???
autoheal.exe:						??? Adware.W32.BargainBuddy ???
autolaunch.exe:						Iomega HotBurn Pro
automove.exe:						??? 2nd Thought Spyware ???
AutoPowerOn.exe:						Auto Power-On & Shutdown 2.04
autoreg.exe:						US Robotics Registration
autorun.exe:						Autorun Executable
AutorunRemover.exe:						PC Optimizer
autotbar.exe:						HP AutoView Toolbar
autotkit.exe:						HP Helper Process
autoup.exe:						!!! AhnLab !!!
autoupdate.exe:						AT&T Hardware Autoupdate
autoupdatev2.exe:						??? Adware.W32.AdClicker ???
aux32.exe:						??? W32.Aizu.G Worm ???
av.exe:						??? W32/Alphx.worm.a ???
av_cleaner.exe:						Symantec Brightmail Antispam
avadmin.exe:						!!! AVIRA Personal Edition Classic !!!
avant.exe:						Avant Browser
AvastSvc.exe:						!!! Avast !!!
AvastUI.exe:						!!! Avast GUI !!!
avcenter.exe:						!!! Avira !!!
avcenter.exe:						!!! Avira !!!
avcmd.exe:						AntiVir Command Line Scanner for Windows
avconfig.exe:						!!! Avira !!!
avconfig.exe:						!!! Avira !!!
avconsol.exe:						!!! McAfee VirusScan Scheduler !!!
Avconsol.exe:						!!! McAfee VirusScan Scheduler !!!
avengine.exe:						!!! Panda Anti-Virus !!!
AVENGINE.exe:						!!! Panda Internet Security !!!
avEngine.exe:						!!! Avast !!!
AVerHIDReceiver.exe:						AVerMedia BDA TV Tuner
AVerQuick.exe:						AVerMedia BDA TV Tuner
AVerRemote.exe:						AVerMedia BDA TV Tuner
AVerScheduleService.exe:						AVerMedia BDA TV Tuner
avesvc.exe:						!!! Avira !!!
avesvc.exe:						!!! Avira !!!
AVExch32.exe:						Network Associates GroupShield Exchange
avfwsvc.exe:						!!! AVIRA Personal Edition Classic !!!
avgam.exe:						!!! AVG 8/8.5 !!!
avgamsvr.exe:						!!! AVG !!!
avgas.exe:						!!! AVG !!!
avgcc.exe:						!!! AVG !!!
avgcc32.exe:						!!! AVG !!!
AVGCHSVX.EXE:						!!! AVG Internet Security !!!
AVGCSRVX.EXE:						!!! AVG Internet Security !!!
avgcsrvx.exe:						!!! AVG 8.5 !!!
avgctrl.exe:						!!! AVG !!!
avgdiag.exe:						!!! AVG !!!
avgemc.exe:						!!! AVG !!!
avgfws8.exe:						!!! AVG !!!
avgfws9.exe:						!!! AVG 9.0 FW !!!
avgfwsrv.exe:						!!! AVG !!!
avghalsb.exe:						??? 180Solutions Spyware ???
AVGIDSAgent.exe:						!!! AVG 8.5/9.0 IDS !!!
AVGIDSMonitor.exe:						!!! AVG 8.5/9.0 IDS !!!
AVGIDSUI.exe:						!!! AVG 8.5 IDS !!!
AVGIDSWatcher.exe:						!!! AVG 8.5 IDS !!!
avginet.exe:						!!! AVG !!!
avgmsvr.exe:						!!! AVG !!!
avgnsx.exe:						!!! AVG 8/8.5 !!!
AVGNSX.EXE:						!!! AVG Internet Security !!!
avgnt.exe:						!!! Avira !!!
avgnt.exe:						!!! Avira !!!
avgregcl.exe:						!!! AVG Registry Cleaner !!!
avgrssvc.exe:						!!! AVG !!!
avgrsx.exe:						!!! AVG Anti-Virus !!!
avgscanx.exe:						!!! AVG !!!
avgserv.exe:						!!! AVG !!!
avgserv9.exe:						!!! AVG !!!
avgsystx.exe:						!!! AVG SysTools !!!
avgtray.exe:						!!! AVG Anti-Virus !!!
avguard.exe:						!!! Avira AntiVir !!!
avgupd.exe:						!!! AVG !!!
avgupdln.exe:						!!! AVG !!!
avgupsvc.exe:						!!! AVG !!!
avgupsvc.exe:						!!! AVG !!!
avgvv.exe:						!!! AVG !!!
avgw.exe:						!!! AVG !!!
avgw.exe:						!!! AVG !!!
avgwb.dat:						!!! AVG !!!
avgwdsvc.exe:						!!! AVG Anti-Virus !!!
avgwizfw.exe:						!!! AVG !!!
AVKProxy.exe:						!!! G Data Internet Security 2007 !!!
AVKService.exe:						!!! G Data Internet Security 2007 !!!
AVKTray.exe:						!!! G Data Internet Security 2007 !!!
AVKWCtl.exe:						!!! G Data Internet Security 2007 !!!
avltmain.exe:						!!! Panda Titanium !!!
avmailc.exe:						!!! Avira !!!
avmailc.exe:						!!! Avira !!!
avmcdlg.exe:						!!! Avira !!!
avmcdlg.exe:						!!! Avira !!!
AVMon32.exe:						GroupShield Monitor
avmserv.exe:						AltaVista Mail Server
avnotify.exe:						!!! Avira !!!
avnotify.exe:						!!! Avira !!!
avp.exe:						!!! Kaspersky !!!
AVP.exe:						!!! Kaspersky !!!
AVP.EXE:						!!! Kaspersky !!!
avpcc.exe:						!!! Kaspersky !!!
AVPDTAgt.exe:						!!! Kaspersky Lab Deployment Tool Agent !!!
avpexec.exe:						!!! Kaspersky !!!
avpm.exe:						!!! Kaspersky !!!
AvpM.exe:						!!! Kaspersky !!!
avpncc.exe:						!!! Kaspersky !!!
avps.exe:						!!! Kaspersky !!!
avps.exe:						!!! Kaspersky !!!
avpupd.exe:						!!! Kaspersky !!!
avrmtctr.exe:						VAIO Zone Remote Commander
avscan.exe:						!!! Avira !!!
avscan.exe:						!!! Avira !!!
avsched32.exe:						AVSCHED32
avserve.exe:						??? W32/Sasser.a ???
avserve2.exe:						??? W32.Sasser.B/C.Worm ???
avserver.exe:						!!! Kerio Winroute Firewall !!!
avshadow.exe:						!!! Avira !!!
Avsynmgr.exe:						!!! McAfee VirusScan Synchronization Manager !!!
avsynmgr.exe:						!!! McAfee VirusScan Synchronization Manager !!!
Avtask.exe:						!!! Panda !!!
avwebgrd.exe:						!!! AVIRA Personal Edition Classic !!!
avwupsrv.exe:						AntiVir Software Update Service for Windows
awe61.exe:						Possibly an ORACLE program
awhost32.exe:						pcAnywhere Host Service
AWHOST32.EXE:						pcAnywhere Host Service
awrem32.exe:						PCAnywhere Remote Control Module
awwvcfg.exe:						CA Unicenter Network & Systems Management
axlbridge.exe:						QuickBooks Module
axlbri~1.exe:						QuickBooks Module
b2search_v17.exe:						??? Spyware.W32.BHO ???
b9.exe:						Firetrust Benign
babylon.exe:						Babylon Translator
Babylon.exe:						Babylon Translator
backdoor.prorat.13.exe:						??? Backdoor.W32.Prorat ???
backdoor.prorat.13_(57).exe:						??? Backdoor.W32.Prorat ???
backdoor.prorat.13_57).exe:						??? Backdoor.W32.Prorat ???
backitup.exe:						Ahead Back It Up
BackItUp.exe:						Ahead Back It Up
BackLog.exe:						InterSect Alliance SNARE BackLog Service
BackupNetworkCoordinator.exe:						Novosoft Handy Backup
BackupNetworkWorkstation.exe:						Novosoft Handy Backup
backupnotify.exe:						HP Digital Imaging Component
backweb-137903.exe:						HP center
backweb-8876480.exe:						Logitech Desktop Messenger
backweb.exe:						Automatic Update Program
backWeb.exe:						??? Backweb Adware Spyware ???
BacsTray.exe:						Broadcom Advanced Control Suite
bacstray.exe:						Broadcom Advanced Control Suite
bagent.exe:						Quicken Scheduled Updates
BAMService.exe:						MSC BAM Services
Bandoo.exe:						Bandoo Toolbar
Bandwidth-Gauges.exe:						Solarwinds tool
banmanpro.exe:						??? Adware.W32.BanManPro ???
bargain3.exe:						??? Adware.W32.BargainBuddy ???
bargain4.exe:						??? Adware.W32.BargainBuddy ???
bargainbuddy.exe:						??? Adware.W32.BargainBuddy ???
bargains.exe:						??? Bargains Spyware ???
barsum.exe:						Reksoft Barsoom Billing
BarsumCollector.exe:						Reksoft Barsoom Billing
bartshel.exe:						BartShell Module
BAS-AS.exe:						Blackberry software
BAS-NCC.exe:						Blackberry software
bascstray.exe:						Advanced Control Suite Tray
basebrd.exe:						Intel Server Management
basfipm.exe:						!!! Broadcom ASF IP monitoring service !!!
bash.exe:						Cygwin Console
bass.exe:						??? Unknown ???
batserv2.exe:						??? Trojan.W32.LOCKSKY ???
bb.exe:						??? Backdoor.W32.Rbot ???
BBAttachMonitor.exe:						Blackberry software
BBAttachServer.exe:						BlackBerry software
bbchk.exe:						??? Adware.W32.BargainBuddy ???
BBConvert.exe:						BlackBerry software
BBConvert.exe:						BlackBerry software
BBConvert.exe:						BlackBerry software
BBConvert.exe:						BlackBerry software
bbdevmgr.exe:						RIM handheld device manager
bbgdfvdd.exe:						??? W32.Sober.V@mm ???
bbi8015.exe:						??? Adware.W32.BargainBuddy ???
bbi8018.exe:						??? Adware.W32.BargainBuddy ???
bbi8024.exe:						??? Adware.W32.BargainBuddy ???
bbi8032.exe:						??? Adware.W32.BargainBuddy ???
bblauncher.exe:						BounceBack
bbnt.exe:						Big Brother SNM Client
bboy.exe:						??? Kernel ???
bbui.exe:						AOL DSL Status Monitor
bcaaa-120.exe:						Blue Coat Authentication and Authorization Agent proxy
bcaaa-130.exe:						Blue Coat Authentication and Authorization Agent proxy
bcaaa.exe:						Blue Coat Authentication and Authorization Agent proxy
bcaaa_20.exe:						Blue Coat Authentication and Authorization Agent proxy
bcb.exe:						Borland C++ Builder
bcmntray.exe:						Broadcom Network Adapter Wireless Network Tray Applet
bcmsmmsg.exe:						BCMSMMSG
BcmSqlStartupSvc.exe:						Sql for Outlook 2007
bcmwltry.exe:						bcmwltry
BCResident.exe:						BC Wipe
bcresident.exe:						Jetico BestCrypt
Bct.exe:						SC Controller
Bctsched.exe:						SC Scheduler
bctstack.exe:						SC serial port server
BCU.exe:						DeviceVM Browser Configuration Utility
BCUService.exe:						DeviceVM Browser Configuration Utility
bcuyfz.exe:						??? Spyware.W32.DyFuCA ???
bcveserv.exe:						Jetico BestCrypt Volume Encryption
bdagent.exe:						!!! BitDefender Security Suite !!!
BDARemote.exe:						USB Video TV Device
bdc.exe:						!!! BitDefender Security Suite !!!
bdl14108.exe:						??? 2nd Thought Spyware ???
bdlite.exe:						!!! BitDefender Security Suite !!!
bdmcon.exe:						!!! BitDefender Security Suite !!!
bdmcon.exe:						!!! BitDefender Security Suite !!!
bdnagent.exe:						BitDefender News Agent
bdoesrv.exe:						Bitdefender 8 Anti-Virus
bdrqbac.exe:						??? Downloader.W32.Qoologic ???
bdss.exe:						!!! BitDefender Security Suite !!!
bdsubmit.exe:						!!! BitDefender Security Suite !!!
bdswitch.exe:						BitDefender Module
bearshare.exe:						BearShare
bedbg.exe:						Symantec Backup Exec
bedbg.exe:						Symantec Backup Exec
belt.exe:						??? searchv.com Spyware ???
benetns.exe:						Backup Exec 7.x/8.x Agent Browser
bengine.exe:						Backup Exec 7.x/8.x Job Engine
benser.exe:						Backup Exec 7.x/8.x Naming Service
berasjatah.exe:						??? Trojan.W32.RONTOKBRO ???
beremote.exe:						Backup Exec Component
BESAlert.exe:						BlackBerry software
beserver.exe:						Backup Exec 7.x/8.x Server
beta.exe:						??? W32/Mytob-BE Worm ???
bfedsx.exe:						SIEMENS
bfprojectsrvx.exe:						SIEMENS
bhodemon.exe:						Freeware BHO Detection Utility
bhp.exe:						??? 2nd Thought Spyware ???
bhsv.exe:						??? W32.Rbot-AVQ Trojan ???
bi5.exe:						??? Adware.W32.DelFin ???
bifrost.exe:						??? Adware.W32.ESyndicate ???
bigfix.exe:						BigFix
bigtra~1.exe:						??? Adware.W32.Begin2Search ???
billmind.exe:						Billminder
billminder:						Quicken Billminder
bindshell.exe:						??? Dialer.W32.Downloader ???
bionet.exe:						??? Backdoor.W32.Bionet ???
biprep.exe:						Browser Helper Object SpyWare
Biprep.exe:						??? Browser Helper Object Spyware ???
birytx.exe:						??? Adware.W32.BargainBuddy ???
bitcomet.exe:						BitTorrent Client
bitlord.exe:						BitLord Client
bittorrent.exe:						BitTorrent
bitview32.exe:						SNMPc Network Manager
bjcfd.exe:						BroadJump Foundation Client
bjfvabf.exe:						??? Adware.W32.PacerD ???
bjmcmng.exe:						Canon Memory Card Utility
BJMyPrt.exe:						Canon My Printer
bk.exe:						??? Adware.W32.SurfSideKick ???
bkupexec.exe:						Backup Exec
BlackBerryAgent.exe:						BlackBerry software
BlackBerryAgent.exe:						BlackBerry software
BlackBerryController.exe:						BlackBerry software
BlackBerryDispatcher.exe:						BlackBerry software
BlackBerryMailStoreSrvr.exe:						Blackberry software
BlackBerryPolicyServer.exe:						Blackberry software
BlackberryRouter.exe:						BlackBerry software
BlackBerrySyncServer.exe:						BlackBerry software
blackd.exe:						!!! BlackIce Firewall !!!
BLACKD.exe:						!!! Black Ice IDS !!!
blackice.exe:						!!! BlackIce Firewall !!!
blat.exe:						Blat Public Domain e-mail program
bldbubg.exe:						Dell Alerts Module
BlicToIPTVService.exe:						IPTV BlicToIPTV
BlitzIn2.exe:						Internet Chess Club Software
block-checker.exe:						??? AdClicker Adware ???
blocker.exe:						Ad Blocker
blocks.exe:						Game?
blss.exe:						??? blss trojan ???
blss.exe:						??? blss trojan ???
bluesoleil.exe:						BlueSoleil Bluetooth Plug and Play Module
bmagent.exe:						Symantec Brightmail Antispam
bman.exe:						??? Adware.W32.DealHelper ???
bmds.exe:						Blackberry BES Browser
bmmlref.exe:						IBM Thinkpad Battery Manager
bmrbd.exe:						Symantec Bare Metal Restore Process
bmrpxeserver.exe:						Symantec Bare Metal Restore Process
bmrt.exe:						!!! Barracuda Malware Removal Tool !!!
bmserver.exe:						Symantec Brightmail Antispam
bmss.exe:						Microsoft Bmonitor Session Manager
bmupdate.exe:						??? BookmarkExpress Spyware ???
bmwebcfg.exe:						Bytemobile Web Configurator
BoamLauncher.exe:						Switch Commander Application
bokja.exe:						??? Adware.SecondThought Spyware ???
bonjour.exe:						Bonjour
bookedspace.exe:						??? 2nd Thought Spyware ???
boot.exe:						??? BOOT ???
bootconf.exe:						??? Internat Conf Spyware ???
bot.exe:						??? Backdoor.W32.IROffer ???
bp.exe:						??? BrowserPal Spyware ???
bpbkar32.exe:						Symantec Netbackup
bpc.exe:						??? RVP Spyware ???
bpftp.exe:						BulletProof FTP
bpinetd.exe:						Veritas Netbackup Client
bpjava-msvc.exe:						Veritas Netbackup Client
bpk.exe:						!!! Blazing Tools Perfect Keylogger
bpk.exe:						!!! Blazing Tools Perfect Keylogger
bpk.exe:						!!! Blazing Tools Perfect Keylogger
bpsinstall.exe:						??? BrowserPal Spyware ???
bpumtray.exe:						BigPond Toolbar
brad32.exe:						Dr. Solomon Antivirus
BRAD32.EXE:						Dr. Solomon Antivirus
brasil.exe:						??? Brasil ???
brassd.exe:						Switch Commander Application
brctrcen.exe:						Control Center 2.0 Main Program
brengkolang.com:						??? Trojan.W32.RONTOKBRO ???
BrightStorMgr.exe:						CA BrightStor ARCserve Backup
brmecom.exe:						xBrotherMeCom
brmfcmon.exe:						Brother Status Monitor
brmfcwnd.exe:						Brother Status Monitor
brmfrmps.exe:						Brother Popup Suspend Service
brmfrsmg.exe:						Brother Resource Manager
BRMFRSMG.EXE:						Brother Resource Manager
bronstab.exe:						??? W32.Rontokbro.D\@mm Worm ???
brqikmon.exe:						Brother Traybar Utility
brss01a.exe:						Brother Print Processor
brstart.exe:						Cisco Works
brsvc01a.exe:						Brother Print Processor
BRSVC01A.EXE:						Brother Print Processor
bs5-lmzdgu.exe:						??? Adware.W32.BargainBuddy ???
bsclip.exe:						Bs CLiP UDF Reader/MRW Remapper
bsoft.exe:						??? Bsoft lppt01 ???
bthelpnotifier.exe:						BT Broadband Help Alerts
btntservice.exe:						IVT Corporation BlueSoleil Module
btprot.exe:						Windows Bluetooth Stack
btstac:						Bluetooth Stack COM Server
btstackserver.exe:						Bluetooth Stack COM Server
btstac~1:						Bluetooth Stack COM Server
BttnServ.exe:						Compaq EasyAccess Buttons Support
bttnserv.exe:						Compaq EasyAccess Buttons Support
bttray.exe:						Widcomms Bluetooth Tray Application
BTTRAY.exe:						Bluetooth Systray
btwdins.exe:						Microsoft Bluetooth Service
buddy.exe:						??? Adware.W32.BargainBuddy ???
Buddy.exe:						??? Solid Peer Spyware ???
bugsfix.exe:						Loveletter Virus
BUGSFIX.EXE:						??? Loveletter Virus Virus ???
BuhtaClient.exe:						Buhta Russian Financial/Admin Software
bundle.exe:						??? Adware.SAHAgent Spyware ???
bundleouter.exe:						??? Adware.W32.PacerD ???
bundleouter2501031120.exe:						??? Adware.W32.VirtualBouncer ???
bundleouter2601031121.exe:						??? 2nd Thought Spyware ???
bundlersi.exe:						??? Downloader.W32.IstBar ???
bundles.exe:						??? 2nd Thought Spyware ???
bundles118.exe:						??? 2nd Thought Spyware ???
bundles53.exe:						??? 2nd Thought Spyware ???
bundle~1.exe:						??? AdStatus Service Spyware ???
bvt.exe:						??? Backdoor.Autoupder virus Virus ???
bw2.exe:						??? Adware.W32.VirtualBouncer ???
bwgo0000:						!!! F-Secure Backweb Temporary Files !!!
BWMeterConSvc.exe:						!!! BWMeter Bandwidth Monitor !!!
bwprnmon.exe:						Bitware Client for FaxServe
Bwv.exe:						BackWeb component
bxnd52x.exe:						Broadcom NetXtreme Driver
bxproxy.exe:						??? Trojan.BXProxy.Process ???
c76bdcb6d01.exe:						??? Dialer.W32.intexusdial ???
ca.exe:						!!! eTrust Firewall !!!
CAAntiSpyware.exe:						!!! CA Internet Security Suite 2007 !!!
caauthd.exe:						CA BrightStor ARCserve Backup
caav.exe:						!!! CA Internet Security Suite 2007 !!!
caavcmdscan.exe:						!!! CA Internet Security Suite 2007 !!!
caavguiscan.exe:						!!! CA Internet Security Suite 2007 !!!
cache.exe:						InterSystems Cache Database
cachemanxp.exe:						CachemanXP - controls file cache and recovers RAM
cacheserver.exe:						BusinessObjects Enterprise 11.5
cadiscovd.exe:						CA BrightStor ARCserve Backup
caf.exe:						!!! CA eTrust Integrated Threat Management 8.1 !!!
cafw.exe:						!!! CA Internet Security Suite 2007 !!!
cagent.exe:						CAgent
cagent32.exe:						Centennial Discovery Client Agent
caissdt.exe:						!!! eTrust Internet Security Suite !!!
cal.exe:						Merak Mail SMTP Service
calc.exe:						Microsoft Calculator
calcheck.exe:						Calcheck
calcon.exe:						Microsoft Exchange Server
CalHelper.exe:						Blackberry software
calmain.exe:						Canon Camera Access Library
CALogDump.exe:						!!! CA Internet Security Suite 2007 !!!
caloggerd.exe:						CA BrightStor ARCserve Backup
cam.exe:						Unicenter Message Queuing
cameraassistant.exe:						Logitech QuickCam Assistant
CameraAssistant.exe:						Logitech QuickCam Assistant
CameraMonitor.exe:						Pixela ImageMixer
camviewer.exe:						??? Dialer.W32.Downloader ???
cap2lak.exe:						Canon Traybar Utility
CAP2LAK.EXE:						Canon Traybar Utility
CAP2RSK.EXE:						Canon Advanced Printing RPC Server Service
cap2rsk.exe:						Canon Advanced Printing RPC Server Service
CAP2SWK.EXE:						Canon Advanced Printing Printer Status Window
cap2swk.exe:						Canon Advanced Printing Printer Status Window
CAP3LAK.EXE:						Canon Advanced Printing Technology PSW Launcher
CAP3RSK.EXE:						Canon Printer Status Window
CAP3SWK.EXE:						Canon Printer Status Window
capabilitymanager.exe:						Sony Ericsson PC Suite
capfaem.exe:						!!! CA Internet Security Suite 2007 !!!
capfasem.exe:						!!! CA Internet Security Suite 2008 !!!
capfax.exe:						Capfax
capfsem.exe:						!!! CA Internet Security Suite 2007 !!!
capharm_unins.exe:						??? Adware.W32.Capharm ???
capiws.exe:						OpenVPN
capmuamagt.exe:						!!! CA eTrust Integrated Threat Management 8.1 !!!
CAPPActiveProtection.exe:						!!! CA Internet Security Suite 2007/8/9 !!!
CAPPActiveProtection.exe    :						!!! CA Internet Security Suite 2007 !!!
CAPPSWK.EXE:						Canon Advanced Printing Printer Status Window
CAPRPCSK.EXE:						Canon
card.exe:						??? Downloader.W32.Small ???
CardView.exe:						Modem Card Program?
carpserv.exe:						CARPService
cartao.exe:						??? Dialer.W32.Downloader ???
cas2setup.exe:						??? Adware.W32.CASClient ???
cas2stub.exe:						??? Adware.W32.CASClient ???
casc.exe:						!!! CA Internet Security Suite 2009 !!!
casclient.exe:						??? Adware.W32.CASClient ???
casdscsvc.exe:						Computer Associates BrightStor Discovery Service
casecuritycenter.exe:						!!! CA Internet Security Suite 2007 !!!
caserved.exe:						CA BrightStor ARCserve Backup
cashback.exe:						??? CashBack Spyware ???
cashsaver.exe:						??? Adware.W32.CashSaver ???
cashsaverupdate.exe:						??? Adware.W32.CashSaver ???
casmrtbk.exe:						BrightStor ARCserve Backup
CASMRTBK.EXE:						CA BrightStor ARCserve Backup
castore.exe:						GTS diplomatic comms system
Catirpc.exe:						BrightStor ARCserve Backup
CatTools_Client.exe:						Kiwi CatTools Network Management
CatTools_Service.exe:						Kiwi CatTools Network Management
Cau.exe:						Huawei iManager T2000 Element Management Software
caunst.exe:						!!! CA Internet Security Suite 2007 !!!
cavrep.exe:						!!! CA Internet Security Suite 2007 !!!
cavrid.exe:						!!! CA AntiVirus Realtime Infection Report !!!
cavscan.exe:						!!! Comodo !!!
cavtray.exe:						!!! eTrust Antivirus !!!
cb.exe:						??? Adware.W32.BargainBuddy ???
cbInterface.exe:						Cobian Backup
cbmain.ex:						BSS Cbank EDS Software
cbsrv.exe:						CacheBoost Component
cbsystray.exe:						Connected DataProtector  System Tray
CBWHost.exe:						Compaq Bitware Fax
cc.exe:						??? SQConfigChecker Spyware ???
CCAgent.exe:						Siemens WinCC Agent run script siemens.eps)
CCAP.EXE:						!!! Symantec !!!
ccap.exe:						!!! Symantec !!!
ccapp.exe:						!!! Symantec !!!
ccApp.exe:						!!! Symantec !!!
ccarss.exe:						??? Downloader.W32.IstBar ???
CCC.exe:						ATI Catalyst Control Center
cccredmgr.exe:						ClearCase component
cccredmgr.exe:						ClearCase
CCCT.exe:						Cisco AnyConnect VPN Client
ccemflsv.exe:						Client and Host Security Platform
CCenter.exe:						!!! Rising !!!
CCEServer.exe:						Siemens WinCC process run script siemens.eps)
ccevtmgr.exe:						!!! Symantec !!!
ccEvtMgr.exe:						!!! Symantec !!!
cclaw.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1 !!!
CClaw.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
ccmagent.exe:						CCM Desktop Agent Component
ccmexec.exe:						Microsoft SMS Agent Host
Ccmexec.exe:						Microsoft SMS Agent Host
CcmExec.exe:						Microsoft SMS Agent Host
ccnfagent.exe:						!!! CA eTrust Integrated Threat Management 8.1 !!!
cconnect.exe:						CorrectConnect
ccprovsp.exe:						!!! CA Internet Security Suite 2008/9 !!!
ccproxy.exe:						!!! Symantec !!!
ccProxy.exe:						!!! Symantec !!!
ccpwdsvc.exe:						Common Client Password Validation
ccpxysvc.exe:						!!! Symantec !!!
ccregvfy.exe:						Common Client Registry Integrity Verifier.
ccschedulersvc.exe:						!!! CA Internet Security Suite 2009 !!!
ccSetmgr.exe:						!!! Symantec !!!
ccsetmgr.exe:						!!! Symantec !!!
ccSetMgr.exe:						!!! Symantec !!!
ccsmagtd.exe:						!!! CA eTrust Integrated Threat Management 8.1 !!!
CCSRVC.exe:						Carbon Copy
ccSvcHst.exe:						!!! Symantec !!!
ccSvcHst.exe:						!!! Symantec !!!
ccsystemreport.exe:						!!! CA Internet Security Suite 2009 !!!
cctray.exe:						!!! CA Internet Security Suite 2007 !!!
ccucsurrotate.exe:						SIEMENS
ccupdate.exe:						!!! CA Internet Security Suite 2007 !!!
ccwin9.exe:						CorelCENTRAL
cd_install.exe:						??? Adware.W32.Cydoor ???
cd_install_202.exe:						??? Adware.W32.Cydoor ???
cd_install_291.exe:						??? Adware.W32.Cydoor ???
cd_load.exe:						??? Cydoor Desktop Media Spyware ???
cdac11ba.exe:						cdac11ba
cdaengine:						See
cdaEngine:						??? See ???
cdaengine0400:						see
cdaengine0500:						see
cdantsrv.exe:						CDANTSRV
cdf.exe:						??? BroadJump Client Foundation Spyware ???
CdfSvc.exe:						Citrix VM Server
cdmsvc.exe:						Citrix VM Server
cdnup.exe:						China Internet Information Center CNNIC) LiveUpdate Module
cdplayer.exe:						Microsoft CD Player
cdproxyserv.exe:						Sony-Bmg Album Background Process
cds.exe:						??? Backdoor.Spymon ???
cdspeed.exe:						Nero Toolkit
CEC_MAIN.exe:						Chicony Camera Assistant Software
ceekey.exe:						CeEKEY
ceepwrsvc.exe:						Toshiba Power Management
center.exe:						ASUS Control Center
cepmtray.exe:						Toshiba Power Management
CertificationManagerServiceNT.exe:						!!! Sophos Control Center !!!
certsrv.exe:						Certificate Server
CESConverter110NT.exe:						Coveo enterprise search
CESService370NT.exe:						Coveo enterprise serach
cfd.exe:						Motive Client Foundation
cfengine.exe:						Alt-N MDAEMON CFEngine
CFEngine.exe:						Alt-N MDAEMON CFEngine
cfexec.exe:						ColdFusion Executive
CFFiles.exe:						CryptoForge Encryption
cfftplugin.exe:						!!! CA eTrust Integrated Threat Management 8.1 !!!
cfgwiz.exe:						cfgwiz
cfmon.exe:						??? w32.Randex Variant ???
cfnotsrvd.exe:						!!! CA eTrust Integrated Threat Management 8.1 !!!
cfp.exe:						!!! Comodo Firewall Pro !!!
cfpconfg.exe:						!!! COMODO VIRUS SCANNER !!!
cfpconfig.exe:						!!! Comodo Firewall Pro !!!
cfplogvw.exe:						!!! Comodo Firewall Pro !!!
cfpsbmit.exe:						!!! Comodo Firewall Pro !!!
cfpupdat.exe:						!!! Comodo Firewall Pro !!!
cfrdsservice.ex:						ColdFusion RDS
cfserver.exe:						ColdFusion Application Server
cfsmsmd.exe:						!!! CA eTrust Integrated Threat Management 8.1 !!!
cfsserv.exe:						Toshiba ConfigFree
cfsvcs.exe:						Toshiba ConfigFree
cftmon.exe:						Microsoft Windows Operating System
CFUS15.EXE:						Allaire Cold Fusion
cfxfer.exe:						Toshiba ConfigFree
cg.exe:						??? Adware.W32.DelFin ???
CGServer.exe:						ComuniGate Messaging Server
CGStarter.exe:						ComuniGate Messaging Server
cgtask.exe:						??? Cgtask Services ???
charmap.exe:						Microsoft Windows Character Map
ChatSpace.exe:						ChatSpace server
check.exe:						??? Adware.W32.GoGoTools ???
checker.exe:						WashAndGo
checkreg.exe:						??? Trojan.Danmec ???
checkup.exe:						!!! Symantec !!!
ChessProgram9.exe:						1C Junior10 Chess Program
chkadmin.exe:						CHKADMIN
chkcolor.exe:						Creative SBAudigy
chkdskw.exe:						??? W32.Monikey\@mm Worm ???
chkntsv.exe:						??? Trojan.W32.Sufiage ???
chkras.exe:						??? NetZero Spyware ???
choke.exe:						??? choke ???
chq7gv5g.exe:						??? Adtomi Spyware ???
chrome.exe:						Chrome Browser
CHROME.EXE:						Google Chrome
cidaemon.exe:						Microsoft Indexing Service
cij3p2ps.exe:						LXP2PS MFC Application
cimlistener.exe:						IBM Systems Director
Cimntfy.exe:						HP Event Notifier
cimntfy.exe:						HP Event Notifier
cinetray.exe:						Sonic CinePlayer Traybar App
cirbisb_new_unicode.exe:						IRBIS Russian Dictionary/Catalog
CIRBISC_NEW_unicode.exe:						IRBIS Russian Dictionary/Catalog
Cisco-Config-Viewer.exe:						Solarwinds tool
CiscoRunVsStartup.exe:						Solarwinds tool
cissesrv.exe:						HP Smart Array Event Notification Service
cisvc.exe:						Microsoft Index Service Helper
cisvvc.exe:						??? Adware.W32.TrojanClicker ???
CITRIX.exe:						Citrix VM Server
Citrix_GTLicensingProv.exe:						Citrix VM Server
civil.exe:						??? Trojan.W32.Amirecivel ???
cjqxe.exe:						??? 180Solutions Spyware ???
cka.exe:						!!! Symantec !!!
ckusdll.exe:						??? Dialer.W32.Downloader ???
clamscan.exe:						!!! ClamAV !!!
ClamTray.exe:						!!! ClamAV !!!
ClamWin.exe:						!!! ClamAV !!!
clbcatex.exe:						??? Backdoor.W32.ZCrew ???
clcapsvc.exe:						CyberLink PowerCinema
cleanmgr.exe:						Disk Space Cleanup Manager
cleanup.exe:						CleanupProgram
clearquest.exe:						IBM ClearQuest
clearquest.exe:						ClearQuest
cledx.exe:						SyncroSoft POS
cli.exe:						ATI Catalyst
client.exe:						DigiGuide
client32.exe:						NetSupport Client Application
clipmate.exe:						ClipMate Clipboard Extender
clipsrv.exe:						Microsoft Clipboard-Server
clisvcl.exe:						SMS Client Service
clmanager.exe:						InterSystems Cache Database
CLNTRUST.EXE:						Novell BorderManager
clocksvc.exe:						*** PATROLWAGON ***
clockwise.exe:						ClockWise
clonecdtray.exe:						Elby CloneCD Tray Bar
CloneCDTray.exe:						Elby CloneCD Tray Bar
CLPS.exe:						!!! Comodo !!!
CLPSLA.exe:						!!! Comodo !!!
CLPSLS.exe:						!!! Comodo !!!
CLSBUPD.EXE:						Wclient108 Banking Software
ClShield.exe:						!!! Panda !!!
clussvc.exe:						Microsoft Cluster Services
cm.exe:						Possibly TrendMicro
cmanager.exe:						PC Manager
cmappsetup.exe:						??? Adware.W32.CASClient ???
cmappupdate.exe:						??? Adware.W32.CasinoClient ???
cmaudio:						Cm-Audio Module
cmd.exe:						+++ Windows Command Prompt +++
cmd32.exe:						??? CMD ???
cmdagent.exe:						!!! Comodo Firewall Pro !!!
cmdinst.exe:						??? Adware.W32.PacerD ???
cmdinstall.exe:						!!! Comodo !!!
CMESys.exe:						??? Adware.W32.Claria ???
cmesys.exe:						??? Gator GAIN Adware Spyware ???
cmeupd.exe:						??? Adware.W32.Claria ???
cmgrdian.exe:						!!! McAfee Guardian Tray Icon !!!
cmicnfg.cpl:						C-Media Control Panel Applet
cmisrv.exe:						Verizon Online DSL Connection Manager Interface
cmluc.exe:						ORiNOCO
cmman.exe:						??? Adware.W32.CasinoClient ???
cmmpu.exe:						cmmpu
cmqcemmpm.exe:						??? Adware.W32.Claria ???
cmrsr.exe:						??? Downloader.W32.Delf ???
cmrss.exe:						??? Downloader.W32.Delf ???
CMS.exe:						BusinessObjects Enterprise 11.5
cmsystem.exe:						CASClient adware variant
cmupd.exe:						??? Spyware.W32.ClientMan ???
CNAB4RPK.EXE:						Canon Advanced Printing
CNAB5RPK.EXE:						Canon
CNAB8SWK.EXE:						Canon
CNABASWK.EXE:						Canon
CNAP2LAK.EXE:						Canon
cnqmax.exe:						??? W32.Randex.P ???
CNTAoSMgr.exe:						!!! TrendMicro OfficeScan !!!
cnxdsltb.exe:						Conexant TaskBar Application
CnxMon.exe:						Wanadoo
cnyhkey.exe:						Chicony Electronics Multimedia Keyboard Hotkey Driver
Cobian.exe:						Cobian Backup
cocimanager.exe:						Logitech Camera Control Interface
coda.exe:						HP OpenView
Collectoragent.exe:						Fortinet Server Authentication
coloreal.exe:						Coloreal
Com4QLBEx.exe:						HP Quick Launch
comcomp.exe:						Kit de Connexion et de Services
comctl_32.exe:						??? Win32.Densmail Trojan Spyware ???
comctl_32.exe:						??? Win32.Densmail Trojan ???
comet.exe:						CC2KUI
comHost.exe:						!!! Symantec !!!
commagent.exe:						Spy Sweeper-Server
command.exe:						??? WinProfile ???
commando.exe:						??? WORM_FALSU.A Worm ???
CommonFileStore:						SCApplications Performance Data Collector
communications_helper.exe:						Logitech Communications Manager
communicator.exe:						MS Office Communicator
Companion.exe:						AOL Connection Suite
companion.exe:						AOL Connection Suite
compaq-rba.exe:						Compaq Message Server
ComproRemote.exe:						Compro Tech Video Mate TV Remote Control
ComproSchedulerDTV.exe:						Compro Tech Video Mate TV Remote Control
comsmd.exe:						3Com Tray Icon
conduit.exe:						Symantec Brightmail Antispam
conf.exe:						Microsoft Netmeeting
Config-Transfer.exe:						Solarwinds tool
config.exe:						Configuration Utility
Config_Download.exe:						Solarwinds tool
Config_Upload.exe:						Solarwinds tool
ConfRoom.exe:						Conference Room 1.5
conhost.exe:						Microsoft Console Windows Host
conime.exe:						Microsoft Console IME (multilanguage input)
conmgr.exe:						Internet Access Connection Manager
connmn~1.exe:						Symbian Connect ConnMngmntBox Module
ConquerCam.exe:						ConquerCam
conquercam.exe:						ConquerCam
conscorr.exe:						??? TrojanDownloader.Win32.Stubby.c ???
consol32.exe:						??? w32.Lamedon.G Trojan Virus Trojan ???
consol32.exe:						??? w32.Lamedon.G Trojan ???
Console.exe:						!!! Panda !!!
ContentReplicator.exe:						IS3 Satcom/Telecom Software
ContLogColl.exe:						Force Computers GmbH ContLC Service
control.exe:						Control Panel
Control.exe:						Control Panel
control_panel.exe:						!!! Entensys UserGate 5 !!!
cookiepatrol.exe:						Pest Patrol Cookie Patrol
cool.exe:						??? W32.HLLW.Donk.B ???
copernicdesktopsearch.exe:						Copernic Desktop Search
copy of optimize.exe:						??? Spyware.W32.DyFuCA ???
corecenter.exe:						FuzzyPWM MSI motherboard monitor
CorelDRW.exe:						CorelDRAW Graphics Suite 13
CoreShredder.exe:						HP File Sanitizer
corpstats.exe:						??? Trojan.W32.Randsom ???
counterspy.exe:						CounterSpy Client
CoverDesigner.exe:						Ahead Nero CD Cover Designer
coverdesigner.exe:						Ahead Nero CD Cover Designer
cp.exe:						??? Iambigbrother Spyware ???
cpanel.exe:						??? Iambigbrother Spyware ???
cpd.exe:						!!! McAfee Firewall !!!
CPDataCollector:						SCApplications Performance Data Collector
cpdclnt.exe:						!!! Symantec !!!
cpf.exe:						!!! Comodo Personal Firewall !!!
cpinit.exe:						CryptoPro CSP
cplbtq00.exe:						Compal  ATR10 Easy Button
CPntSrv.exe:						!!! Panda !!!
cpqa1000.exe:						Compaq A1000 Settings Utility
cpqdfwag.exe:						CPQDFWAG
cpqdmi.exe:						Compaq Management Agent
cpqeadm.exe:						Compaq Multimedia
CPQEADM.exe:						Compaq Multimedia
CpqEAKSystemTray.exe:						Compaq Easy Access Button Support
cpqeaksystemtray.exe:						Compaq Easy Access Button Support
cpqinet.exe:						CPQInet Runtime Service
CPQMGMT.EXE:						CQPMgmt Insight Agents
cpqmgmt.exe:						CQPMgmt Insight Agents
cpqnimgt.exe:						Compaq NIC Agents
CPQRCMC.EXE:						Compaq Remote Monitor Service
CpqRcmc.exe:						Compaq Remote Monitor Service
cpqrcmc.exe:						Compaq Remote Monitor Service
Cpqriis.exe:						HP ProLiant Rack Infrastructure Interface Service
cpqriis.exe:						HP ProLiant Rack Infrastructure Interface Service
cpqset.exe:						Hewlett Packard Configuration Module
Cpqset.exe:						Hewlett Packard Configuration Module
cpqteam.exe:						Compaq LAN teaming process
cpqwmgmt.exe:						Compaq Web Agents
cpr.exe:						??? Adware.W32.AdRoar ???
cprmcsp.exe:						CryptoPro CSP
cprmtkey.exe:						Dritek Multimedia HotKey Program
cpruninst.exe:						??? Adware.W32.AdRoar ???
cps_buap_filemgr.exe:						AP/CPS Switch Control
cps_buap_loader.exe:						AP/CPS Switch Control
cps_buap_parmgr.exe:						AP/CPS Switch Control
CPS_BUFTPD.exe:						AP/CPS Switch Control
cps_busrv.exe:						AP/CPS Switch Control
cpshelprunner.exe:						Roxio PhotoSuite
CpSvc.exe:						Citrix VM Server
cpunumber.exe:						Compaq Cpu number
cqmghost.exe:						Compaq Foundation Agents
cqmgserv.exe:						Compaq Server Agents
cqmgstor.exe:						Compaq Storage Agents
cr3.exe:						CoolReader E-Book Reader
crackserver-service.exe:						??? AdClicker Spyware ???
crashrep.exe:						!!! Comodo Firewall Pro !!!
crauto.exe:						Paragon Encrypted Disk
crdm.exe:						Netsys Enterprise Security (Encryption)
CReadSVC.exe:						Cisco Reader?
CReadSVC.EXE:						Cisco Reader?
createcd.exe:						Adaptec Easy CD Creator
createcd50.exe:						createcd50
creativelicensing.exe:						Creative Labs Licensing Service
crmlog.exe:						CiscoWorks
crmrsh.exe:						Cisco Works
crmtftp.exe:						Cisco Works
crons.exe:						Cron service
crossmenu.exe:						Toshiba CrossMenu
CRServices.exe:						Conference Room ?
crss.exe:						??? W32.AGOBOT.GH Worm Virus Trojan ???
crssrv.exe:						Content Replication System
crsss.exe:						??? W32.Rbot.mx Worm Virus Trojan ???
CRStatus.exe:						Conference Room ?
crypserv.exe:						CrypKey Software Licensing
crystalras.exe:						BusinessObjects Enterprise 11.5
csacontrol.exe:						!!! Cisco Security Agent !!!
csacontrol.exe:						!!! Cisco Security Agent 5.1 !!!
CSAdmin.exe:						CSAdmin
csagent.exe:						Copernic Summarizer
csaolldr.exe:						??? 2nd Thought  Spyware ???
CSAuth.exe:						CSAuth
CSController.exe:						Proventia Webfilter ISA
cscript.exe:						Microsoft Console Based Script Host
CSDbSync.exe:						CSDbSync
CSDBSync.exe:						CSDbSync
cservice.exe:						InterSystems Cache Database
csinject.exe:						!!! Symantec !!!
csinsm32.exe:						!!! Symantec !!!
csinsmnt.exe:						!!! Symantec !!!
CSLog.exe:						Cisco ACS
CSMon.exe:						CSMon
csmsv.exe:						??? W32.Looksky.B Trojan ???
CSRadius.exe:						Cisco ACS
csrdeu32.exe:						??? BKDR_BREPLIBOT.M Trojan ???
csrnvrt.exe:						??? Backdoor.W32.BREPIBOT ???
Csrrs.exe:						??? W32.Gaobot.AO Worm Virus Trojan ???
csrrs.exe:						??? W32.Gaobot.AO Worm ???
csrs.exe:						??? W32/Agobot Worm ???
csrsc.exe:						??? W32.Spybot.CF Virus Virus Trojan ???
csrse.exe:						??? Backdoor.Hesive.dr ???
csrss.exe:						Client-Server Runtime Server Subsystem
csrss32.exe:						??? W32.Agobot.JI Worm Virus Trojan ???
csrss_tc.exe:						!!! Atompark StaffCop !!!
cssauth.exe:						Client Security Solution
CSTacacs.exe:						CSTacacs
CStudio.exe:						InterSystems Cache Studio
csv5p070.exe:						??? 2nd Thought Spyware ???
csystray.exe:						InterSystems Cache Database
ct_load.exe:						??? CyDoor Spyware ???
ctbbserv.exe:						Dialogic Host Media Processing
ctbclick.exe:						??? CTB Click Spyware ???
ctcms.exe:						Creative MediaSource Go!
ctcmsgo.exe:						Creative MediaSource Go!
CTDataLoad.exe:						!!! Altiris !!!
ctdetect.exe:						Creative Soundblaster Removable Media Alerter
ctdvddet.exe:						CTDVDDet
cteaxspl.exe:						CTStartup
ctelnetd.exe:						InterSystems Cache Database
cterm.exe:						InterSystems Cache Studio
ctfmon.exe:						Microsoft Office XP - Alternative User Input Service
ctfmon32.exe:						??? CoolWebSearch Spyware ???
cthelper.exe:						Plug-in manager
CTLauncher.EXE:						Creative Labs SoundBlaster Launcher
ctlauncher.exe:						Creative SB Audigy Launcher
ctlcntr.exe:						IBM fingerprint Software
ctltask.exe:						Creative SB Audigy Taskbar
ctltray.exe:						Creative SB Audigy Traybar
ctmix32.exe:						Creative ShareDLL
CTMIX32.EXE:						Creative Labs Mixer
Ctmix32.exe:						Creative Labs Mixer
ctmodutl.exe:						Creative PowerSysTrayApp
ctnotify.exe:						Creative Technology Disc Detector
ctpdesrv.exe:						Personal Media Storage Server
ctplay2.exe:						Creative PlayCenter
ctpowuti.exe:						Creative PowerSysTrayApp Application
CtrITService.ex:						ControlIT
ctrlvol.exe:						VolumeMeter
ctsrreg.exe:						Creative Labs Registration Reminder
ctsvccda.exe:						Creative CD-ROM Services
ctsysvol.exe:						Creative Volume Manager
ctxcpusched.exe:						Citrix VM Server
ctxcpuusync.exe:						Citrix VM Server
ctxfihlp.exe:						Creative Audio Helper
ctxfireg.exe:						Creative Labs sound card driver
ctxfispi.exe:						Creative Audio Utility
CtxSFOSvc.exe:						Citrix VM Server
ctxwmisvc.exe:						Citrix VM Server
ctxxmlss.exe:						Citrix VM Server
cucu.exe:						??? Adware.W32.Cashback ???
cursorxp.exe:						Stardock CursorXP
curtainssyssvcnt.exe:						Curtains for Windows
cusrvc.exe:						Novell Client Update Service
cuteftp.exe:						Globalscape CuteFTP
cuteftppro.exe:						CuteFTP Professional
cutftp.exe:						Globalscape CuteFTP
CUTFTP32.EXE:						Cute FTP
Cvd.exe:						CrystalTech CommVault Backup
cvpnd.exe:						Cisco Systems
cvsservice.exe:						CVS Suite
CWB_ipmAgingSer:						Cisco Internetwork Performance Monitor
CWB_ipmAgingServ.exe:						Cisco Works
CWB_ipmConfigSe:						Cisco Internetwork Performance Monitor
CWB_ipmConfigServerd.exe:						Cisco Works
CWB_ipmData_col:						Cisco Internetwork Performance Monitor
CWB_ipmData_colld.exe:						Cisco Works
CWB_ipmDataView:						Cisco Internetwork Performance Monitor
CWB_ipmDataViewServer.exe:						Cisco Works
CWB_ipmDBServ.e:						Cisco Internetwork Performance Monitor
CWB_ipmDBServ.exe:						Cisco Internetwork Performance Monitor
CWB_ipmNameServ:						Cisco Internetwork Performance Monitor
CWB_ipmNameServ.exe:						Cisco Works
CWB_ipmPMServ.e:						Cisco Internetwork Performance Monitor
CWB_ipmPMServ.exe:						Cisco Works
CWB_ipmRTPServe:						Cisco Internetwork Performance Monitor
CWB_ipmRTPServer.exe:						Cisco Works
CWB_ipmSnmpd.ex:						Cisco Internetwork Performance Monitor
CWB_ipmSnmpd.exe:						Cisco Internetwork Performance Monitor
CWB_ipmStopper.:						Cisco Internetwork Performance Monitor
CWB_ipmStopper.exe:						Cisco Internetwork Performance Monitor
CWB_msgLogServe:						Cisco Internetwork Performance Monitor
CWB_msgLogServer.exe:						Cisco Works
cwjava.exe:						CiscoWorks Java
cxtpls.exe:						??? Apropos Media Spyware/Adware Spyware ???
cyb2k.exe:						CYBERsitter
cydoor.exe:						??? Adware.W32.Cydoor ???
cydoor_uninstall.exe:						??? Adware.W32.Cydoor ???
cygrunsrv.exe:						Cygwin Run as Service
cyxipjsxdua.exe:						??? ABetterInternet Spyware ???
cz.exe:						!!! Bropia Worm
cz.exe:						!!! Bropia Worm
cz.exe:						!!! Bropia Worm
czncin.exe:						??? Adware.W32.CashSaver ???
d.exe:						??? W32/Mytob-GH Trojan ???
D4.exe:						Dimension 4 Clock Adjuster
d4.exe:						Dimension 4
d6.exe:						??? Adware.W32.TVMediaDisplay ???
d98008w.exe:						??? Adware.W32.AntivirusGold ???
DACMON.exe:						Disk array controler driver
daconfig.exe:						3Com Diagnostic Console
dadapp.exe:						Dell AccessDirect Applet
dadqh.exe:						??? 180SearchAssistant Spyware ???
dadtray.exe:						Dell AccessDirect Tray
daemon.exe:						Daemon Tools
damon.exe:						Dell Support Damon
DAO_Log.exe:						!!! McAfee DAO Logger !!!
dap.exe:						DownLoad Accelator
data2.exe:						??? Trojan.W32.Randsom ???
data3.exe:						??? Trojan.W32.Randsom ???
data4.exe:						??? Trojan.W32.Randsom ???
Database-Maint.exe:						Solarwinds tool
datacollectorsvr.exe:						Huawei T2000 Element Mgmt Software
datala:						Nokia PC Suite DataLayer
datala~1.exe:						Nokia PC Suite DataLayer
Datalog.exe:						SC process
datalog.exe:						Windows Performance Monitor service)
DataMan.exe:						MSC BAM Services
DataMngrUI.exe:						Windows Searchqu Toolbar
datemanager.exe:						??? Date Manager Spyware ???
dating.exe:						??? Adware.W32.DelFin ???
davcdata.exe:						Microsoft HTTP-DAV common data
DavCData.exe:						Microsoft HTTP-DAV common data
db2jds.exe:						IBM Database
db2licd.exe:						IBM Database
db2sec.exe:						IBM Database
db2syscs.exe:						IBM DB2 database service
dbaccess.exe:						??? Dialer.W32.Dbaccess ???
dbasqlr.exe:						Computer Associates BrightStor Agent Backup Service
DBASVR.exe:						Backup Agent RPC Server?
dbeng.exe:						ARCserveIT Database Engine
DBENG.EXE:						ARCserveIT Database Engine
DBM.exe:						InterSystems MSM Workstation
dbmonitor.exe:						Monitor for MS SQL database servers
dbserv.exe:						!!! Symantec !!!
dbsnmp.exe:						Oracle process
DBSNMP.EXE:						Oracle Intelligent Agent
dbsrv7.exe:						Siemens Step7 process
dbsrv9.exe:						!!! Symantec !!!
dbwebsrv.exe:						dbWebService
dcevt32.exe:						Dell Openmange Event Monitor
dcfssvc.exe:						Kodak DC Direct Connection) File System Driver
dchuefy.exe:						??? Adware.W32.BargainBuddy ???
dcmobj.exe:						Dialogic Host Media Processing
dcnetmon.exe:						Dell software?
DCNSV.exe:						SC DCN monitor
dcnsv.exe:						SC DCN monitor
dcomcfg.exe:						??? Unknown ???
dcomx.exe:						??? Dcomx ???
DCServer.exe:						Huawei T2000 Element Mgmt Software
DCService.exe:						Huawei Datacard Service
dcstor32.exe:						Dell Openmanage Server Agent
ddcman.exe:						Wild Tangent Digital Distribution Channel Manager
DDHELP.EXE:						Direct Draw Help
ddhelp.exe:						Microsoft DirectDraw Helper
ddhelper32.exe:						??? ddhelper32 BDS/Sub7-220.Srv!) ???
DDWMon.exe:						TOSHIBA Direct Disc Writer
de_serv.exe:						AVM FRITZ!web Routing Service
dealhelper.exe:						??? Adware.W32.DealHelper ???
DeaSvc32.exe:						KlientBank Data Exchange Agent
deborah.exe:						??? Dialer.W32.Coulomb ???
defrag.exe:						Microsoft Disk Defragmenter Module
defscangui.exe:						??? WebScan Virus Spyware ???
Defwatch:						!!! Symantec !!!
DefWatch.exe:						!!! Symantec !!!
defwatch.exe:						!!! Symantec !!!
delayrun.exe:						Hewlett Packard Delay
delldmi.exe:						Dell DMI Service Provider
dellmmkb.exe:						DellTouch
DellVideoChat.exe:						Dell Video Chat
DellWMgr.exe:						Dell Webcam Manager
delmsbb.exe:						??? 180Solutions Spyware ???
deloeminfs.exe:						!!! BitDefender Security Suite !!!
deploy.exe:						SpyAnywhere
DeploymentAgent.exe:						Antigen Enterprise Manager Deployment Agent
desk98.exe:						ATI HydraVision Desktop Manager
deskadkeep.exe:						180 Search Assistant SpyWare
DeskAdKeep.exe:						??? 180Search Assistant Spyware ???
deskadserv.exe:						180 Search Assistant SpyWare
DeskAdServ.exe:						??? 180Search Assistant Spyware ???
desktop.exe:						??? Backdoor.SdBot.md Trojan ???
desktopmgr.exe:						Handheld Tools Desktop Manager
desktopsuite.exe:						Motorola Desktop Suite
deskup.exe:						Iomega refresh
devdetect.exe:						ACD Systems Device Detect
DevDetect.exe:						ACD Systems Device Detect
devenv.exe:						Microsoft Visual Studio
devldr.exe:						Creative Technology devldr.exe
devldr16.exe:						Devldr16
devldr32.exe:						Creative Labs Audio Support
devmapserver.exe:						Dialogic Host Media Processing
devsvc.exe:						InterVideo Capture Device Service
dexplore.exe:						Microsoft Visual Studio Combined Help
df5serv.exe:						Faronics Deep Freeze
df5serverservice.exe:						Deep Freeze
df_kme.exe:						??? ADW_FIXER.A Spyware ???
dfe.exe:						??? Adware.W32.WinFixer ???
dfrgfat.exe:						Diskeeper Disk Defragmenter
dfrgntfs.exe:						Windows Defrag
DFServ.exe:						Faronics DeepFreeze
Dfsr.exe:						Distributed File System Replication
DFSRS.exe:						Distributed File System Replication
dfsrs.exe:						Distributed File Server Replication Server
DFSRs.exe:						Distributed File System Replication Service
dfssvc.exe:						Distributed File System Service
Dfssvc.exe:						Distributed File System
DGBoard.exe:						Hitachi Starboard Application
dgprpsetup.exe:						??? Downloader.W32.Agent ???
dgrpencx.exe:						Digi RealPort encryption service
dhbrwsr.exe:						??? Adware.W32.DealHelper ???
DHCP-Scope-Monitor.exe:						Solarwinds tool
dho.exe:						??? Trojan.W32.Atomicks ???
dhsvr.exe:						??? Adware.W32.DealHelper ???
dhun.exe:						??? Adware.W32.DealHelper ???
dhupdt.exe:						??? Adware.W32.DealHelper ???
dhwin1.exe:						??? Downloader.W32.Delf ???
diagent.exe:						Creative Technology diagent.exe
diagorb.exe:						Dell Open Manage Tool
dial.exe:						??? Downloader.W32.Agent ???
dialer.exe:						Microsoft Phone Dialler
dialogic.exe:						Dialogic Host Media Processing
dic_istgah.exe:						khoshkar Dictionary
Dictionary.exe:						Websters Dictionary
diff.exe:						Solarwinds tool
DigitalBoardManager.exe:						Hitachi Starboard Application
digitv.exe:						Nebula DigiTV
digservices.exe:						ESPN RunTime
digstream.exe:						ESPN Motion
dinotify.exe:						Windows Device Installation
dinput.exe:						*** FRIENDLY TOOL - Seek Help ***
dinst.exe:						??? Downloader.W32.Intexp ???
dioxin.exe:						??? W32.Dinoxi Trojan ???
DIRECTCD.EXE:						Adaptec Direct CD
directcd.exe:						Roxio Easy CD/DVD Creator DirectCD Packet Writing
Directcd.exe:						Roxio Easy CD/DVD Creator DirectCD Packet Writing
directs.exe:						??? W32/Bagle.t@MM ???
directx.exe:						??? DirectX ???
directxset.exe:						??? Directxset ???
DisableInactiveUserAccounts.exe:						AP/ACS Switch Control
discagnt.exe:						HP Discovery Agent
discgui.exe:						Digital Interactive Systems User Interface
discstreamhub.exe:						DISCover Stream Hub
discusge.exe:						HP OpenView
DIServer.exe:						CiscoWorks
diskimageservice.exe:						Search and Recover 2
diskmon.exe:						!!! Symantec !!!
diskWatcher.exe:						Cisco Works
disp1150.exe:						??? Adware.W32.WebRebates ???
dispatch.exe:						Microsoft Exchange Server
dispatcher.exe:						IS3 Satcom/Telecom Software
display.exe:						??? Backdoor.W32.Iroffer ???
DisplayFusion.exe:						DisplayFusion
dist001.exe:						??? Adware.W32. ICanNews ???
dit.exe:						Drive Icon and Label Utility
ditexp.exe:						ICSI USB 2.0 reader
divx player.exe:						DivX Player
divx.exe:						??? Divx ???
djmypt800.exe:						??? Adware.W32.WebRebates ???
djsnetcn.exe:						!!! Symantec !!!
DjVuReader.exe:						DjVuReader Digital Document Reader
dkicon.exe:						Diskeeper Traybar
dkservice.exe:						Diskeeper
DKSERVICE.EXE:						Diskeeper
DKService.exe:						Diskeeper
DkService.exe:						Diskeeper
dla.exe:						Drive Letter Access
dlactrlw.exe:						Sonic Solutions Drive Letter Access DLA)
dlbabmgr.exe:						Dell AIO Printer
dlbabmon.exe:						AIO Button Monitor Executable
dlbcserv.exe:						Dell Photo Printer Helper
dlbfbmgr.exe:						Dell A960 All-In-One Printer
dlbkbmgr.exe:						Dell Printer Module
dlbkbmon.exe:						Dell Printer Module
dlbtbmgr.exe:						Dell Photo AIO Button Manager
dlbtbmon.exe:						Dell Photo AIO Helper
dlbubmgr.exe:						Dell Photo AIO Helper
dlg.exe:						Digital Line Detect
dlgc_srv.exe:						Dialogic Host Media Processing
dlgimrservice.exe:						Dialogic Host Media Processing
dlgli.exe:						??? Backweb installer Spyware ???
dlgsysmonitorserver.exe:						Dialogic Host Media Processing
dlgtimeslotdolerserver.exe:						Dialogic Host Media Processing
dlhost.exe:						??? Iambigbrother Spyware ???
dll32.exe:						??? Backdoor.W32.IROffer ???
dllcmd32.exe:						Dllcmd32
dllhost.exe:						Microsoft DCOM DLL Host Process
dllml.exe:						Creative DLL Module Loader
dllreg.exe:						??? Dumaru.c Virus Virus ???
dlomaintsvcu.exe:						Symantec Backup Manager
dlsdbnt.exe:						Dell Status Monitor Service
DLServer.exe:						DeviceLock Enterprise Service
DLService.exe:						!!! SmartLine DeviceLock Service !!!
dlt.exe:						Legacy Translator
DLTray.exe:						!!! SmartLine DeviceLock Tray Notifier !!!
DLTray.EXE:						!!! SmartLine DeviceLock !!!
dluca.exe:						??? DLUCA.C VIRUS! ???
dm1service.exe:						Olympus DeviceDetector
DM3Config.exe:						Dialogic Host Media Processing
dmadmin.exe:						Veritias LDM-Service Logical Disk Manager)
dmascheduler.exe:						DigitalMedia Plus Archiver
dmaster.exe:						Download Master
dmgr.exe:						??? Keystroke Logger  ???
dmgtd.exe:						Cisco Works
dmremote.exe:						Veritas Logical Disk Manager component
dmserver.exe:						??? Win32.Comet Spyware ???
DMWakeup.exe:						Panasonic Device Monitor
dmxlauncher.exe:						Dell Media Experience
dnar.exe:						Dell Dnar
dnetc.exe:						distributed.net client
DNS-Analyzer.exe:						Solarwinds tool
DNS-Audit.exe:						Solarwinds tool
dns.exe:						Microsoft DNS Server
dnscatcher.exe:						??? Adware.W32.Shorty.Gopher ???
dnscst.exe:						Dell Laser Printer Helper
DNTUS26.exe:						DameWare NT Utilities
dodrrr.exe:						??? W32.Secefa.A Trojan ???
DolphinCharge.e:						!!! GoldenDolphin Chinese IDS !!!
DolphinCharge.exe:						!!! GoldenDolphin Chinese IDS !!!
dolyt16.exe:						SpyAnywhere
dopus.exe:						Directory Opus
dos4gw.exe:						Microsoft DOS 32 bit extension
doscan.exe:						!!! Symantec !!!
dot1xcfg.exe:						Intel PROSet/wireless 802.1x server
dotnetfx.exe:						Microsoft Windows .Net Updater
doul.exe:						??? Dialer.W32.Agent ???
down.exe:						??? Hijacker.W32.Adlight ???
download.exe:						Webcelerator web browser
downloadplus.exe:						??? Download plus Spyware ???
dp-b23011805.exe:						??? Adware.W32.PromulGate ???
dp-him.exe:						??? Adware.W32.DealHelper ???
dp-k13w13.exe:						??? Adware.W32.DealHelper ???
dpagnt.exe:						DigitalPersona
dpcproxy.exe:						Intel Server Manager CLI
dpfusmgr.exe:						DigitalPersona
dphost.exe:						DigitalPersona
dpi.exe:						??? The DelFin Project
dpmapp.exe:						DPM Download/Configuration Module
DPMRA.exe:						Microsoft Security Center Data Protection Manager
dpmw32.exe:						??? Dpmw32 ???
dpps2.exe:						Dont Panic!
dptelog.exe:						Adaptec Storage Manager
dptserv.exe:						Adaptec Storage Manager
dpupdchk.exe:						Microsoft IntelliPoint
dpwinlct.exe:						DigitalPersona
dr.exe:						??? Dialer.W32.Downloader ???
dr_s.exe:						??? Downloader.W32.IstBar ???
dragdiag.exe:						Dragdiag
dragdrop.exe:						Dragn Drop CD+DVD
dreamweaver.exe:						Macromedia DreamWeaver
drgtodsc.exe:						Roxio DragTo Disc
DrgToDsc.exe:						Roxio DragTo Disc
drivecrypt.exe:						SecureStar DriveCrypt
drivespeed.exe:						Nero Toolkit
drmservice.exe:						Legato Networker Disaster Recovery Services
Dropbox.exe:						DropBox Desktop Client
drsd.exe:						*** FRIENDLY TOOL - Seek Help ***
drst.exe:						Dr SpeedTouch
drv.exe:						??? Backdoor.W32.Iroffer ???
drvddll.exe:						??? W32.BAGLE.AJ Worm Virus Trojan ???
DrvLsnr.exe:						Compaq SoundMAX integrated audio
drvlsnr.exe:						Compaq SoundMAX integrated audio
drvmgr.exe:						DrvMgr
drvmon.exe:						Drive Monitor
DRWAGNTD.EXE:						!!! DrWeb Enterprise !!!
drwagntd.exe:						!!! DrWeb Enterprise !!!
DRWAGNUI.EXE:						!!! DrWeb !!!
drwatsom.exe:						??? Hacker FTP Server ???
drwatsom.exe:						??? Hacker FTP Server ???
drwatson.exe:						+++ Dr. Watson +++
drwatson.exe:						+++ Dr. Watson +++
drweb.exe:						!!! DrWeb !!!
drweb32.exe:						!!! DrWeb !!!
DRWEB32W.EXE:						!!! DrWeb !!!
drweb32w.exe:						!!! DrWeb !!!
drweb386.exe:						!!! DrWeb !!!
drwebcgp.exe:						!!! DrWeb !!!
drwebcom.exe:						!!! DrWeb Plesk COM for Windows !!!
drwebdc.exe:						!!! DrWeb !!!
drwebmng.exe:						!!! DrWeb !!!
drwebscd.exe:						!!! DrWeb !!!
DRWEBSCD.EXE:						!!! DrWeb !!!
DRWEBUPW.EXE:						!!! DrWeb !!!
drwebupw.exe:						!!! DrWeb !!!
drwebwcl.exe:						!!! DrWeb !!!
drwebwin.exe:						!!! DrWeb !!!
DRWINST.EXE:						!!! DrWeb !!!
DRWTSN16.EXE:						??? w32.lovgate\@mm Worm Virus Trojan ???
drwtsn16.exe:						??? w32.lovgate\@mm Worm ???
DRWTSN32.EXE:						+++ Dr. Watson +++
drwtsn32.exe:						+++ Dr. Watson +++
DRWTSN32.EXE:						+++ Dr. Watson +++
drwtsn32.exe:						+++ Dr. Watson +++
drwupgrade.exe:						!!! DrWeb Enterprise !!!
ds.exe:						??? Backdoor.Spymon ???
ds_listener.exe:						BMC Patrol Asset Management)
ds_listener.exe:						BMC Listener Client
dsagent:						Dell Support AUAgent
dsagnt.exe:						Dell Support AUAgent
dsamain.exe:						Exchange Directory Service
DSAMAIN.EXE:						Exchange Directory Service
dsentry.exe:						Dell DVD Sentry
dseraser.exe:						Absolute Shield
DSES_TX.exe:						DSES USB thumb drive encryption
dsisrv.exe:						HP OpenView
dslagent.exe:						Eicon Communications Assistant
dslmon.exe:						Sagem DSL Modem Component
dslstat.exe:						ADSL Monitor
dsm_om_connsvc32.exe:						Dell Openmanage DSM SA Connection Services
dsm_om_shrsvc32.exe:						Dell Openmanage DSM SA Share Services
dsm_sa_connsvc32.exe:						Dell System Manage SA Connection Service
dsm_sa_datamgr32.exe:						Dell System Manage SA Data Manager
dsm_sa_eventmgr32.exe:						Dell System Manage SA Event Manager
dsm_sa_shrsvc32.exe:						Dell System Manage SA Shared Services
DSMain.exe:						!!! 360_Safe !!!
dsmain.exe:						!!! 360_Safe !!!
dsmcsvc.exe:						IBM Tivoli Storage Manager
dsnthapp.exe:						ATI Diamond MultiScreen hook loader
dsnthser.exe:						ATI Diamond MultiScreen hook device driver
dssagent.exe:						??? DSSAgent Spyware ???
DTIS_Q.exe:						GTS diplomatic comms chat system
DTLite.exe:						DAEMON Tools Lite
dtloader.exe:						??? Downloader.W32.IstBar ???
duc20.exe:						No-IP Dynamic IP Client
duel.exe:						??? Trojan.W32.Luder ???
dumeter.exe:						Hagel Technologies DU Meter
DUMeter.exe:						DU Bandwidth Meter
DUMeterSvc.exe:						DU Bandwidth Meter
dummy.exe:						Ahead Nero Temporary File
dump_arcsas.exe:						SAS RAID Driver
dumpcap.exe:						+++ Wireshark +++
dumprep.exe:						Dump Reporting Tool
Dumptimer.exe:						Richsoft Dumptimer
dun.exe:						??? Adware.W32.DealHelper.com ???
dvbern.exe:						??? Trojan.W32.Rontokbr ???
dvchost.exe:						??? AdClicker Spyware ???
dvd43_tray.exe:						Inline DVD Decryption engine
dvdaccess.exe:						Apple Computer DVD\@ccess
dvdkeyauth.exe:						??? G-data Dialer ???
dvdlauncher.exe:						CyberLink PowerCinema Resident Program
dvdramsv.exe:						DVD-RAM Utility Helper Service
DVDRegionFree.exe:						Fengtao DVD Region
dvdregionfree.exe:						Fengtao DVD Region
dvdtray.exe:						Hewlett-Packard DVD
dvldr32.exe:						??? Deloder ???
dvpapi.exe:						Authentium Antivirus
dvremind.exe:						Tobit InfoCenter Notifier
dvwnhd.exe:						??? Downloader.W32.IstBar ???
dvzincmsgr.exe:						DataViz Messenger
dvzmsgr.exe:						DataViz Messenger
dw.exe:						DownloadWare
DW20.EXE:						Windows Error Reporting
dw20.exe:						Office 2003 Error Reporting
dw[1].exe:						??? Adware.W32.DelFin ???
dwcg.exe:						??? Adware.W32.DelFin ???
dwe.exe:						??? Adware.W32.DelFin ???
dwengine.exe:						!!! DrWeb !!!
dwheartbeat.exe:						Weather Channel HeartBeat Monitor
DWHeartbeatMonitor.exe:						Weather.com module
dwheartbeatmonitor.exe:						Weather.com module
dwhwizrd.exe:						!!! Symantec !!!
DWHWizrd.exe:						!!! Symantec !!!
dwm.exe:						Vista Desktop Window Manager
dwnupdt.exe:						??? Downloader.W32.Small ???
dwrcs.exe:						Dwrcs
dwrcst.exe:						DameWare Tray Icon
DWRCST.EXE:						DameWare Remote Control Client
dwwin.exe:						!!! TrendMicro or DrWatson !!!
DXA.EXE:						Exchange Directory Synchronization Service
dxa.exe:						Exchange Directory Synchronization Service
dxdebugservice.exe:						DirectX Debug Service
DxDebugService.exe:						DirectX Debug Service
dxdiag.exe:						??? Feardoor Trojan ???
dxdllreg.exe:						Microsoft DXDllRegExe
dxenum.exe:						Ahead Nero Wave Editor
DXEnum.exe:						Ahead Nero Wave Editor
dxnf.exe:						??? 180Solutions Spyware Application Spyware ???
Dynamics.exe:						Microsoft GP
e-s0bic1.exe:						Epson Stylus C62 Series
e_a10ic2.exe:						EPSON Status Monitor 3
E_FATIAAP.EXE:						Epson Status
e_fatiaca.exe:						Epson Status Monitor
e_fatiaia.exe:						Epson Status Monitor
e_s00rp1.exe:						EPSON Status Monitor 3
e_s00rp2.exe:						EPSON Status Monitor 3
e_s0hic1.exe:						Epson Stylus C82 Series
e_s10ic1.exe:						EPSON Status Monitor 3
e_s10ic2.exe:						Epson Status Monitor
e_s10mt2.exe:						EPSON Status Monitor 3
e_s4i0f2.exe:						EPSON Status Monitor 3
e_s4i0h2.exe:						EPSON Status Monitor 3
e_s4i0p1.exe:						EPSON Status Monitor 3
e_s4i0t1.exe:						EPSON Status Monitor 3
e_s4i2f1.exe:						EPSON Status Monitor 3
e_s4i2g1.exe:						EPSON Status Monitor 3
e_s4i2h1.exe:						EPSON Status Monitor 3
e_s4i2j1.exe:						EPSON Status Monitor 3
e_s4i2k1.exe:						EPSON Status Monitor 3
e_s4i2l1.exe:						EPSON Status Monitor 3
e_s4i2m1.exe:						EPSON Status Monitor 3
e_s4i2p1.exe:						EPSON Status Monitor 3
e_s4i3f2.exe:						EPSON Status Monitor 3
e_srcv03.exe:						Epson Status Monitor
eabservr.exe:						eabconfg
eanthology.exe:						eAcceleration Software Station
EAPSigner161.exe:						Infosec Continent Client VPN
easy.windows.monitoring.exe:						??? Trojan.W32.Renama ???
easy.windows.monitoring.exe.exe:						??? Trojan.W32.MINUSIA ???
EasyAV.exe:						??? Win32.Netsky.S\@mm Worm Virus Trojan ???
easyav.exe:						??? Win32.Netsky.S\@mm Worm ???
easyclip.exe:						Lotus Organizer EasyClip
easygoback.exe:						UnH Solutions Easy Go Back
easynote.exe:						TK8 EasyNote
easyshare.exe:						Easy Share
EasyShare.exe:						Easy Share
EAUSBKBD.EXE:						Compaq USB keyboard
eausbkbd.exe:						Compaq USB keyboard
ebaytbdaemon.exe:						eBay Toolbar
ebrr.exe:						Epson Bi-directional Request Router EBRR)
ecfmserv.exe:						Symbian Connect
eclean.exe:						eClean 2000
ecodec.exe:						??? Trojan.W32.Emcodec ???
ecsrv.exe:						Eicon Cards
edd.exe:						LG Software System Control Manager
edict.exe:						Microsoft Encarta Dictionary Tools
edisk.exe:						!!! McAfee VirusScan Emergency Disk Creator !!!
edit server.exe:						??? Trojan.W32.AIMVision ???
Edit-Dictionaries.exe:						Solarwinds tool
EDLauncher.exe:						PROMT Machine Translation System
edlm2.exe:						??? Trojan.W32.Tabela ???
edonkey.exe:						edonkey
edow.exe:						??? Adware.W32.DealHelper ???
edow_as2.exe:						??? Adware.W32.WinTools ???
edowst3.exe:						??? Downloader.W32.QDown ???
ee.exe:						Evidence Eliminator
eebagent.exe:						Epson Status Agent
eEBSvc.exe:						Epson
eebsvc.exe:						EPSON Status Agent Service
eetu.exe:						??? PurityScan Adware ???
eeventmanager.exe:						Epson Creativity Suite
eeyeevnt.exe:						eEye Retina Digital Security
EFICStoPOINTCustInfo.exe:						Mobilink Billing Software
egui.exe:						!!! Nod32 !!!
ehmsas.exe:						Microsoft Media Center State Aggregator Service
ehrec.exe:						Microsoft Windows Media Center Recording Process
ehrecvr.exe:						Media Center Receiver Service
ehSched.exe:						Microsoft Media Center Scheduler Service
ehsched.exe:						Media Center Scheduler Service
ehshell.exe:						Microsoft Media Center Shell
ehtray.exe:						Microsoft Media Center Tray Icon
EHttpSrv.exe:						!!! Nod32 !!!
eie.exe:						BMC Atrium Integration Engine
eijk.exe:						??? Adware.W32.AntivirusGold ???
ekrn.exe:						!!! Nod32 !!!
eksplorasi.exe:						??? WORM_RONTOKBRO.Y Trojan ???
elbycheck.exe:						ElbyCheck
elccest.exe:						??? Solid Peer Spyware ???
elementmgr.exe:						Web Element Manager
elitejho32.exe:						??? Spyware.W32.ClientMan ???
elkctrl.exe:						Logitech Camera Module
elogerr.exe:						Symbian Connect
elogsvc.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
elos.exe:						??? Adware.W32.MediaAccess ???
elsblaunch.exe:						EarthLink SpamBlocker
elservice.exe:						IntelR) Quick Resume Technology driver
em40.exe:						Enterprise Monitor
EM9STA.exe:						System Tray for Winstron NeWeb wireless card
EM_EXEC.EXE:						Logitech Mouseware Driver
em_exec.exe:						Logitech Mouse Settings
emagent.exe:						Oracle Enterprise Manager
EMAILA~1.EXE:						Persist Software Email Agent
EmailProxy2.11.:						EmailProxy 2.11
EmailProxy2.12.:						Custom email proxy software
emaudsv.exe:						E-MU audio
EmfFaultDm.exe:						Huawei T2000 Element Mgmt Software
EmfSchdSvr.exe:						Huawei T2000 Element Mgmt Software
EmfSecuDm.exe:						Huawei T2000 Element Mgmt Software
EmfSysmoniDm.exe:						Huawei T2000 Element Mgmt Software
EmfTopoDm.exe:						Huawei T2000 Element Mgmt Software
eml.exe:						??? Trojan.W32.Beagle ???
Eml_monitomcat.exe:						Huawei T2000 Element Mgmt Software
Eml_PerfSvr.exe:						Huawei T2000 Element Mgmt Software
Eml_PubSvr.exe:						Huawei T2000 Element Mgmt Software
Eml_WebLCTSvr.exe:						Huawei T2000 Element Mgmt Software
EMLibUpdateAgentNT.exe:						!!! Sophos Control Center !!!
EMLPROUI.exe:						!!! Omniquad Total Security 3.0.0 !!!
EMLPROXY.exe:						!!! Omniquad Total Security 3.0.0 !!!
emqvdm.exe:						??? Adware.W32.Begin2Search ???
ems.exe:						Huawei iManager T2000 Element Management Software
emsmta.exe:						Microsoft Exchange Message Transfer Agent
EMSMTA.EXE:						Microsoft Exchange Message Transfer Agent
emsw.exe:						??? emsw Spyware ???
emule.exe:						eMule Component
enbiei.exe:						??? W32/Lovsan.worm ???
encmontr.exe:						Encompass Monitor
encsvc.exe:						Citrix Metaframe encryption service
EndPointSecurity.exe:						!!! GFI EndPointSecurity !!!
Energy Management.exe:						Lenovo Energy Management
energyplugin.exe:						??? Adware.W32.EnergyPlugin ???
EngineServer.exe:						!!! McAfee !!!
engineserver.exe:						!!! Mcafee !!!
engutil.exe:						EasyCD Creator 6.0 Component
EnhancedPing.exe:						Solarwinds tool
enigmapopupstop.exe:						Enigma Popup Stop
ENMClient.exe:						SC Client Service
ENMFSService.ex:						SC FS server
ENMFSService.exe:						Switch Commander Application
ENMLogArchive.e:						SC log archiver
ensmix32.exe:						ensmix32
ensoniqmixer:						Ensoniq Mixer
enternet.exe:						Connection manager
EntityMain.exe:						!!! Trend Micro Control Manager !!!
enuubwafo.exe:						??? Adware.W32.TVMediaDisplay ???
eouwiz.exe:						Intel ProSet Ease Of Use Wizard Application
epkb.exe:						180SearchAssistant spyware
epm-dm.exe:						Acer EPM Device Manager
epmworker.exe:						Ericsson PC Suite
epmwor~1.exe:						Sony Ericsson CAPI Worker Module
epswad4.exe:						??? Adware.W32.EpsWad4 ???
era.exe:						!!! ESET Remote Administrator !!!
eraser.exe:						Eraser
ERClient7.exe:						eRoom 7
errorguard.exe:						??? Adware.W32.ErrorGuard ???
ers.exe:						??? Trojan.W32.ErrorSafe ???
ersvc.exe:						??? Trojan.W32.Renama ???
esb.exe:						Easy Start Button Definition
escan.exe:						??? Downloader.W32.Evidence ???
esecagntservice.exe:						!!! GFI EndPoint Security !!!
esecservice.exe:						!!! GFI EndPointSecurity !!!
esmagent.exe:						!!! Enterprise Security Agent !!!
esmtp.exe:						??? Trojan.W32.Bagle ???
espacewanadoo.exe:						Kit de Connexion et de Services
essspk.exe:						Essspk
essvr.exe:						Gigabyte EasySaver
ESSVR.EXE:						Gigabyte EasySaver
esyndicateinst.exe:						??? Adware.W32.ESyndicate ???
etagent.exe:						!!! EventTracker by Prism Microsystems !!!
ETConsole3.exe:						!!! EventTracker Console !!!
ETCorrel.exe:						!!! EventTracker log cache !!!
eTCrtMng.exe:						E-token Certificate Manager
ethereal.exe:						+++ Ethereal +++
ethereal.exe:						+++ Ethereal +++
ETLogAnalyzer.exe:						!!! EventTracker by Prism Microsystems !!!
ETReporter.exe:						!!! EventTracker by Prism Microsystems !!!
ETRssFeeds.exe:						!!! EventTracker by Prism Microsystems !!!
EtScheduler.exe:						!!! EventTracker Scheduler !!!
eTSrv.exe:						Aladdin E-token notification
EtwControlPanel.exe:						!!! EventTracker Console !!!
eudora.exe:						Eudora Mail Client
euni_bbi8015.exe:						??? Adware.W32.BargainBuddy ???
EUQMonitor.exe:						!!! TrendMicro ScanMail for Exchange !!!
EUserman2.11.ex:						EUserman 2.11
EUserman2.12.ex:						Custom email monitoring software
eusexe.exe:						ICH Synth
EventParser.exe:						!!! McAfee !!!
events.exe:						Exchange Event Service
EVENTS.EXE:						Exchange Event Service
EventServer.exe:						BusinessObjects Enterprise 11.5
eventvwr.exe:						Event Viewer
EVENTVWR.EXE:						Event Viewer
EvMgrC.exe:						CrystalTech CommVault Backup
evntsvc.exe:						RealOne Player
evtarmgr.exe:						!!! EventTracker by Prism Microsystems !!!
evteng.exe:						Intel EvtEng Module
evtmgr.exe:						!!! EventTracker by Prism Microsystems !!!
evtProcessEcFile.exe:						!!! EventTracker , pops up and disappears !!!
ewerfw.exe:						??? Trojan.W32.BAGLE ???
ewidoctrl.exe:						Ewido Security Suite
ewidoguard.exe:						Ewido Security Suite
ExBPACmd.exe:						MS Exchange Best Practices Analyzer
excel.exe:						Microsoft Excel
Exchange.exe:						MSC BAM Services
exchng32.exe:						??? Gaobot Worm ???
exclean.exe:						??? Adware.W32.BargainBuddy ???
exdl.exe:						??? CashBackBuddy Spyware ???
exe82.exe:						??? MediaMotor Trojan ???
exec.exe:						??? W32/Spybot-Z Trojan ???
execstat.exe:						!!! StatWin !!!
EXMGMT.EXE:						Microsoft Exchange Console
exmgmt.exe:						Microsoft Exchange Console
exp.exe:						??? Trojan Application ???
expand.exe:						EXPAND.EXE Compression Utility
expl32.exe:						??? RATSOU virus Virus ???
explore.exe:						??? GRAYBIRD.G virus Virus ???
explored.exe:						??? W32/Nexiv.worm ???
exploreff.exe:						??? Trojan.Finfanse ???
explorer.exe:						Windows Explorer Shell
explorer32.exe:						??? W32/KWBot-A ???
explorere.exe:						??? W32.Yaha.x\@MM Virus Virus Trojan ???
express.exe:						MP3.com PLuS Express player
exshow95.exe:						Eexshow95
extravalue.exe:						??? Backdoor.W32.Adcliker ???
exul.exe:						??? Adware.W32.BargainBuddy ???
exul1.exe:						??? Adware.W32.BargainBuddy ???
Eye.exe:						IS3 Satcom/Telecom Software
ezbutton.exe:						EZbutton Media Player
ezejmnap.exe:						EasyEject Utility
ezinstall.exe:						??? Adware.W32.Cashback ???
ezinstall[1].exe:						??? Adware.W32.Ezula ???
ezpopstub.exe:						??? Adware.W32.Ezula ???
ezprint.exe:						Lexmark EZPrint
ezsp:						ezShieldProtector Application
ezsp_px.exe:						ezShieldProtector for Px
ezsp_pxengine.exe:						ezShieldProtector Engine
ezstub.exe:						??? Adware.W32.Ezula ???
ezstub22.exe:						??? Adware.W32.Ezula ???
ezstubseedcorn.exe:						??? Adware.W32. Ezula ???
ezulains.exe:						??? Adware.W32.Ezula ???
ezulumain.exe:						??? KaZaa Spyware ???
F1Server.exe:						GARANT.Platform F1 Application Server
F1Shell.run:						russian legal translation software
f3403484.exe:						??? Downloader.W32.Qoologic ???
f5r4bnh.exe:						??? Downloader.W32.IstBar ???
fahkpym.exe:						??? Downloader.W32.IstBar ???
fameh32.exe:						!!! F-Secure Alert and Management Extension Handler !!!
FAMEH32.exe:						!!! F-Secure Internet Security !!!
FamItrfc.exe:						Radmin
Famitrfc.Exe:						Rserver
fan.exe:						Fan
Far.exe:						File manager
farmmext.exe:						??? Transponder parasite componet Spyware ???
fash.exe:						IBIS Toolbar
Fash.exe:						??? IBIS Toolbar Spyware ???
fast.exe:						FastUsr
fast_monitor.exe:						IS3 Satcom/Telecom Software
fastdown.exe:						??? acocash ???
fasterxp.exe:						??? Adware.W32.FasterXP ???
fastobjectsserver.exe:						SIEMENS
FAXCTRL.exe:						RightFax Client
faxsvc.exe:						Faxdienst
fbdirect.exe:						Fbdirect
fbguard.exe:						Firebird SQL
fbserver.exe:						Firebird SQL
fc.exe:						??? CAMPURF virus Virus ???
FCACheck.exe:						Family Cyber Alert
FCDBLog.exe:						!!! FortiClient Host Security !!!
fcengine.exe:						CASClient adware variant
fch32.exe:						!!! F-Secure Configuration Handler !!!
FCH32.exe:						!!! F-Secure Internet Security !!!
FcsMs.exe:						Microsoft Forefront Client Security Management Service
fcsms.exe:						Microsoft Forefront Client Security Management Service
FcsSas.exe:						Microsoft Forefront Client Security State Assessment Service
fcssas.exe:						Microsoft Forefront Client Security State Assessment Service
fdhost.exe:						MSSQL Text search tool
fdlauncher.exe:						MSSQL Text search tool
fdm.exe:						Free Download Manager
FEPFramework.exe:						Hitachi Starboard Application
ffisearch.exe:						FFIsearch SpyWare
fgadmin.exe:						Netgear Print Server
fih32.exe:						!!! F-Secure Installation Launcher !!!
fileaccessmanager.exe:						WinBackup Open File Manager
filemon.exe:						+++ File Monitor +++
FileSyncService.exe:						Lumisoft Mail Server File Sync
FileZilla server.exe:						FileZilla
find.exe:						Grep-like command
finder.exe:						Microsoft Office Advanced Find Facility
FINDFAST.EXE:						Microsoft Office Helper Program
findfast.exe:						Microsoft Office Indexing
findstr.exe:						Grep-like Command
FineExec.exe:						ABBYY FineReader 10
FineReader.exe:						ABBYY FineReader 10
FINGER.EXE:						FINGER.EXE Command
fingrd32.exe:						IMail FINGER Server
finished.exe:						SpyAnywhere
fips.exe:						Dos Partition Manager
firedaemon.exe:						Firedaemon
firefox.exe:						Mozilla Firefox
firesvc.exe:						!!! McAfee Desktop Firewall !!!
FireSvc.exe:						!!! McAfee Desktop Firewall !!!
FireTray.exe:						!!! McAfee Desktop Firewall !!!
firetray.exe:						!!! McAfee Desktop Firewall Traybar Helper !!!
firewall.exe:						BitGuard Personal Firewall
FirewallGUI.exe:						!!! PC Tools Firewall Plus !!!
FISHES.SCR:						Windows Fish Screen Saver
fix[1].exe:						??? Backdoor.W32.Ciadoor ???
fixcamera.exe:						CameraFixed MFC Application
fixtitle.exe:						??? Spyware.W32.ClientMan ???
fjdbfvk.exe:						??? Downloader.W32.QDown ???
FJTWMKSV.exe:						Fujitsu printer/scanner software
FjtwMkup.exe:						Fujitsu printer/scanner software
FjtwSetup.exe:						Fujitsu printer/scanner software
flash.exe:						Microsoft HTML Help Workshop
flashfxp.exe:						FlashFXP
flashget.exe:						maybe a browser hijacker12popup.exe
Flashget3.exe:						Trend Media FlashGet Network
flashksk.exe:						DataCaching
flashtalk-wise1000.exe:						??? ABetterInternet Ceres Spyware ???
FlashUtil101_Plugin.exe:						Macromedia Flash
FlashUtil10e.exe:						Macromedia Flash
flatbed.exe:						PP3100b
flcss.exe:						??? Funlove Virus ???
floater.exe:						WinPortrait Pivot Pro
floomby.exe:						Floomby media sharing
FlushServ.exe:						American Megatrends FlushService
fm3032.exe:						Fax Center Server
fmctrl.exe:						Genius SM-Live Control Panel
fmon.exe:						!!! FortiClient Host Security 3.0.459 !!!
fms_cpf_server.exe:						AP/FMS Switch Control
fmstart.exe:						faxmaker client
FNPLicensingService.exe:						Macrovision FLEXnet Publisher
FNPLicensingService.exe:						Macrovision Shared FLEXnet Publisher
fnrb32.exe:						F-Secure Network Request Broker
fntldr.exe:						??? Adware.SearchCounter Spyware ???
Focus6.exe:						FocusRT Resource Planning
foldershare.exe:						Iomega FolderShare
FolderSizeSvc.exe:						FolderSize for Windows
fontloader.exe:						??? W32.Dinoxi.B Trojan ???
fontview.exe:						??? W32.OPASERV.T Virus Virus Trojan ???
FONTVIEW.EXE:						??? W32.OPASERV.T Virus Virus Trojan ???
foobar2000.exe:						Media Player
ForceField.exe:						!!! ZoneAlarm ForceField !!!
formatm.exe:						Conversions Plus
formulario.exe:						??? Dialer.W32.Downloader ???
forte.exe:						Computer game
fortifw.exe:						!!! FortiClient Host Security 3.0.459 !!!
FortiProxy.exe:						!!! FortiClient Host Security 3.0.459 !!!
FortiTray.exe:						!!! FortiClient Host Security 3.0.459 !!!
FortiWF.exe:						!!! FortiClient Host Security 3.0.459 !!!
FourEngine.exe :						ASUS Graphics
Foxmail.exe:						Email client
fpassist.exe:						FreePDF Assistant
FPAVServer.exe:						!!! F-PROT Antivirus !!!
FPCOUNT.EXE:						Front Page Tool
fpcount.exe:						Front Page Tool
fpdisp4.exe:						Fpdisp4
fpdisp5a.exe:						FinePrint Dispatcher
fpn16100.exe:						??? 2nd Thought Spyware ???
FpNotifier.exe:						Fingerprint Suite Notifier Application
fppdis1.exe:						FinePrint PDF Factory
fppdis2a.exe:						pdfFactory Component
FProtTray.exe:						!!! F-PROT Antivirus !!!
fpxpress.exe:						Microsoft Frontpage Express
fqc.exe:						??? Adware.W32.AdClicker ???
FrameworkServic:						!!! McAfee Framework Services !!!
frameworkservic.exe:						!!! Mcafee VirusScan Framework Service !!!
frameworkservice.exe:						!!! McAfee VirusScan Enterprise !!!
FrameworkService.exe:						!!! McAfee VirusScan Enterprise !!!
fran-hot.exe:						??? Adware.W32.PacerD ???
freecell.exe:						Microsoft Freecell
freedom.exe:						Freedom
FreeProxy.exe:						!!! Hand-Crafted Software FreeProxy !!!
freeram xp pro 1.40.exe:						YourWare Solutions FreeRAM
freeram xp pro.exe:						YourWare Solutions FreeRAM
freexxx.exe:						??? 180Solutions Spyware ???
frlog.exe:						Proventia Webfilter ISA
frontpage.exe:						Microsoft FrontPage
FRONTPG.EXE:						Front Page Web Page Administration
frontpg.exe:						Microsoft Front Page
frsk.exe:						??? FRSK Spyware ???
FrzState2k.exe:						Faronics DeepFreeze
fs20.exe:						Free Surfer Companion fsc)
FS3EXEC.EXE:						FailSafe III Power Monitor?
FS3SVC.EXE:						FailSafe III Power Monitor?
fsaa.exe:						!!! F-Secure Authentication Agent !!!
fsaua.exe:						!!! F-Secure Internet Security !!!
fsav32.exe:						!!! F-Secure Internet Security !!!
fsavgui.exe:						!!! F-Secure Internet Security GUI !!!
fsbwlan.exe:						F-Secure BackWeb LAN Access
fsbwsys.exe:						F-Secure BackWeb
FSCUIF.exe:						!!! F-Secure Internet Security !!!
fscuif.exe:						!!! F-Secure Internet Security !!!
fsdfwd.exe:						!!! F-Secure Internet Security !!!
fsecontentscanner.exe:						Antigen Signature Update
fservice.exe:						??? Backdoor.Prorat Trojan ???
fsg.exe:						??? Trickler Spyware ???
fsg_3202.exe:						??? Trickler Spyware ???
fsg_4104.exe:						??? Trickler Spyware ???
fsgk32.exe:						!!! F-Secure Internet Security !!!
fsgk32st.exe:						!!! F-Secure Internet Security !!!
fsguidll.exe:						!!! F-Secure Internet Security !!!
fsguiexe.exe:						!!! F-Secure Internet Security !!!
fshdll32.exe:						!!! F-Secure Internet Security !!!
FSHDLL32.exe:						!!! F-Secure Internet Security !!!
fshttps.exe:						F-Secure Parental Control HTTP Server
fsm32.exe:						!!! F-Secure Internet Security !!!
FSM32.exe:						!!! F-Secure Internet Security !!!
fsma32.exe:						!!! F-Secure Internet Security !!!
FSMA32.exe:						!!! F-Secure Internet Security !!!
fsmb32.exe:						!!! F-Secure Internet Security !!!
FSMB32.exe:						!!! F-Secure Internet Security !!!
fsorsp.exe:						!!! F-Secure Internet Security !!!
fspc.exe:						!!! F-Secure Internet Security !!!
fspex.exe:						!!! F-Secure Anti-Virus Updater !!!
fsproflt.exe:						FSPro Labs Filter Service
fsqh.exe:						!!! F-Secure Internet Security !!!
fsrremos.exe:						IBM Mouse Suite
fsscrctl.exe:						FSScrCtl
FSScrCtl.exe:						FSScrCtl
fsshd2.exe:						F-Secure SSH Server
fssm32.exe:						!!! F-Secure Internet Security !!!
fsssvc.exe:						Windows Live OneCare Family Safety Service
FsUsbExService.Exe:						Samsung MobileTop Service
fsw.exe:						??? Free Scratch And Win ???
fswsService.exe:						Easy File Sharing Web Server
ftamctrs.exe:						openFT FTAM server
FTErGuid.exe:						Fujitsu printer/scanner software
FtLnSOP.exe:						Fujitsu printer/scanner software
ftp-gw.exe:						Gauntlet FTP Proxy?
ftp.exe:						FTP.EXE File Transfer Program
FTP.EXE:						FTP.EXE File Transfer Program
ftplogsrv.exe:						Ipswitch FTP Log Server
FTPMan.exe:						MSC BAM Services
ftpte.exe:						CuteFTP Tranfer Engine
fts.exe:						Friendly Technologies Process
fullgames.exe:						??? Downloader.W32.PlayGames ???
funcade_icmediax_install.exe:						??? Adware.W32.Ezula ???
FUSServices.exe:						Xerox Companion Suite
fuwxenc.exe:						??? Dialer.W32.Downloader ???
fvprotect.exe:						??? W32/Netsky-P Virus Virus ???
FVProtect.exe:						??? W32/Netsky-P Virus Virus ???
FWatcher.exe:						Friendly Net Watcher
FwcAgent.exe:						ISA Firewall Client Agent
FWCfg.exe:						!!! Symantec !!!
FwcMgmt.exe:						Microsoft Firewall Client Management
fwenc.exe:						Check Point Secure Remote VPN client
fwinst.exe:						!!! AVIRA Personal Edition Classic !!!
fwntoolbar.exe:						??? Adware.W32.RapidBlaster ???
fws.exe:						Radialpoint Security Services PCGuard
fwsession.exe:						CheckPoint Session Authentication Agent 5.0
fxredir.exe:						fxredir
fxssvc.exe:						Microsoft Fax
fxsvr2.exe:						Logitech Multimedia Server
fxzrggu.exe:						??? Adware.W32.PurityScan ???
g-vga.exe:						Gigabyte video utility
g181511.a.stub.exe:						??? Adware.W32.DelFin ???
g2comm.exe:						Citrix GoToMyPC
g2pre.exe:						GoToMyPC Pre-Launcher plugin
g2svc.exe:						GoToMyPC Host Loader
g2tray.exe:						GoToMyPC Host Launcher
G6FTPTray.exe:						FTP Server
ga311.exe:						Netgear GA311 Adapter Configuration Utility
gah95on6.exe:						??? EliteBar Adware ???
gain_trickler_3102.exe:						??? Adware.W32.Claria ???
gain_trickler_3202.exe:						??? Adware.W32.Claria ???
Gamdrv.exe:						HP Global Array Manager
game.exe:						??? W32.Gaze\@mm worm ???
gamechannel.exe:						GameChannel WildTangent
gamedrvr.exe:						WildTangent Game Loader
GameDrvr.exe:						WildTangent Game Loader
GamerOSD.exe:						ASUS Skins audio/video upgrade
Gamevent.exe:						HP Global Array Manager
Gamevlog.exe:						HP Global Array Manager
gammatray.exe:						MagicTune Traybar Assistant
GAMSCM.exe:						Global Array Manager
GAMSERV.exe:						Global Array Server
Gateway.exe:						??? Adware.W32.MediaAccess ???
gateway.exe:						??? Adware.W32.MediaAccess ???
GatewayUI.exe:						Clarent VOIP Gateway User Interface
gatherer.exe:						AP/SGS Switch Control
gator.exe:						??? Gator Spyware ???
gatoroemres_gozilla_1825.exe:						??? Adware.W32.Claria ???
gatorstubsetup.exe:						??? Adware.W32.Claria ???
gatoruninstaller.exe:						??? Adware.W32.Claria ???
gauntlet.exe:						Gauntlet?
GauntletFailove:						Gauntlet Failover
GBMAgent.exe:						Genie-Soft Agent
gbpoll.exe:						GoBack Polling Service
GbpSv.exe:						G Buster Browser Defense
gbtray.exe:						Roxio GoBack Tray Icon
gcascleaner.exe:						!!! Microsoft AntiSpyware Cleaner Process !!!
gcasdtserv.exe:						!!! Microsoft AntiSpyware Server Process !!!
gcasinstallhelper.exe:						!!! Microsoft AntiSpyware Helper Process !!!
gcasnotice.exe:						!!! Microsoft AntiSpyware Notifier Process !!!
gcasserv.exe:						!!! Microsoft AntiSpyware Server Process !!!
gcasservalert.exe:						!!! Microsoft AntiSpyware Alert Process !!!
gcasswupdater.exe:						!!! Microsoft AntiSpyware Updater Process !!!
gcastdtserv.exe:						Microsoft Antispyware Data Service
gcc.exe:						LinkSys Wireless LAN Helper
gcIPtoHostQueue.exe:						??? Unknown ???
GDFirewallTray.exe:						!!! G Data Internet Security 2007 !!!
GDFwSvc.exe:						!!! G Data Internet Security 2007 !!!
gdonkey.exe:						Edonkey2000 Peer-to-peer tool
gear311t.exe:						Netgear Wireless Configuration Module
gear511.exe:						Netgear Wireless Configuration Module
gearsec.exe:						Gear CD/DVD Burning Software
GemServ.exe:						AMD Cool'n'Quiet
generic.exe:						Device Management
gesfm32.exe:						??? RANDEX.C ???
get.exe:						??? 2Search Spyware ???
getbuys.exe:						??? Spyware.W32.ClientMan ???
getflash.exe:						Macromedia Flash Player Updater
GetFlash.exe:						Macromedia Flash Player Updater
Getright.exe:						GetRight Monitor
getright.exe:						GetRight Monitor
gfireporterservice.exe:						!!! GFI EndPointSecurity !!!
gfxacc.exe:						??? GIBE VIRUS Virus Spyware ???
ghost.bat:						??? W32.Feldor.A WORM ???
GHOST32.exe:						Norton Ghost
ghost32.exe:						Norton Ghost
ghost_2.exe:						!!! Symantec !!!
ghostexp.exe:						Ghost Explorer
Ghostexp.exe:						Ghost Explorer
ghoststartservice.exe:						Ghost Start Service
GhostStartService.exe:						Ghost Start Service
GhoststarttrayA.exe:						Norton Ghost Tray Icon
GhostStartTrayApp.exe:						Norton Ghost 2003
GHOSTS~2.EXE:						Ghost Start Service
ghosts~2.exe:						Ghost Start Service
ghosttray.exe:						!!! Symantec !!!
giantantispywaremain.exe:						!!! Microsoft AntiSpyware !!!
giantantispywareupdater.exe:						!!! Microsoft AntiSpyware !!!
Gilautouc.exe:						LG Software Update
ginst_001_1234_4201.exe:						??? Adware.W32.Claria ???
gld.exe:						??? Backdoor.Zagaban ???
glf2fglf2f.exe:						??? Adware.W32.TargetSaver ???
glf56glf56.exe:						??? Adware.W32.TargetSaver ???
glf8dglf8d.exe:						??? Adware.W32.TargetSaver ???
GLOBAL.EXE:						Microsoft NTReskit Program
gm.exe:						??? 180Solutions Spyware ???
gmt.exe:						??? Gator Spyware Component Spyware ???
GMT.exe:						??? Gator Spyware Component Spyware ???
gnetmous.exe:						Genius NetScroll + Series Mouse
gnotify.exe:						GMail Notifier
Go.exe:						Gozilla Download Manager
go.exe:						Go!Zilla Monster Downloads
gogoaddisplay.exe:						??? Adware.W32.GoGoTools ???
gogoaddressbar.exe:						??? Adware.W32.GoGoTools ???
gogofileshare.exe:						??? Adware.W32.GoGoTools ???
gogotoolbar.exe:						??? Adware.W32.GoGoTools ???
gogotools.exe:						??? Adware.W32.GoGoTools ???
gogotools0.exe:						??? Adware.W32.GoGoTools ???
gogotoolsinstaller.exe:						??? Adware.W32.GoGoTools ???
goidr.exe:						??? Spyware.Goidr Spyware ???
GOLDLA~1.SCR:						Gold Lace Screen Saver
GoogleCrashHandler.exe:						Google Update
googledcc.exe:						Google Compute Toolbar Client
googledesktop.exe:						Google Desktop
GoogleDesktop.exe:						Google Desktop
googledesktopcrawl.exe:						Google Desktop Search
googledesktopdisplay.exe:						Google Desktop
googledesktopindex.exe:						Google Desktop Search
googledesktopoe.exe:						Google Desktop Search
googleearth.exe:						Google Earth
googlefah.exe:						Google Folding\@Home
googlefahcore_65.exe:						Google Folding\@Home
GoogleQuickSearchBox.exe:						Google Quick Search
googletalk.exe:						Google Talk Instant Messenger
googletalkplugin.exe:						Google Talk
GoogleToolbarNotifier.exe:						Google Toolbar for IE
GoogleToolbarUser_32.exe:						Google Toolbar
GoogleUpdate.exe:						Google Update
googleupdater.exe:						Google Updater
GoogleUpdaterService.exe:						Google Updater
googlewebaccclient.exe:						Google Web Accelerator
GOVsrv.exe:						PJ Technologies GoverLAN Agent
gozilla.exe:						GoZilla Download Administrator
gra.exe:						GRA
graph.exe:						Microsoft Office Graph Facility
GRED.exe:						InterSystems MSM Workstation
GROOVE.exe:						MS Office Groove Monitor
groove.exe:						MS office
groovemonitor.exe:						Microsoft Office 2007 Groove Monitor
GrooveMonitor.exe:						Microsoft Office 2007 Groove Monitor
grpconv.exe:						Windows Program Group Converter
grpwise.exe:						Novell Groupwise
GrpWise.exe:						Novell Groupwise
GS_Agnt.exe:						Georgia Softworks Windows SSH/Telnet Server
GS_Tnet.exe:						Georgia Softworks Telnet Server
gsicon.exe:						Eicon Networks Connection Monitor
gstartup.exe:						??? Gator AdWare Spyware ???
GSvr.exe:						GIGABYTE EnergySaver
gtb2122.tmp.exe:						Google Toolbar
gtb34D6.tmp.exe:						Google Toolbar
gtb43C.tmp.exe:						Google Toolbar
gtb5BA9.tmp.exe:						Google Toolbar
gtb6275.tmp.exe:						Google Toolbar
gtb9E7B.tmp.exe:						Google Toolbar
gtbB436.tmp.exe:						Google Toolbar
gtbB723.tmp.exe:						Google Toolbar
gtbB80.tmp.exe:						Google Toolbar
gtbDAC7.tmp.exe:						Google Toolbar
gtbE8CF.tmp.exe:						Google Toolbar
gthrsvc.exe:						Search Gatherer Service
GTItoPOINTSales.exe:						Mobilink Billing Software
gtsdsp.exe:						GTS diplomatic comms system
gtsrcv.exe:						GTS diplomatic comms system
gtssend.exe:						GTS diplomatic comms system
gtstimer.exe:						GTS diplomatic comms system
gtsztftp.exe:						GTS diplomatic comms system
gttask:						QuickTime Task Scheduler
gtwatch.exe:						Mustek Multimedia
guard.exe:						!!! AVG !!!
guard.exe:						!!! AVG !!!
GuardGuard.exe:						Mail.Ru GuardRea Application
guardgui.exe:						!!! Avira !!!
guardgui.exe:						!!! Avira !!!
GuardMailRu.exe:						Mail.ru Guard
gui.exe:						??? Adware.W32.Shorty.Gopher ???
guiW.exe:						SKPB Homegrown Encryption SW
guninstaller.exe:						??? Adware.W32.Claria ???
gwhotkey.exe:						Gateway Multi-function Keyboard Utility
gwmdmmsg.exe:						Gateway Modem Utility
gwmdmpi.exe:						GWMDMPI
gwsystemservice.exe:						Genesis World Applikations server
gwum.exe:						Gigabyte Motherboard Utility
hacker.exe:						??? Trojan.Esteems.E Trojan ???
haiyang.exe:						??? Backdoor.W32.EJL ???
harvester.exe:						Symantec Brightmail Antispam
hasplms.exe:						Aladdin HASP License Manager
hbinst.exe:						??? Hotbar.com Spyware ???
hbsrv.exe:						??? Hotbar.com Spyware ???
HbtOEAddOn.exe:						Hotbar - adware
HbtSrv.exe:						Hotbar - adware
HBTV.exe:						Hotbar - adware
HbtWeatherOnTray.exe:						Hotbar - adware
hc.exe:						Compaq help
HCAService.exe:						Citrix
hcontrol.exe:						ASUS Multimedia
hdashcut.exe:						High Definition Audio Property Page Shortcut
hdaudpropshortcut.exe:						Universal Audio Architecture UAA) High Definition Audio class driver
HDDControlGuard.exe:						Ashampoo HDD Control Guard
HDDSvc.exe:						AltrixSoft Hard Drive Inspector
HDDTsvc.exe:						Hard drive temperature application service
HDeck.exe:						VIA VIAudioi HDADeck
HealthService.exe:						Microsoft System Center Operations Manager
heat.exe:						??? Trojan.W32.Apher ???
hellmsn.exe:						??? Trojan.W32.MyTob ???
help16.exe:						*** SOMETHING YOU UPLOADED??? ***
helpctr.exe:						Microsoft Help and Support Center
helper.exe:						LIUtilities SpeedUpMyPC
helpexp.exe:						??? Attune HelpExpress. Spyware ???
helphost.exe:						Microsoft Help Center Hosting Server
HelpHost.exe:						Microsoft Help Center Hosting Server
helpinst.exe:						Installation Help File
helpsvc.exe:						Microsoft Helpsvc
heomstool.exe:						??? Trojan.Heoms ???
hf.exe:						Hide Folders tool
hgqhp.exe:						??? Trojan.W32.Flush ???
hh.exe:						Microsoft Windows Help
hhctrl.ocx:						Microsoft HTML Help Control
hhs32.pif:						??? W32/Rbot-ATE ???
hhw.exe:						Microsoft HTML Help Workshop
hidden32.exe:						??? hidden32 ???
hidedown.exe:						??? Downloader.W32.Leodon ???
hidfind.exe:						Alps Pointing Device Driver
hidr.exe:						??? Trojan.W32.Beagle ???
hidserv.exe:						Microsoft Human Interface Device Audio Service
hijackthis.exe:						Merijn Hijackthis
hisistheurls.exe:						??? Adware.W32.Network1 ???
hjgerhds.exe:						??? W32.Sober.T\@mm Trojan ???
hjym.exe:						??? BugBear.1 Virus Trojan ???
hkcmd.exe:						Intel Hotkey
hkserv.exe:						HotKey Utility
hkss.exe:						Compaq Multimedia
hkwnd.exe:						Sony Vaio HotKey Client
hl.exe:						Half Life
hloader.exe:						??? Trojan.Lodear Variant ???
hloader_exe.exe:						??? Trojan.W32.Lodear ???
hndlrsvc.exe:						Intel Alert Handler
HNDLRSVC.EXE:						Intel alert handler for email
Hoda.exe:						Payampardaz Hoda TrueCrypt
hookdump.exe:						??? Hookdump Trojan ???
host.exe:						??? Adware.W32.Begin2Search ???
hostmanager:						AOL Host Manager
hostmon.exe:						GTS diplomatic comms host monitor
HostSync.exe:						SC process
hot.exe:						??? Trojan.W32.MYTOB ???
hotkey.exe:						OneTouchHotKey Application
hotkeyapp.exe:						HotkeyApp
hotkeyscmds.exe:						Intel Extreme Graphics Hot Key Interceptor
hotsync.exe:						HotSync Manager
HOTSYNC.EXE:						Palm HotSync Manager
hottray.exe:						Hottray
hp wireless assistant.exe:						HP Wireless Assistant
HP1006MC.EXE:						HP LaserJet P1006 Printer Driver
HP1006MC.EXE:						HP Print Monitor
HP2014MC.EXE:						HP LaserJet P2014
hpacubin.exe:						HP Array configuration utility
hpb2ksrv.exe:						HP Status Win2k Service
hpbhksrv.exe:						HP Status Driver Hooking Service
hpbjdsnt.exe:						HP Printer
HPBOID.EXE:						HP Printer Driver
hpbootop.exe:						HP Boot Optimizer
hpbpro.exe:						HP Printer Driver
HPBPRO.EXE:						HP Printer Driver
hpbpsttp.exe:						HP Toolbox Startup
hpbspsvr.exe:						HP Printer
hpcmpmgr.exe:						HP Component Manager
hpcmpsvc.exe:						HPComponent
Hpdiags.exe:						HP Insight Diagnostics
hpdiags.exe:						HP Insight Diagnostics
hpdrv.exe:						HP utility
HPEsySvc.Exe:						HPEsySvc
HPEsySvc.exe:						HPEsySvc
hpesysvc.exe:						HPEsySvc
hpevtsvc.exe:						HPEventLog
HPEvtSvc.Exe:						HPEventLog
HPEvtSvc.EXE:						HPEventLog
HpFkCrypt.exe:						HP Drive Encryption
hpfpcSvc.exe:						HPFpcSvc
hpfpcSvc.Exe:						HPFpcSvc
hpfsched.exe:						HP Deskjet Configuration Tool
HPFSService.exe:						HP
hpgs2wnd.exe:						Share-to-web
hpgs2wnf.exe:						Share-to-web
hphmon03.exe:						Hewlett-Packard Printing Products
hphmon04.exe:						Hewlett-Packard Photosmart
hphmon05.exe:						Hewlett Packard Card Reader
hphmon06.exe:						Hewlett-Packard Printing Products
hphupd04.exe:						HP Photosmart Updater
hphupd05.exe:						HP Photosmart Updater
hphupd06.exe:						HP Photosmart Updater
hpjetdsc.exe:						HP Jet Discovery?
HPJETDSC.EXE:						HP Jet Discovery?
hplamp.exe:						HP Precision Scan Module
hpledSvc.exe:						HPLedSvc
hpledSvc.Exe:						HPLedSvc
HPLerSvc.Exe:						HPLerSvc
HPLerSvc.exe:						HPLerSvc
hplersvc.exe:						HPLerSvc
hpmanager.exe:						??? W32.Mytob.KE\@mm Worm ???
HPMapSvc.exe:						HPMapSvc
HPMapSvc.Exe:						HPMapSvc
hpnra.exe:						HP Network Registry Agent
hpobnz08.exe:						hpobnz08
hpoddt01.exe:						Hewlett Packard HP-2170 Config Tool
hpodev07.exe:						Hewlett-Packard Printers
hpoevm06.exe:						Hewlett-Packard Printers
hpoevm07.exe:						Hewlett-Packard Printers
hpoevm08.exe:						Hewlett-Packard Printers
hpoevm09.exe:						Hewlett-Packard Printers
hpofxm07.exe:						HP OfficeJet Fax Manager
hpogrp07.exe:						Hewlett-Packard AiO
hpohmr08.exe:						HP OfficeJet Component
hpoipm07.exe:						HP Printer Component
hpoojd07.exe:						HP OfficeJet Utility
hpoopm07.exe:						Hewlett-Packard Printers
hposol08.exe:						Hewlett Packard multi-function printers
hposts07.exe:						HP Printer Software
hposts08.exe:						Hewlett Packard OfficeJets diagnostics
hpotdd01.exe:						HP Digital Imaging
hppapml0.exe:						HP PML Printing
hpPfmSvc.Exe:						HPPfmSvc
hpPfmSvc.exe:						HPPfmSvc
hppfmsvc.exe:						HPPfmSvc
HPPU.exe:						HP Toolkit
HPPUDH.exe:						HP Toolkit
HPPUDS.exe:						HP Toolkit
hppusg.exe:						HP Usage Tracking
hpqcmon.exe:						HP Digital Imaging
hpqgalry.exe:						HP Digital Imaging Component
hpqimzone.exe:						HP Imaging Module
hpqnrs08.exe:						HP Digital Imaging
hpqste08.exe:						HP Imaging
hpqthb08.exe:						HP Image Zone Fast Start
hpqtra08.exe:						Hewlett Packard Imaging
HPQTRA08.EXE:						Hewlett Packard Imaging
hpqusgl.exe:						HP Digital Imaging
hpqwmi.exe:						HP WMI Interface
hpqWmiEx.exe:						HP ProtectTools Security Manager
hprblog.exe:						Hewlett-Packard Product Assistant
hpsdnSvc.Exe:						HPSdnSvc
hpsdnSvc.exe:						HPSdnSvc
hpsdnsvc.exe:						HPSdnSvc
hpservice.exe:						HP 3D DriveGuard
HPSIsvc.exe:						HP Smart-Install Service
hpsjvxd.exe:						HP Scan Monitor
hpsmhd.exe:						HP System Management Homepage
hpstatus.exe:						HP Printer
hpsysdrv.exe:						Hewlett-Packard Monitoring Tool
hptasks.exe:						HP Display Settings
HPTLBXFX.exe:						HP ToolBoxFX
hptskmgr.exe:						HP Task Management Component
HPWAMain.exe:						HP Wireless Service
hpwebjetd.exe:						HP Webjet Admin
hpwepdelay.exe:						HP Care Pack WEP MFC Appication
hpwmistor.exe:						HP WBEM Storage Service
HPWUCli.exe:						HP Software Update Client
hpwuschd.exe:						Hewlett Packard Software Update Scheduler
HPWuSchd2.exe:						Hewlett Packard Software Update Scheduler
hpwuschd2.exe:						Hewlett Packard Software Update Scheduler
hpwuSchd2.exe:						Hewlett-Packard printer software HP Software Update Application)
HPZinw12.exe:						HP Dot4Net Network Printer Driver
hpzipm12.exe:						HP Printer Driver
HPZIPM12.EXE:						HP Printer Driver
HPZipm12.exe:						HP Printer Driver
hpzstatn.exe:						Printer Status Server
hpzts04.exe:						HP Deskjet Taskbar Utility
hpztsb01.exe:						HP Deskjet Taskbar Utility
hpztsb02.exe:						HP Deskjet Taskbar Utility
hpztsb03.exe:						HP Deskjet Taskbar Utility
hpztsb04.exe:						HP Deskjet Taskbar Utility
hpztsb05.exe:						HP Deskjet Taskbar Utility
hpztsb06.exe:						HP Deskjet Taskbar Utility
hpztsb07.exe:						HP Deskjet Taskbar Utility
hpztsb08.exe:						HP Deskjet Taskbar Utility
hpztsb09.exe:						Hewlett Packard Taskbar Utility
hpztsb10.exe:						Hewlett Packard Taskbar Utility
hpztsb11.exe:						Hewlett Packard Deskjet Utility
hpztsbol.exe:						Hewlett Packard Taskbar Utility
hqtray.exe:						VMware network access status tray application
hro.exe:						??? Adware.W32.AdClicker ???
hsssrv.exe:						Hotspot Wireless VPN
htmdeng.exe:						??? Aureate trojan Virus Trojan ???
htpatch.exe:						SiS Multimedia
http_proxy.exe:						Gauntlet HTTP Proxy?
httpd.exe:						Netscape Enterprise Server
HTTPDL.EXE:						IBM NetQuestion text search service
httpma.exe:						MailSite HTTP Management Service
HTTPMA.EXE:						MailSite HTTP Management Service
HW_VSP3s_srv.exe:						HW Group Virtual COM Port
HWAPI.exe:						!!! McAfee Internet Security Suite !!!
hwclock.exe:						??? W32.Hwbot-A Trojan ???
hxdef.exe:						??? Trojan.W32.LovGate ???
hxdl.exe:						??? Hxdl Spyware ???
hxiul.exe:						??? Hxiul Spyware ???
hydradm.exe:						HydraVision Desktop Manager
hypertrm.exe:						Microsoft HyperTerminal
HYPERTRM.EXE:						Hyperterminal
i3k0hgad.exe:						??? Downloader.W32.ShopAtHome ???
i81sccp.exe:						??? Downloader.W32.Envolo ???
i8kfangui.exe:						Dell Inspirion Fan Control
i_view32.exe:						irfanview
i_view32.exe:						IrfanView Media Viewer
iaanotif.exe:						Event Monitor User
iaantmon.exe:						Intel Application Accelerator Component
iam.exe:						Internet Answering Machine
iamapp.exe:						iamapp
iao.exe:						AMS originator service
IAO.exe:						intel alert originator
IAO.EXE:						Intel Alert Originator
iap.exe:						Iap
Iap.exe:						Dell OpenManage Client Instrumentation
ibguard.exe:						InterBase Server Component
ibm00001.exe:						??? Trojan.W32.Torpig ???
ibmasrex.exe:						IBM Automatic Server Restart
ibmhpasv.exe:						IBM activePCI alert service
IBMIASRW.EXE:						IBM Server Auto-Restart Utility
IBMIASRW.exe:						IBM IPMI ASR
ibmmessages.exe:						IBM Message Center
ibmpmsvc.exe:						Ibmpmsvc
ibmprc.exe:						ibmprc Application
IBMSA.exe:						IBM Systems Director
ibmsmbus.exe:						IBM SMBus Package
ibmsprem.exe:						IBM Remote Supervisor Adapter II
ibmspsvc.exe:						IBM Remote Supervisor Adapter II
ibserver.exe:						InterBase Server Module
ic_ssk.exe:						??? Adware.W32.SurfSideKick ???
icabar.exe:						Citrix Metaframe
icas.exe:						GTS diplomatic comms system
icepack.exe:						!!! Symantec !!!
IcePack.exe:						!!! Symantec !!!
ico.exe:						Mouse Suite 98 Daemon
icon.exe:						RapidBlaster parasite
iconfig.exe:						SCM iconfig
ICQ Service.exe:						ICQ6 Toolbar
ICQ Service.exe:						ICQ updater
icq.exe:						ICQ
ICQCorp.exe:						ICQ
ICQLfite.exe:						ICQ Lite
icqlite.exe:						ICQ Lite
ICQLite.exe:						ICQ instant messenger
icsmgr.exe:						ICSMGR
icwconn1.exe:						Internet Connection Wizard
icwconn2.exe:						Internet Connection Wizard
icwnotify.exe:						Microsoft Windows SBS Networking
icwtutor.exe:						Microsoft Internet Explorer
idag.exe:						+++ IDA Pro +++
idaw.exe:						+++ IDA Pro +++
idemlog.exe:						??? Backdoor.W32.Agent ???
idispr.exe:						GTS diplomatic comms system
idisps.exe:						GTS diplomatic comms system
IDMan.exe:						Internet Download Manager
idriver.exe:						InstallDriver Module
idrivert.exe:						InstallDriver Module
IdsInst.exe:						!!! Symantec !!!
IE-REDIST.EXE:						Internet Explorer 8 Installer
ie4321.exe:						??? Dialer.W32.dialer ???
ie5setup.exe:						Microsoft Internet Explorer Installation Package
ie6setup.exe:						Microsoft Internet Explorer Installation Package
IE8-Setup-Full.exe:						Internet Explorer 8 Installer
iedll.exe:						??? iedll Spyware ???
iedriver.exe:						??? iedriver Spyware ???
IeEmbed.exe:						Huawei T2000 Element Mgmt Software
iehost.exe:						turown.g adware
IEHost.EXE:						??? turown.g adware Spyware ???
IELowutil.exe:						Internet Explorer Low-Mic Utility
IEMonitor.exe:						Internet Download Manager
iep.exe:						??? Adware.W32.AdRoar ???
iesetup.exe:						??? Adware.W32.Windupdates ???
iexpiore.exe:						??? Troj/Oblivion-B Trojan ???
iexplore.exe:						Internet Explorer
iexplore32.exe:						??? SPEX virus Virus ???
iexplorer.exe:						*** UNITEDRAKE INSTALLER *** or RapidBlaster Virus
iface.exe:						!!! Panda Anti-Virus !!!
ifrmewrk.exe:						Intel PRO/Set Wireless Component
iFtpSvc.exe:						Ipswitch WS_FTP Server
iftpsvc.exe:						Ipswitch FTP Service
igateway.exe:						!!! CA eTrust Integrated Threat Management 8.1/CA Jinchen Kill !!!
igetnet_3845_3645.exe:						??? Adware.W32.sqwire ???
igfxcpl.exe:						*** EXPANDINGPULLY ***
igfxext.exe:						Intel Common User Interface
igfxpers.exe:						Intel Common User Interface Module
igfxsrvc.exe:						Intel Graphics
igfxtray.exe:						igfxtray
igps.exe:						??? Trojan-Clicker.Win32.VB.kc ???
igudyn.exe:						??? Adware.W32.BargainBuddy ???
iinstall.exe:						??? Downloader.W32.180SearchAssistant ???
ijplmsvc.exe:						PIXMA Extended Survey Program camera software
ikernel.exe:						InstallShield Engine
ikeymain.exe:						Wireless keyboard driver
ildap.exe:						IMail LDAP Server
iLDAP.exe:						IMail LDAP Server
ILDAP.exe:						IMail LDAP Server
ilmt_tray.exe:						MSC BAM Services
IM.exe:						ZTE
im_1.exe:						??? Trojan.W32.Bagle ???
im_2.exe:						??? Trojan.W32.Bagle ???
IMAAdvanceSrv.exe:						Citrix
image.exe:						??? Unknown ???
ImageDrive.exe:						Ahead Nero Virtual Drive
imagedrive.exe:						Ahead Nero Virtual Drive
ImageFox.exe:						ACD Systems ImageFox
imailsrv.exe:						Internet Mail Service
IMailSrv.exe:						Internet Mail Service
imap4a.exe:						MailSite IMAP4 Server
IMAP4d32.exe:						IMail IMAP4 Server
IMAP4D32.exe:						IMail IMAP4 Server
imap4d32.exe:						IMail IMAP4 Server
imap4s.exe:						VOPmail IMAP4 Server
IMAP4S.exe:						VOPmail IMAP4 Server
imapi.exe:						Microsoft IMAPI
IMApp.exe:						IncrediMail
imapp.exe:						IncrediMail
imapsvc.exe:						Huawei T2000 Element Mgmt Software
ImaSrv.exe:						Citrix VM Server
IMBooster.exe :						Iminent Instant Messager
ime.exe:						Cisco IPS Manager Express (management of external IPSes)
IMEKRMIG.EXE:						Microsoft Office Alternative Alphabet Input Module
imekrmig.exe:						Microsoft Office Alternative Alphabet Input Module
IMEServer.exe:						Cisco IPS Manager Express (management of external IPSes)
imgedit.ocx:						Microsoft Imgedit Control
IMGICON.exe:						IOMEGA Disk Icons
Imgicon.exe:						IOMEGA Disk Icons
IMGICON.EXE:						IOMEGA Disk Icons
ImgIcon.exe:						IOMEGA Disk Icons
imgicon.exe:						IMGICON
imgscan.ocx:						Microsoft SCAN CONTROL
imgstart.exe:						Iomega ZIP Drives
imguninst.exe:						??? ABetterInternet ImGiant Spyware ???
imiconxp.exe:						Iomega REV System Module
imjpmig.exe:						imjpmig
imjpmig8.1:						Input Method Editor
imlua.exe:						IMLUA Module
imon.exe:						GTS diplomatic comms system
IMonitor.exe:						IMail Monitor Service
imonitor.exe:						IMail Monitor Service
IMONITOR.EXE:						IMail Monitor Service
imonnt.exe:						Imonnt
imontray.exe:						Intel Active Monitor Component
imqsmdem.exe:						IBM NetQuestion text search service
imscinst.exe:						Translation Component
imsser.exe:						Imsser Service
incd.exe:						InCD Packet Writing Software
incdsrv.exe:						Ahead Nero InCD Service
InCDsrv.exe:						Ahead Nero InCD Service
IncMail.exe:						Incredimail
incmail.exe:						Incredimail
incredimail.exe:						Incredimail
indexsearch.exe:						PaperPort Scanner Module
inetd:						Internet Services Superserver
inetd32.exe:						Hummingbird Inetd Component
INETDSRV.exe:						Pragma Systems InetD Service
inetdsrv.exe:						Pragma Systems InetD Service
inetinfo.exe:						IIS Admin Service Helper
infium.exe:						QIP messenger
infoctl.exe:						??? Spyware.W32.ClientMan ???
infomyca.exe:						Wireless-G Network Monitor
infopath.exe:						Microsoft Office Info Path
informe.exe:						??? W32.Vig.C Trojan ???
infotool.exe:						Nero Toolkit
InfoTool.exe:						Nero Toolkit
infus.exe:						??? Infus Dialer ???
infwin.exe:						??? Msview parasite Spyware ???
inicio.exe:						!!! Panda Internet Security !!!
iniswitcher.exe:						Antivirus Configuration-Converter
init:						System V init
init32m.exe:						??? Troj/Dloader-JT Worm ???
initsdk.exe:						Lexware ReweSdk
ink.exe:						??? Adware.W32.AdClicker ???
inonmsrv.exe:						!!! CA Jinchen Kill !!!
InoNmSrv.exe:						!!! CA Jinchen Kill !!!
inorpc.exe:						!!! eTrust Antivirus !!!
InoRpc.exe:						!!! eTrust Antivirus !!!
inort.exe:						!!! eTrust Antivirus !!!
InoRT.exe:						!!! eTrust Antivirus !!!
inotask.exe:						!!! CA eTrust Integrated Threat Management 8.1/CA Jinchen Kill !!!
InoTask.exe:						!!! CA eTrust Integrated Threat Management 8.1/CA Jinchen Kill !!!
InoWeb.exe:						!!! CA Jinchen Kill !!!
inputfileserver.exe:						BusinessObjects Enterprise 11.5
inst.exe:						??? Trojan.W32.RealSearch ???
install.exe:						??? Adware.W32.EasySearch ???
installdashbar.exe:						??? Adware.W32.Claria ???
installdatemanager.exe:						??? Adware.W32.Claria ???
installer.exe:						??? Adware.W32.GoGoTools ???
installprecisiontime.exe:						??? Adware.W32.Claria ???
installstub.exe:						Plaxo AutoUpdater
instant access.exe:						??? Dialer.W32.InstantAccess ???
instantaccess.exe:						Instantaccess
instmsiw.exe:						Windows Installer Service
IntAdmin.exe:						InterSystems MSM Workstation
intdel.exe:						??? Inet Delivery Spyware ???
INTEL.exe:						Dialogic Host Media Processing
intel32.exe:						Hijacker
intell32.exe:						??? Desktophijack Trojan ???
intell321.exe:						??? Trojan.W32.Alemod ???
IntellPMIService.exe:						Melloware Intelliremote
intelmem.exe:						Intel Modem Assistant
IntelMEM.exe:						Intel Modem Assistant
intenat.exe:						??? Backdoor.W32.Delf ???
Interior.scr:						Interior Design Ideas Screen Saver
internat.exe:						Microsoft Input Locales
Internat.exe:						Internationalization
internet.exe:						??? MAGICCALL virus Virus ???
internetfeatures.exe:						??? 180Solutions Spyware ???
internetfeatures[1].exe:						??? 180Solutions Spyware ???
intfysvc.exe:						Ipswitch Notification Server
intmon.exe:						??? Puper-D Trojan ???
intmonp.exe:						??? Puper-D Trojan ???
intxt.exe:						??? Trojan.W32.RealSearch ???
invbn.exe:						??? Adware.W32.BargainBuddy ???
IoctlSvc.exe:						USB
iomdmi.exe:						Intel Server Management
iomgr.exe:						adaptec io manager
IOMRPCCM.EXE:						CIOArrayManager RPC Command
IOMRPCEP.EXE:						CIOArrayManager RPC EventP
IOMRPCEV.EXE:						CIOArrayManager RPC Event
IP Operator.exe:						LG Software IP Operator
IP-Address-Management.exe:						Solarwinds tool
ip-client.exe:						Amicon FPSU-IP VPN Client
IP-Network-Browser.exe:						Solarwinds tool
ipc4remote.exe:						Server Monitor
ipccheck.exe:						iPass Downloader Utility
ipclient.exe:						IPInSightLAN 01
ipconfig.exe:						IPCONFIG.EXE IP Configure Command
IPCONFIG.EXE:						IPCONFIG.EXE IP Configure Command
ipfw.exe:						??? Trojan.W32.Yabe ???
iphsend.exe:						AOL Uninstaller
IPMI.exe:						Avocent IPMI Device Driver
ipmon32.exe:						IPInSightMonitor 01
ipnaadm_server.exe:						AP/OCS Switch Control
ipodmanager.exe:						Apple iTunes
iPodManager.exe:						Apple iTunes
ipodservice.exe:						Apple iTunes
ipodwatcher.exe:						Apple iTunes
iPodWatcher.exe:						Apple iTunes
ipoint.exe:						Microsoft IntelliPoint
ipsa.exe:						Intel Server Management
ipssvc.exe:						LANCOM VPN Client Service
iptray.exe:						Intel Desktop Utilities Tray Program
ipu.exe:						??? Adware.W32.AdLogix ???
irasyncd.exe:						??? Trojan.IRASHoul ???
irbis_server.exe:						IRBIS64 Web Service
ireike.exe:						ireike
IRIC.exe:						MC IRI (Switch) Controller
irmon.exe:						Windows Infrared Port Monitor
iroffer.exe:						??? Backdoor.W32.IROffer ???
isafe.exe:						!!! CA AntiVirus ISafe Service !!!
isafinst.exe:						!!! CA Internet Security Suite 2007 !!!
isass.exe:						??? Optix.Pro virus Trojan ???
isastg.exe:						Microsoft ISA Server Storage Service
isbmgr.exe:						Sony ISB Utility
isburnwatcher.exe:						HP Updater Utility
iscsiexe.exe:						MS iscsi discovery service
ISDNPAD.exe:						ISDN Protocol Adapter
ISFaxService.exe:						IS3 Satcom/Telecom Software
isftpd.exe:						InterScan FTP VirusWall
ishost.exe:						??? Trojan.W32.Zlob ???
ishttpd.exe:						InterScan Web VirusWall
isignup.exe:						Internet Connection Signup Wizard
isinstalldonecrazy.exe:						??? Adware.W32.BargainBuddy ???
islp2sta.exe:						Islp2sta
ismon.exe:						??? Trojan.W32.Zlob ???
ismserv.exe:						Microsoft Server Intersite Messaging
isnotify.exe:						??? Trojan.W32.Zlob ???
IsntSmtp.exe:						!!! TrendMicro !!!
ISNTSysMonitor:						!!! TrendMicro InterScan System Monitor !!!
ISNTSysMonitor.:						Trend Micro Interscan NT
ISODrive.exe:						DVD CD ROM Device Driver
ispsupport.exe:						??? Trojan.W32.Mytob ???
isPwdSvc.exe:						!!! Symantec !!!
isqlplus:						Oracle process
isqlw.exe:						Microsoft SQL Query Analyzer
issch.exe:						InstallShield Update Service
isscsf.exe:						ISS Security Scanner
issCSF.exe:						ISS Security Scanner
issdaemon.exe:						ISS Security Scanner
issDaemon.exe:						ISS Security Scanner
issearch.exe:						??? Trojan.W32.Zlob ???
ISSMTPD.exe:						InterScan E-Mail VirusWall
isstart.exe:						Logitech Image Studio
ISSVC.exe:						!!! Symantec !!!
issvc.exe:						!!! Symantec !!!
ISTranportService.exe:						IS3 Satcom/Telecom Software
istsvc.exe:						??? IST Service Spyware ???
isUAC.exe:						!!! Symantec !!!
isuspm.exe:						InstallShield Automatic Updater
ISUSPM.exe:						InstallShield
ISWMGR.exe:						!!! ZoneAlarm ForceField !!!
ITAdminServer.exe:						BlackBerry software
itbill.exe:						??? spyware.w32.spysheriff ???
itmoh.exe:						Lucent Modem Driver Helper
ITMRT_SupportDiagnostics.exe:						!!! CA Internet Security Suite 2007 !!!
ITMRT_SupportDiagnostics.exe:						!!! CA Internet Security Suite 2007 !!!
ITMRT_TRACE.exe:						!!! CA Internet Security Suite 2007 !!!
ITMRTSVC.exe:						!!! CA Internet Security Suite 2007 !!!
itouch.exe:						Logitech iTouch Keyboard Driver
iTouch.exe:						Logitech Keyboard Driver
itphwd.exe:						??? Adware.W32.AdLogix ???
ItSecMng.exe:						TOSHIBA Bluetooth Stack for Windows
itunes.exe:						Apple iTunes
ituneshelper.exe:						Apple Itunes
iTunesHelper.exe:						Apple Itunes
itype.exe:						Microsoft IntelliType Pro
iunkjjsc.exe:						??? 180Solutions Spyware ???
iviRegMgr.exe:						WinDVD
ivpsvmgr.exe:						TOSHIBA IVP Service Manager
IVRAlfaActiveServices.exe:						Alfa Active Services
iw.exe:						InternetWasherPro
iwatcher.exe:						GTS diplomatic comms system
iwctrl.exe:						NovaStor NovaDisk
IWebCal.exe:						IMail Web Calendar Service
iwebmsg.exe:						IMail Web Service
IWebMsg.exe:						IMail Web Service
IWEBMSG.EXE:						IMail Web Service
iwh2serv.exe:						IBM Database
ixapplet.exe:						Camio Viewer x
ixizgfcp.exe:						??? Spyware.W32.DyFuCA ???
j2gdllcmd.exe:						efax dllcmd
j2gtray.exe:						eFax Messenger
j95i15ei.exe:						??? Adtomi Spyware ???
jabber.exe:						??? Adware.W32.PacerD ???
JAMMER2ND.EXE:						??? NETSKY.Z Worm Virus Trojan ???
jammer2nd.exe:						??? NETSKY.Z Worm ???
jap.exe:						Proxy
jasgcc.exe:						Jasmine Database?
jasgcn.exe:						Jasmine Database?
jasproc.exe:						Jasmine Database?
java.exe:						Java
JavaService.exe:						Run Java program as Windows service
javaw.exe:						Java
javaws.exe:						Java Web Start
jawa32.exe:						??? Backdoor.Agent.bg ???
jconfigdnt.exe:						Hummingbird Jconfig Daemon
jdbgmgr.exe:						Microsoft Registrar for Java
JDBGMGR.EXE:						Microsoft Registrar for Java
jdbgmrg.exe:						??? TROJ_DASMIN.B VIRUS! ???
jetcar.exe:						Amazesoft FlashGet
jif.exe:						??? W32.Mytob.MK\@mm Worm ???
jk_nt_service.e:						Adobe Document Server
jk_nt_service.exe:						Jakarta NT Service
jkill.exe:						??? Adware.W32.WebRebates ???
jmnmxr.exe:						??? Adware.W32.DealHelper ???
jnfdtdi.exe:						??? Adware.W32.DealHelper ???
jobeng.exe:						ARCserveIT Job Engine
JOBENG.EXE:						ARCserveIT Job Engine
JobServer.exe:						BusinessObjects Enterprise 11.5
joyurls19.exe:						??? Adware.W32.Network1 ???
jq34042x.exe:						??? Adtomi Spyware ???
JQS.EXE:						Java Quick Start
jqs.exe:						Java
jrun.exe:						ColdFusion JAR Launcher
jrunsvc.exe:						JRun Service Controller
jucheck.exe:						Sun Java UpdateChecker Module
jusched.exe:						Sun Java Update Scheduler
jushed.exe:						Sun Java Scheduler
jushed32.exe:						??? CoolWebSearch Adware Spyware ???
K-MANIA.EXE:						Kleptomania Text Selection Program
k1205.exe:						+++ Tektronix Visual Network Monitor +++
k2admin.exe:						ColdFusion MX7 Search Server
k2index.exe:						ColdFusion MX7 Search Server
k2server.exe:						ColdFusion MX7 Search Server
k4eboy6.exe:						??? Adtomi Spyware ???
KABackReport.exe:						!!! Kingsoft !!!
kaccore.exe:						!!! Kingsoft !!!
kahlisetup_demo.exe:						??? Adware.W32.BargainBuddy ???
kane.exe:						??? Backdoor.W32.Dckane ???
KANMCMain.exe:						!!! Kingsoft !!!
kansgui.exe:						!!! Kingsoft Antivirus !!!
kansvr.exe:						!!! Kingsoft Antivirus !!!
kastray.exe:						!!! Kingsoft !!!
kav.exe:						!!! Kaspersky !!!
kav32.exe:						!!! Kingsoft Internet Security 2008 !!!
KavAdapterExe.exe:						!!! Kaspersky Anti-Virus for Lotus Notes !!!
kavfs.exe:						!!! Kaspersky Anti-Virus service process !!!
KAVFS.EXE:						!!! Kaspersky Anti-Virus service process !!!
kavfsgt.exe:						!!! Kaspersky Anti-Virus management service process !!!
kavfsrcn.exe:						!!! Kaspersky Anti-Virus remote management process !!!
kavfsscs.exe:						!!! Kaspersky script interception dispatcher service process !!!
kavfswp.exe:						!!! Kaspersky Anti-Virus working process !!!
kavisarv.exe:						!!! Kaspersky !!!
kavisarv.exe:						!!! Kaspersky !!!
kavlotsingleton.exe:						!!! Kaspersky Anti-Virus for Lotus Notes !!!
kavmm.exe:						!!! Kaspersky !!!
kavpf.exe:						Kapersky Anti Hacker
kavshell.exe:						!!! Kaspersky command line utility process !!!
kavss.exe:						!!! Kaspersky !!!
KAVStart.exe:						!!! Kingsoft Internet Security !!!
kavstart.exe:						!!! Kingsoft Internet Security !!!
kavsvc.exe:						!!! Kaspersky !!!
kavtray.exe:						!!! Kaspersky task tray process !!!
kazaa.exe:						Kazaa
kazaalite.exe:						Kazaalite
kazza.exe:						??? Kazza.exe trojan ???
kazza.exe:						??? Kazza.exe trojan ???
kb021119.exe:						??? Trojan.W32.Wisfc ???
kb891711.exe:						Windows Security Update
kbd.exe:						Logitech Multimedia
kbdap32a.exe:						Multi-Media Keyboard Application
kbdtray.exe:						Logitech iTouch Traybar
KBOXManagementService.exe:						KACE KBOX asset management software
KBOXSMMPService.exe:						KACE KBOX asset management software
keenpostback.exe:						??? Adware.W32.BargainBuddy ???
keenvalue.exe:						??? Keenvalue Spyware ???
kem.exe:						SetPoint Configuration Utility
KEM.exe:						SetPoint Configuration Utility
KEMailKb.EXE:						Micro Innovation keyboard app
kencapi.exe:						AVM Ken Server - KENCAPI
kencli.exe:						AVM Ken Client
kencron.exe:						AVM Ken Server - KENCRON
kendns.exe:						AVM Ken Server - KENDNS
kenftpgw.exe:						AVM Ken Server - FTP-Gateway
keninet.exe:						AVM Ken Server
kenmail.exe:						AVM Ken Server - Mailserver
kenmap.exe:						AVM Ken Server
kenproxy.exe:						AVM Ken Server - HTTP-Proxy
kenserv.exe:						AVM Ken Server
kensocks.exe:						AVM Ken Server - SOCKS-Proxy
kentbcli.exe:						AVM Ken Client
kernal32.exe:						??? Backdoor.Doly Trojan Virus Trojan ???
kernal32.exe:						??? Backdoor.Doly Trojan ???
kernal64.exe:						??? w32.yimper Trojan ???
kerne1412.exe:						??? Trojan.W32.Gashlio ???
kernel32.exe:						??? Floodnet virus Virus Trojan ???
kernel8:						??? Trojan.W32.Vixup ???
kernelfaultcheck:						dumprep
kernels32.exe:						??? DLOADER-FC Trojan ???
kernels64.exe:						??? Trojan.W32.Vixup ???
keyboardsurrogate.exe:						Microsoft Tablet PC Component
keygen.exe:						??? Backdoor.W32.Agent ???
keyhook.exe:						KeyHook
keylogger.exe:						JanNet Keylogger
keyword.exe:						??? Jraun.com hijacker  Spyware ???
kgnjas.exe:						??? Adware.W32.Ezula ???
khalmnpr.exe:						Logitech Mouse Utility
KHALMNPR.exe:						Logitech Mouse Utility
khooker.exe:						SIS Control Console
khost.exe:						khost
KIPS-C.exe:						PayamPardaz Keyhan VPN Client
kis.exe:						!!! Kaspersky !!!
kislive.exe:						!!! Kingsoft !!!
kissvc.exe:						!!! Kingsoft Internet Security 2008 !!!
kl.exe:						??? Trojan.Anserin ???
klnacserver.exe:						!!! Kaspersky Lab Cisco NAC Posture Validation Server !!!
klnagent.exe:						!!! Kaspersky !!!
klnagent.exe:						!!! Kaspersky Network Agent !!!
KLNAGENT.EXE:						!!! Kaspersky !!!
klobkveb.exe:						??? 180SearchAssistant Spyware ???
klserver.exe:						!!! Kaspersky Administration Server !!!
klswd.exe:						!!! Kaspersky !!!
klwtblfs.exe:						!!! Kaspersky !!!
KMailMon.exe:						!!! Kingsoft !!!
kmailmon.exe:						!!! Kingsoft !!!
KMCONFIG.exe:						5-button mouse
KmPcFax.exe:						Panasonic
KMPlayer.exe:						Media Player
KMProcess.exe:						5-button mouse
KMService.exe:						ZWT Keygen for Windows 7 Pro
kmw_run.exe:						Kensington MouseWorks
KMWDSrv.exe:						5-button mouse
kmwoa.exe:						??? Adware.W32.TargetSaver ???
kmwol.exe:						??? Adware.W32.TargetSaver ???
kmwom.exe:						??? Adware.W32.TargetSaver ???
kmwop.exe:						??? Adware.W32.TargetSaver ???
knlwrap.exe:						Unclassified key/mouse logger
knot.exe:						CyLog KNot Floating Desktop Notes
knownsvr.exe:						!!! Rising Antispyware !!!
KNUpdateMain.exe:						!!! Kingsoft !!!
knuzql.exe:						??? 180Solutions Spyware ???
kodakccs.exe:						Kodak Digital Cameras Component
kodakimage.exe:						Kodak Imaging
kodakimg.exe:						Kodak Imaging
kodakprv.exe:						Kodak Imaging Preview
kodorjan.exe:						??? Kodorjan Trojan Component ???
kontiki.exe:						Kontiki Delivery Manager
koolbar_setup.exe:						??? Adware.W32.Begin2Search ???
koss.exe:						Siemens Simatic Net process
KPDRV4XP.EXE:						keyboard driver
kpf4gui.exe:						!!! Sunbelt Personal Firewall 4 !!!
kpf4gui.exe:						!!! Sunbelt Personal Firewall !!!
kpf4ss.exe:						!!! Sunbelt Personal Firewall 4 !!!
kpf4ss.exe:						!!! Sunbelt Personal Firewall !!!
kpfw32.exe:						!!! Kingsoft Internet Security 2008 !!!
KPFWSvc.exe:						!!! Kingsoft Internet Security !!!
kpfwsvc.exe:						!!! Kingsoft Internet Security !!!
kpfwsvc.exe:						!!! Kingsoft Internet Security !!!
KRaidMan.exe:						TOSHIBA RAID Console
kraidsvc.exe:						TOSHIBA RAID Service
krbcc32s.exe:						!!! CA Jinchen KILL / eTrust Antivirus !!!
krxz.exe:						??? Adware.W32.ESyndicate ???
kservice.exe:						Delivery Manager Service
KSWebShield.exe:						!!! Kingsoft !!!
kvdetech.exe:						!!! Jiangmin AV and FW !!!
kvmonxp.kxp:						!!! Jiangmin AV and FW !!!
KVMonXP.kxp:						!!! Jiangmin AV and FW !!!
kvmonxp_2.kxp:						!!! Jiangmin AV and FW !!!
KVMonXP_2.kxp:						!!! Jiangmin AV and FW !!!
kvolself.exe:						!!! Jiangmin AV and FW !!!
KVSrvXP.exe:						!!! Jiangmin AV and FW !!!
kvsrvxp.exe:						!!! Jiangmin AV and FW !!!
kvsrvxp_1.exe:						!!! Jiangmin AV and FW !!!
KvXP.kxp:						!!! Jiangmin AV and FW !!!
kvxp.kxp:						!!! Jiangmin AV and FW !!!
kw[1].exe:						??? Adware.W32.SearchMiracle.EliteBar ???
KWatch.exe:						!!! Kingsoft Internet Security !!!
kwatch.exe:						!!! Kingsoft Internet Security !!!
KWSProd.exe:						!!! Kaspersky !!!
kwsprod.exe:						!!! Kaspersky !!!
kxeserv.exe:						!!! Kingsoft !!!
kxmixer.exe:						Eugene Gavrilov kX Audio
kzah.exe:						??? 180SearchAssistant Spyware ???
lanbrup.exe:						??? SafeSurfing Adware Module ???
lansas.exe:						??? Trojan.W32.MyTob ???
LanScope.exe:						LanTricks LanScope (Network Shares Scanner)
lao.exe:						Intel Alert Originator
lass.exe:						??? Troj.Bdoor.AKM Virus Trojan ???
lastloginsvc.exe:						AP/ACS Switch Control
launch.exe:						Vantarakis Launchh
launch32.exe:						Microsoft launch32
launchadware.exe:						??? Adware.W32.GoGoTools ???
launchap.exe:						Acer Launch Manager
launchapplication.exe:						Nokia PC Suite Launcher
launcher.exe:						Webshots Launcher
Launcher_LO.exe:						LevelOne Surveillance System
LauncherUI_LO.exe:						LevelOne Surveillance System
launchpd.exe:						Launch Pad
Launchy.exe:						Launchy Open Source Keystroke Launcher
LAUNCH~1.EXE:						Nokia PCSuite Tray Application
lawsrv.exe:						Law Receiver
layer.exe:						??? W32.Mogi Trojan ???
lbtwiz.exe:						Bluetooth services
lcc.exe:						??? Trojan.W32.Redplut ???
lcfd.exe:						IBM Tivoli desktop management
lckfldservice.exe:						Lock Folder Service
LCKSrv.exe:						National Instruments Logos
LClock.exe:						Clock
LcSvrAdm.exe:						ELSAwin - Manuals for VW cars
LcSvrAuf.exe:						ELSAwin - Manuals for VW cars
LcSvrDba.exe:						ELSAwin - Manuals for VW cars
LcSvrHis.exe:						ELSAwin - Manuals for VW cars
LcSvrKds.exe:						ELSAwin - Manuals for VW cars
LcSvrPas.exe:						ELSAwin - Manuals for VW cars
ldap3a.exe:						MailSite LDAP Directory Server
LDBserver.exe:						CA BrightStor ARCserve Backup
leerlaufprozess:						System Idle Process
letum.exe:						??? Trojan.MSIL.Letum ???
leventmgr.exe:						!!! Cisco Security Agent !!!
leventmgr.exe:						!!! Cisco Security Agent 5.1 !!!
lex.exe:						??? Downloader.W32.IstBar ???
LEXBCES.EXE:						LexBce Server
lexbces.exe:						LexBce Service
Lexiconer.exe:						Lexiconer Dictionary
lexplore.exe:						??? SODABOT VIRUS! ???
lexpps.exe:						Lexmark Printer Sharing
LexStart.exe:						LexMark Printer Support
LexStart.Exe:						LexMark Printer Support
LEXSTART.EXE:						LexMark Printer Support
lexstart.exe:						Lexstart
LF2GRPOW.exe:						Xerox Companion Suite
lgnkrv.exe:						??? Adware.W32.PurityScan ???
libsys32.exe:						??? W32/Sdbot.worm.gen.j - IRC bot ???
lic98rmt.exe:						Computer Associates License Client
lic98rmtd.exe:						Computer Associates License Server
lic98Service.exe:						Computer Associates License Server
licmgr.exe:						AntiVir License Manager
LicMngAdmin.exe:						InfoTech Service License Manager Viewer
LicMngServ.exe:						Paragraph System Admin Monitor
ligasrv.exe:						Liga DataBase Server
lightbox.exe:						Conceiva Lightbox
lights.exe:						Modem Lights Program?
LightScribeControlPanel.exe:						LightScribe Control Panel
limewire.exe:						LimeWire Executable
Lingvo.exe:						ABBYY Lingvo
lingvo.exe:						Russian to English translator
links.exe:						??? depress worm variant ???
listserver.exe:						Eudora List Management Agent
live.exe:						??? Backdoor.W32.Iroffer ???
livenote.exe:						Asus Livenote
livesrv.exe:						!!! BitDefender Security Suite !!!
livesystem.exe:						Iomega Automatic Backup
liveupdate.exe:						??? Spyware Doctor LiveUpdate ???
llbam_service.exe:						Force Computers GmbH AM Services
llbserver.exe:						HP OpenView
llssrv.exe:						Microsoft License Service
LLSSRV.EXE:						License Logging Service
LMG.exe:						License Software for Flexlm
lmgrd.exe:						Macrovision lmgrd Component
LMIGuardian.exe:						LogMeIn Desktop App
LMIGuardianSvc.exe:						LogMeIn
lmon.exe:						!!! Sophos Anti-Virus !!!
lmovie.exe:						??? Trojan.W32.Bagle ???
lmpdpsrv.exe:						Lexmark Printing
lmrepl.exe:						Lan Manager Replicator Service
LMREPL.EXE:						Lan Manager Replicator Service
LMS.exe:						Intel Local Manageability Service
LMSRVNT.exe:						Panasonic Local Print
LMSTATUS.EXE:						LexMark Printer Support
lmt_server.exe:						MSC BAM Services
lmu.exe:						??? Hyperlinker Adware Spyware ???
lnssatt.exe:						GFI LANguard (Patch management, not PSP)
load.exe:						??? Nimda-A Worm Module ???
load32.exe:						??? NIBU
loader(1).exe:						??? Backdoor.W32.Ruledor ???
loader.exe:						??? Loader ???
loader1).exe:						??? Backdoor.W32.Ruledor ???
loader32.exe:						+++ SoftICE Symbol Loader +++
loader32.exe:						+++ SoftICE Symbol Loader +++
loader[1].exe:						??? 2nd Thought Spyware ???
loadpowerprofile:						Microsoft Power Management Module
loadqm.exe:						MSN Queue Manager Loader
loadwc.exe:						IE Browser/Load Web Check
LocalFileStoreM:						SCApplications Performance Data Collector
locationfinder.exe:						Microsoft Location Finder
LOCATOR.EXE:						RPC Locator
locator.exe:						RPC Locator
lockbar.exe:						??? Trojan.W32.Loxbot ???
lockbr.exe:						??? Trojan.W32.Loxbot ???
lockmgr.exe:						ClearCase component
lockmgr.exe:						ClearCase
LockoutStatus.exe:						MS Account Lockout Tools
lockx.exe:						??? W32/Sdbot-ADD worm ???
lodctr32.exe:						??? Trojan.W32.Hyborate ???
log.exe:						NAI Gauntlet Logger
log_qtine.exe:						!!! McAfee !!!
logd.exe:						BMC Patrol Agent
LogGetor.exe:						!!! GoldenDolphin Chinese IDS !!!
logi_mwx.exe:						Logi_mwx
logitechdesktopmessenger.exe:						Logitech Desktop Messenger
logitray.exe:						Logitech QuickCam Assistant
LogMan.exe:						MSC BAM Services
logmein.exe:						LogMeIn Helper
logmeinsystray.exe:						LogMeIn Helper
logo1_.exe:						??? Trojan.W32.Looked ???
logon.exe:						adware.abox Hijacker
logon.scr:						Microsoft Logon Screensaver
logonmgr.exe:						MSN Internet Access
logonmgrexe:						MSN Logon Manager
logonui.exe:						Microsoft Logon User Interface
LogWatNT.exe:						Event Log Watch
logwatnt.exe:						Logwatnt
lorena.exe:						??? MAPSON.C virus Virus ???
loud.exe:						??? Adware.W32.Windupdates ???
LouderIt.exe:						Volume Control
lowlight.exe:						Logitech WebCam Component
lp.exe:						??? Adware.W32.RapidBlaster ???
lpmgr.exe:						ThinkVantage Productivity Center Manager
LQserver.exe:						CA BrightStor ARCserve Backup
lqsonline.exe:						DragonKnight Online Game
lra.exe:						Intel Server Management
LS3SVC.EXE:						LanSave III Power Monitor?
ls4dlp.exe:						??? Downloader.W32.QDown ???
lsa.exe:						??? WIN32.RBOT Trojan Variant ???
lsadst.exe:						??? Backdoor.W32.BREPIBOT ???
lsamgr.exe:						??? Trojan.W32.Bagle ???
lsas.exe:						??? W32.Agobot.AA Virus ???
LSAS.exe:						??? W32.Agobot.AA Virus Virus Trojan ???
lsass.exe:						Local Security Authority Server Subsystem
lsass32.exe:						??? w32/Randex.AR Virus ???
Lsass32.exe:						??? w32/Randex.AR Virus Virus Trojan ???
lsassa.exe:						??? CIADOOR.122 Trojan Virus Trojan ???
lsassa.exe:						??? CIADOOR.122 Trojan ???
lsasss.exe:						??? w32/Sasser.E Worm Virus Trojan ???
lsburnwatcher.exe:						LightScribe Watcher
lscntrl.exe:						Microsoft Exchange Server
lsdxa.exe:						Microsoft Exchange Server
lserver.exe:						Terminal Server Licensing
LSERVER.EXE:						Terminal Server Licensing
lsm.exe:						Vista Local Session Manager
lsmexin.exe:						Microsoft Exchange Server
lsmexnts.exe:						Microsoft Exchange Server
lsmexout.exe:						Microsoft Exchange Server
lsmmonitor.exe:						LANDesk System Monitor
lsmsnmpsrv.exe:						LanDesk System Monitor SNMP Service
lsntsmex.exe:						Microsoft Exchange Server
lssas.exe:						??? W32.AGOBOT.RL Virus Trojan ???
lsserv.exe:						??? W32.RBOT.CW Virus Trojan ???
lssrvc.exe:						HP Light Scribe Module
ltcm000c.exe:						Xircom Ltcm000c
ltdmgr.exe:						??? PowerStrip Technologies Spyware ???
ltmoh.exe:						Lucent Technologies Communciations
ltmsg.exe:						Lucent Technologies Communciations
ltsmmsg.exe:						Lucent Messaging
luall.exe:						!!! Symantec !!!
LUALL.EXE:						!!! Symantec !!!
LUALL.exe:						!!! Symantec !!!
lucallbackproxy.exe:						!!! Symantec !!!
lucoms.exe:						!!! Symantec !!!
lucomserver.exe:						!!! Symantec LiveUpdate !!!
lucoms~1.exe:						!!! Symantec !!!
LvAgent.exe:						ABBY Lingvo 6.0 Launcher
lvcoms.exe:						Lvcoms
lvcomser.exe:						Logitech Video COM Service
LVCOMSX.EXE:						Logitech Multimedia
lvcomsx.exe:						Logitech Multimedia
lvprcsrv.exe:						Logitech QuickCam
LVPrcSrv.exe:						Logitech QuickCam software
LWDMServer.exe:						!!! TrendMicro Infrastructure !!!
lwemon.exe:						Logitech Wingman
LWS.exe:						Logitech QuickCam Ribbon
lxbabmgr.exe:						Lexmark Series Button Manager
lxbbmgr.exe:						Lexmark Series Button Manager
lxbfbmgr.exe:						Lexmark Series Button Manager
lxbfbmon.exe:						Lexmark Series Button Manager
lxbkbmgr.exe:						Lexmark Printer Manager
lxbkbmon.exe:						Lexmark Printer Component
lxbmbmgr.exe:						Lexmark Series Button Manager
lxbmbmon.exe:						Lexmark Button Monitor Executable
lxbrcmon.exe:						Lexmark Printing Helper
lxbucoms.exe:						Lexmark Communication System
lxbumon.exe:						Lexmark Series Button Manager
lxdboxcp.exe:						Lexmark DOS Printing
lxrjd31s.exe:						Lexar Jump USB Thumb Drive
LxrSII1s.exe:						Lexar Secure II Service
lxsupmon.exe:						Lexmark Monitor
m-triplauncher.exe:						Olympus m
ma.exe:						??? Iambigbrother Spyware ???
MAC-Address-Discovery.exe:						Solarwinds tool
mace.exe:						ATI Technologies Cnotrol Centre
macname.exe:						Conversions Plus MacOpener Interface Loader
MAD.EXE:						Exchange System Attendant
mad.exe:						Exchange System Attendant
MADRMAgent.exe:						MarkAny DRM Agent
magent.exe:						Mail.ru agent (Check path in processdeep)
MagicPvt.exe:						MagicRotation
mahtfi.exe:						??? Adware.W32.ESyndicate ???
mailalrt.exe:						Proxy Alert Notification Service
MAILALRT.EXE:						Proxy Alert Notification Service
mailarchivaserver.exe:						MailArchiva Email Server
mailarchivaserverw.exe:						MailArchiva Email Server
MailCtrl.exe:						Magic Winmail
maildisp.exe:						MailScan for MDaemon
mailma.exe:						MailSite Mail Management Server
MailMS.exe:						VOPmail Mail Management Server
MailServer.exe:						Magic WinMail
mailskinner.exe:						Mail Skinner
Mailspy.exe:						Mailspy.ru
mailwasher.exe:						FireTrust MailWasher Pro
main.exe:						SpyCop ScanCheck
mainserv.exe:						PowerChute Personal Edition
Maintain.exe:						MSC BAM Services
MakeHash.exe:						MakeHash
makereport.exe:						!!! 360_Safe !!!
ManagementAgentNT.exe:						!!! Sophos Control Center !!!
manager.exe:						??? Backnote Virus Trojan ???
manifestengine.exe:						Logitech QuickCam Updater
mantispm.exe:						!!! ZoneAlarm Internet Security Suite 2007 !!!
mantispm.exe:						!!! ZoneAlarm Internet Security Suite 2007 !!!
mapiicon.exe:						ADSL Diagnostic Tools
mapisp32.exe:						Windows Messaging Subsystem
MAPISP32.EXE:						Windows Messaging Subsystem
mapisvc32.exe:						??? KX virus Virus Spyware ???
mario.exe:						??? trojan.mario ???
marker.exe:						SMART Board Software
MAS_CPTASP_cptcentral.exe:						AP/MAS Switch Control
MAS_CPTASP_cptcentral_A.exe:						AP/MAS Switch Control
MAS_CPTASP_cptcentral_B.exe:						AP/MAS Switch Control
MAS_CPTASP_cptheartbeat.exe:						AP/MAS Switch Control
MAS_MODD_Handler.exe:						AP/MAS Switch Control
MAS_MODT_Handler.exe:						AP/MAS Switch Control
masalert.exe:						!!! McAfee AntiSpyware !!!
massrv.exe:						!!! McAfee AntiSpyware application !!!
master t.exe:						Remote Anything Master
master.exe:						??? master trojan ???
master.exe:						??? Master Trojan ???
matcli.exe:						Verizon Online Support Center
matcli.exe:						Verizon Online Support Center
matlab.exe:						MATLAB
matlabserver.ex:						MATLAB Server
matlabserver.exe:						MATLAB
maxthon.exe:						Maxthon Web Browser
mbm4.exe:						Motherboard Monitor 4
mbm5.exe:						Motherboard Monitor 5
mbop1-0-3b.exe:						??? Adware.W32.WinBo32 ???
mc-110-12-0000079.exe:						??? Downloader.W32.LowZones ???
mc-110-12-0000080.exe:						??? Dialer.W32.Downloader ???
mc-58-12-0000111.exe:						??? Adware.W32.Shorty.Gopher ???
mc.exe:						Kittyfeet MouseCount
mcafee.update.exe.exe:						??? Trojan.W32.Renama ???
McAfeeDataBackup.exe:						!!! McAfee Internet Security Suite !!!
mcagent.exe:						!!! McAfee Agent !!!
mcappins.exe:						!!! McAfee Application Installer !!!
mcc monitor.exe:						ArcSoft Media Card Companion
mcconsol.exe:						!!! McAfee VirusScan Enterprise !!!
mcdash.exe:						!!! McAfee Security Center Dashboard !!!
mcdetect.exe:						!!! McAfee Security Centre Module !!!
mcdlc.exe:						Media Catalog Conversion Tool
mcepoc.exe:						!!! McAfee VirusScan for EPOC OS !!!
McEPOC.exe:						!!! McAfee VirusScan for EPOC OS !!!
McEPOCfg.exe:						!!! McAfee VirusScan for EPOC OS !!!
mcepocfg.exe:						!!! McAfee VirusScan for EPOC OS !!!
mcf.exe:						??? Adware.W32.RapidBlaster ???
mcinfo.exe:						!!! McAfee Internet Security !!!
mcmnhdlr.exe:						!!! McAfee VirusScan Command Handler !!!
mcmscsvc.exe:						!!! McAfee Internet Security Suite !!!
McNASvc.exe:						!!! McAfee Internet Security Suite !!!
mcods.exe:						!!! McAfee Internet Security Suite !!!
mcpalmcfg.exe:						!!! McAfee VirusScan for Palm OS !!!
mcpromgr.exe:						!!! McAfee Internet Security Suite !!!
McProxy.exe:						!!! McAfee Internet Security Suite !!!
mcpserver.exe:						Stardock MCP
mcrdsvc.exe:						MCRD Device Service
mcregwiz.exe:						!!! McAfee Registration Wizard !!!
mcs_adh_adm.exe:						AP/MCS Switch Control
mcs_aiap_adm.exe:						AP/MCS Switch Control
mcs_alda_adm.exe:						AP/MCS Switch Control
mcs_alec_adm.exe:						AP/MCS Switch Control
mcs_alis_adm.exe:						AP/MCS Switch Control
mcs_mss_adm.exe:						AP/MCS Switch Control
mcs_mts_adm.exe:						AP/MCS Switch Control
McSACore.exe:						Mcafee Site Advisor
mcscript_inuse.exe:						!!! McAfee VirusScan Enterprise !!!
McScript_InUse.exe:						!!! McAfee VirusScan Enterprise !!!
mcshell.exe:						!!! McAfee GUI !!!
mcshield.exe:						!!! McAfee VirusScan !!!
Mcshield.exe:						!!! McAfee VirusScan !!!
MCSHIELD.EXE:						!!! McAfee VirusScan !!!
Mcshield.exe:						!!! McAfee VirusScan !!!
mcshld9x.exe:						!!! McAfee AntiVirus Component !!!
mcsysmon.exe:						!!! McAfee System Monitor !!!
Mctray.exe:						!!! McAfee VirusScan Enterprise !!!
mctskshd.exe:						!!! McAfee Task Scheduler !!!
MCUI32.exe:						!!! Symantec !!!
mcuicnt.exe:						McAfee UI Container
mcuimgr.exe:						!!! McAfee Internet Security Suite !!!
mcupdate.exe:						!!! McAfee VirusScan Enterprise !!!
mcupdmgr.exe:						!!! McAfee Update Manager !!!
mcvsescn.exe:						mcvsescn
mcvsftsn.exe:						!!! McAfee VirusScan Online !!!
mcvsrte.exe:						!!! McAfee.com VirusScan Online Realtime Engine !!!
mcvsshld.exe:						!!! McAfee VirusScan !!!
McWCE.exe:						!!! McAfee VirusScan for WindowsCE OS !!!
mcwce.exe:						!!! McAfee VirusScan for WindowsCE OS !!!
McWCECfg.exe:						!!! McAfee VirusScan for WindowsCE OS !!!
mcwcecfg.exe:						!!! McAfee VirusScan for WindowsCE OS !!!
md.exe:						??? SystemMD Virus Spyware ???
mdabrd.exe:						AntiVirus Agent Communications Server
mdaemon.exe:						MDaemon
MDaemon.exe:						MDaemon
MDAEMON.EXE:						MDaemon
MDConv.exe:						InterSystems MSM Workstation
MDISP32.EXE:						OLE Messageing Helper
mdm.exe:						Script Debugger Helper
MDM.EXE:						Script Debugger Helper
mdms.exe:						??? W32/SdBot-CH Trojan ???
mdnsresponder.exe:						Bonjour for Windows Component
mDNSResponder.exe:						Bonjour Zero Configurartion Service for Windows
mdp.exe:						Huawei iManager T2000 Element Management Software
MDSpamD.exe:						MDaemon SpamAssassin
me.exe:						??? Adware.W32.DelFin ???
medgs1.exe:						??? PacerD Adware ???
mediaaccess.exe:						??? Adware.W32.MediaAccess ???
mediaaccessinstpack.exe:						??? Adware.W32.MediaAccess ???
mediaacck.exe:						??? Adware.W32.MediaAccess ???
mediadet.exe:						Mediadet
mediadetect.exe:						Corel Photo Album Media Detect
mediagateway.exe:						??? Adware.W32.MediaAccess ???
mediaget.exe:						MediaGet Downloader/Torrent Client
mediaman.exe:						??? iMesh media manager Spyware ???
mediamotor_49.exe:						??? Adware.W32.TargetSaver ???
mediapass.exe:						MediaPass adware process
mediapassk.exe:						MediaPass adware process
Mediasvr.exe:						CA BrightStor ARCserve Backup
Megaserv.exe:						MegaRAID Service Monitor
members-area.exe:						??? 5-1-61-96 ???
memokit2.exe:						MemoKit
memoptimizer.exe:						TuneUp Utilities
memorymeter.exe:						??? Memory meter Spyware ???
menu.exe:						??? Adware.W32.GoGoTools ???
messenger.exe:						Pelican Messenger 1.14
mestrxsvc.exe:						GFI Mail Essentials AntiSpam
MetaWebS.exe:						MetaInfo Web Config Server
mfcom.exe:						Citrix VM Server
mfeann.exe:						!!! McAfee !!!
mfevtps.exe:						!!! McAfee Process Validation !!!
MFFSUM.exe:						Xerox Companion Suite
mfin32.exe:						??? MyFreeInternetUpdate Spyware ???
MFIndexer.exe:						CorelDraw indexing for media files
mfpmp.exe:						Windows Media Foundation
MFPrintServer.exe:						Xerox Companion Suite
mfqjjr.exe:						??? Backdoor.W32.Delf ???
MFServices.exe:						Xerox Companion Suite
mgabg.exe:						Matrox BIOS Guard
mgactrl.exe:						Matrox Multimedia
mgahook.exe:						Matrox Video Driver
mgaqdesk.exe:						Matrox Quick Desk
mgasc.exe:						Matrox G450 DualHead
MGASC.exe:						Matrox video dual head driver
mgavrtcl.exe:						!!! McAfee antivirus software !!!
mghtml.exe:						!!! McAfee VirusScan Component !!!
mgmtservice.exe:						Adaptec Storage Manager
MgntSvc.exe:						!!! Sophos Control Center !!!
MGrntw.exe:						Magic 8 Code Partitioning
MGrqmrb.exe:						Magic 8 Code Partitioning
MGrqmrb.exe:						Magic 8 Code Partitioning
mgsev.exe:						??? Trojan.W32.Spybot ???
MGSysCtrl.exe:						LG Software System Control Manager
mgui.exe:						BullGuard AntiVirus
mgutrc.exe:						??? Adware.W32.AdLogix ???
MgWTrap3.exe:						MG-SOFT MIB Browser SNMP Trap Service
MgWTrap3.exe:						MG-SOFT MIB Browser
mhotkey.exe:						Chicony Multimedia Console
mhss.exe:						Statistics Server
MIB-Browser.exe:						Solarwinds tool
MIB-Walk.exe:						Solarwinds tool
MIBViewer.exe:						Solarwinds tool
Microsoft.ActiveDirectory.WebServices.exe:						Microsoft Active Directory Web Services
microsoft.exe:						??? GAOBOT Virus Virus Trojan ???
microsoftlog.exe:						??? W32/Sdbot.worm.gen.bi - IRC bot ???
microsystem.exe:						??? Trojan.W32.MyDoom ???
microupdate.exe:						??? Trojan.W32.Mytob ???
midaemon.exe:						HP OpenView
miiserver.exe:						Microsoft Identity Integration Server
mil.exe:						??? Adware.W32.PurityScan ???
mim.exe:						Musicmatch Jukebox Process
mimboot.exe:						Musicmatch Jukebox Startup Process
minibug.exe:						??? WeatherBug ad plugin Spyware ???
minilog.exe:						Minilog
miniwinagent.exe:						IBM ServeRAID FlashCopy Agent
MIProHst.exe:						MouseImp PRO
miranda32.exe:						Miranda IM
mirc.exe:						mIRC Internet Relay Chat
mirc32.exe:						??? Backdoor.IRC.Spybuzz ???
MIRC32.exe:						??? Backdoor.IRC.Spybuzz Virus Trojan ???
mirindaa1i.exe:						??? Adtomi Spyware ???
mirindaspe.exe:						??? Adtomi Spyware ???
mirror_plugin.exe:						??? Downloader.W32.INService ???
mis.exe:						Microsoft Money Module
misrv.exe:						HP OpenView
mixer.exe:						Mixer
mixersel.exe:						Realtek Audio Module
mksc.exe:						??? RelevantKnowledge Spyware ???
mlo.exe:						My Life Organized
mloop.exe:						GTS diplomatic comms system
mm.exe:						??? Trojan.Spamforo ???
mm15201518.exe:						??? Adware.W32.PromulGate ???
mm15201518.stub.exe:						??? Adware.W32.DelFin ???
mm_server.exe:						Musicmatch Music Server
mm_tray.exe:						MusicMatch Jukebox Traybar
MM_TRAY.EXE:						MusicMatch
mmbun.exe:						??? Adware.W32.Roings ???
mmbun2.exe:						??? Downloader.W32 ???
mmc.exe:						Microsoft Management Console
mmdiag.exe:						MusicMatch Jukebox Component
mmefxe.ocx:						Microsoft Multimedia Controls Effects Library
mmhotkey.exe:						Dritek Communications Helper
mmjb.exe:						MUSICMATCH Jukebox
mmkeybd.exe:						Mmkeybd
MML.exe:						MSC BAM Services
MMLadc.exe:						SC process
mmod.exe:						??? Mmod Spyware ???
mms.exe:						Acronis Disk Director Advanced
mmsg.exe:						??? Trojan.W32.Renama ???
mmtask.exe:						MusicMatch Jukebox
MMTASK.EXE:						MusicMatch
mmtask.tsk:						Multimedia Support Task
mmtray.exe:						MusicMatch Jukebox Traybar
mmtray2k.exe:						Morgan Multimedia Toolbox
mmtraylsi.exe:						Morgan Multimedia Toolbox
mmttil.exe:						??? Adware.W32.Ezula ???
mmups.exe:						??? Roimoi/Media-Motor adware Spyware ???
mmusbkb2.exe:						Mmusbkb2
mmwho.exe:						??? Downloader.W32 ???
mmwork.exe:						??? Adware.W32.Network1 ???
mmx.exe:						Adobe MMX Technology Plug-ins
mnmsrvc.exe:						Microsoft NetMeeting
mnss.exe:						??? Adware.W32.PurityScan ???
mnsvc.exe:						??? TROJ_SUA.A Trojan ???
mnybbsvc.exe:						Microsoft Money Background Banking Service
mnyexpr.exe:						Microsoft Money Express
mnyschdl.exe:						Microsoft Money Task Scheduler
mobiConnect.exe:						Huwaei Mobile Internet Connection Daemon
mobsync.exe:						Microsoft Synchronization Manager
MOD_SNMPADCServ:						SC process
MOD_SNMPADCService.exe:						Switch Commander Application
modemview.exe:						Intel Server Manager
modsrv.exe:						SIEMENS Modem Utility
MOE.exe:						Microsoft Windows Live Mesh
MOM.exe:						ATI Catalyst Control Center
MOMHost.exe:						Microsoft Operations Manager
MOMService.exe:						Microsoft Operations Manager
money express.exe:						Microsoft Money Express
monitor.exe:						Microsoft Monitor
Monitor_LO.exe:						LevelOne Surveillance System
MonitoringAgent.exe:						Intel NGSMS Monitoring Agent
MonitoringHost.exe:						Microsoft System Center Operations Manager
monitr32.exe:						Canon monitr32
monsvcnt.exe:						!!! Ahnsd Korean AV !!!
monsysnt.exe:						!!! Ahnsd Korean AV !!!
monwow.exe:						Monwow
morpheus.exe:						Morpheus 3.4
mosearch.exe:						Fast Search Utility
mostat.exe:						??? Mostat Spyware ???
motivebrowser.exe:						Motive Browser
motivesb.exe:						AT&T Assistant
motmon.exe:						Motive Communications Resolution Assistant
mouse.exe:						??? Unknown ???
mouse32a.exe:						Mouse Driver
mousebm.exe:						??? Esbot Worm Module ???
moviemk.exe:						Microsoft Movie Maker
movienetworks.exe:						??? Adware.W32.DelFin ???
movieplace.exe:						??? Movieplace Virus Trojan ???
Mozilla.exe:						Mozilla Browser
mozilla.exe:						Mozilla Browser
mp3conv.exe:						IS3 Satcom/Telecom Software
mp3serch.exe:						??? mp3serch.exe Spyware ???
mpapi3s.exe:						Nokia Mobile Phone API
mpbtn.exe:						Motive SmartBridge
mpcmdrun.exe:						!!! Windows Defender !!!
MpCmdRun.exe:						!!! Windows Defender !!!
MPDataCollector:						SCApplications Performance Data Collector
mpeng.exe:						Microsoft Windows OneCare Live
mpf.exe:						!!! McAfee Personal Firewall !!!
mpfagent.exe:						!!! McAfee Personal Firewall !!!
MpfAgent.exe:						!!! McAfee Personal Firewall !!!
mpfconsole.exe:						!!! McAfee Personal Firewall !!!
mpfservice.exe:						!!! McAfee Personal Firewall Component !!!
MpfSrv.exe:						!!! McAfee Internet Security Suite !!!
mpftray.exe:						!!! McAfee Personal Firewall Tray icon !!!
mplayer.exe:						Windows Media Player
mplayer2.exe:						Windows Media Player
mpm.exe:						HP Printer
mprexe.exe:						Windows Routing Process
mps.exe:						!!! McAfee Internet Security Suite !!!
mpservic.exe:						Canon MultiPASS Service
mpsetup.exe:						Windows Media Player Installer
mpsevh.exe:						!!! McAfee Internet Security Suite !!!
mpssvc.exe:						Microsoft OneCare Live
mpsvc.exe:						!!! Omniquad Total Security 3.0.0 !!!
mptbox.exe:						MultiPASS Tool Box
mqlsr.exe:						GTS diplomatic comms system
MQNETListener.exe:						MQ Net File Transport Server
mqra.exe:						GTS diplomatic comms system
mqsa.exe:						GTS diplomatic comms system
mqsvc.exe:						Microsoft Message Queue Server
mqtgsvc.exe:						Message Queuing Triggers Service
mr2kserv.exe:						Dell Openmanage Service
mrf.exe:						!!! TrendMicro Infrastructure !!!
mrjj.exe:						??? Puper-E Trojan ???
mrkscr.exe:						RelevantKnowledge
mrmonitor.exe:						RAID Web Console 2 MegaMonitor
mrouterconfig.exe:						Intuwave Connection Manager
mrouterruntime.exe:						Intuwave Connection Manager
mrt.exe:						Malicious Software Removal Tool.
MRTclock.exe:						Win2Farsi.com
mrtmngr.exe:						Mrtmngr
mrtstub.exe:						unclassified malware
msaa.exe:						??? Dldr.WinSh.AC.02 Trojan ???
MSACCESS.EXE:						Microsoft Access
msaccess.exe:						Microsoft Access
msacm32.exe:						*** EXPANDINGPULLY ***
msalgmon.exe:						*** VALIDATOR ***
msams.exe:						??? WORM_RBOT.AHR/X Trojan Virus Trojan ???
msams.exe:						??? WORM_RBOT.AHR/X Trojan ???
msapp.exe:						??? RSBOT virus Virus ???
MSASCui.ex:						!!! Windows Defender !!!
msascui.exe:						!!! Windows Defender or Microsoft Forefront (Check Registry Keys) !!!
msawindows.exe:						??? Spyware.W32.ClientMan ???
msbb.exe:						??? 180Solutions Web3000 Spyware Application Spyware ???
msbb[1].exe:						??? 180Solutions Spyware ???
msblast.exe:						??? MSBlast Worm ???
msbntray.exe:						Microsoft Broadband Networking Tray Application
msc32.exe:						??? msc32.exe Trojan Virus Trojan ???
msc32.exe:						??? msc32.exe Trojan ???
mscache.exe:						??? Integrated Search Technologies Spyware ???
mscache32.exe:						*** FRIENDLY TOOL - Seek Help ***
msccn32.exe:						??? Win32.Sobig.B\@mm ???
mscfg32.exe:						*** UNITEDRAKE ***
mscifapp.exe:						!!! McAfee Privacy Service !!!
msckin.exe:						??? Spyware.W32.ClientMan ???
mscman.exe:						??? Odysseus Marketing Spyware ???
mscnsz.exe:						??? W32.Rbot.HQ Virus Trojan ???
mscomct2.ocx:						Microsoft Common Controls 2 ActiveX Control DLL
mscomm32.ocx:						MSComm Control
mscommand.exe:						??? W32.Kwbot.P.Worm ???
msconfgh.exe:						??? WORM_MYTOB.NB Trojan ???
msconfig.exe:						Windows System Configuration Utility.
msconfig32.exe:						??? W32.Tulu virus Virus ???
mscornet.exe:						??? Troj/Zlob-AO Trojan ???
mscorsvw.exe:						.NET Runtime Optimization Service
mscvb32.exe:						??? Sobig worm ???
msd.exe:						Microsoft COM Port Diagnostics
MSD.EXE:						Microsoft COM Port Diagnostics
msdaemon.exe:						Huawei HWMSuite
msdcsvc.exe:						*** MORBIDANGEL ***
msdef.exe:						??? Trojan.W32.Secefa ???
msdioo.exe:						??? Spyware.W32.ClientMan ???
msdirectx.exe:						*** UNITEDRAKE ***
msdm.exe:						??? MULDROP.352 virus Media Plug x.1.2 Virus ???
msdmlib.xpc:						BMC Patrol Agent
msdnsche.exe:						*** FRIENDLY TOOL - Seek Help ***
msdtc.exe:						Distributed Transaction Coordinator
msdtc32.exe:						*** DMW ***
msdtctm.exe:						*** EXPANDINGPULLY ***
msdtssrvr.exe:						MSDTSServer
MsDtsSrvr.exe:						Microsoft SQL Server
msdxm.ocx:						Windows Media Player 2 ActiveX Control
mse7.exe:						Microsoft Script Editor
msecatt.exe:						GFI Mail Essentials AntiSpam
msexcimc.exe:						Exchange Internet Mail Service
MSEXCIMC.EXE:						Exchange Internet Mail Service
msexreg.exe:						??? Adware.W32.BargainBuddy ???
msfeedssync.exe:						Microsoft Feeds Synchronization
MsFTEFD.exe:						Microsoft SQL Server
msftesql.exe:						Microsoft SQL Server
msg32.exe:						msg32
msgdmf.exe:						??? Spyware.W32.ClientMan ???
MSGENG.EXE:						ARCserveIT Message Engine
msgeng.exe:						ARCserveIT Message Engine
msgfix.exe:						??? W32.Gaobot.SN Virus Trojan ???
msgkd.exe:						*** GROK ***
msgki.exe:						*** GROK ***
msgku.exe:						*** GROK ***
msgloop.exe:						Crystal Msgloop
MsgManager.exe:						Message Manager
msgplus.exe:						MSN MessengerPlus
msgsrv32.exe:						Windows Message Server
msgsys.exe:						Intel LANdesk
MSGSYS.EXE:						INTEL landesks alert manager system
mshta.exe:						Microsoft HTML Application Host
msiexec.exe:						Windows Installer Component
msiexec16.exe:						??? Troj/OptixP-13 Trojan ???
msimg32.exe:						*** EXPANDINGPULLY ***
msimn.exe:						Microsoft Outlook Express
msinfo.exe:						??? CoolWebSearch Adware Spyware ???
MSIService.exe:						System Control Manager
mskagent.exe:						!!! McAfee SpamKiller Module !!!
mskdetct.exe:						!!! McAfee Spamkiller !!!
mskiks.exe:						??? Trojan.W32.Skenkly ???
msksrver.exe:						!!! McAfee Internet Security Suite !!!
msksrvr.exe:						!!! McAfee Spamkiller !!!
mslagent.exe:						??? Adware.Slagent Spyware ???
mslaugh.exe:						??? BLASTER.E WORM ???
msmc.exe:						??? Win32.Small.i Virus Trojan ???
msmdsrv.exe:						Microsoft SQL Server Analysis Services
msmgs.exe:						??? W32.Alcarys.B/G\@mm Worm Virus Trojan ???
msmgt.exe:						??? Total Velocity Spyware ???
msmm.exe:						??? Spyware.W32.ClientMan ???
msmmc32.exe:						*** FRIENDLY TOOL - Seek Help ***
msmoney.exe:						Microsoft Money Executable
MsMpEng.ex:						!!! Windows Defender !!!
msmpeng.exe:						!!! Windows Defender or Microsoft Forefront (Check Registry Keys) !!!
msmpsvc.exe:						OneCare Live
msmsg.exe:						??? Backdoor.Prorat.10b3 Trojan ???
msmsgri32.exe:						??? RANDEX.D virus. ???
MSMSGS.EXE:						MSN Messenger
msmsgs.exe:						MSN Messenger
MSMWS002.exe:						InterSystems MSM Workstation
msn.exe:						??? W32.Flita virus Virus ???
MSN.exe:						??? W32.Flita virus Virus ???
msn_sl.exe:						MSN Search Toolbar Helper
msnappau.exe:						MSN Toolbar Updater
msncc.exe:						MSN Connection Center
msndc.exe:						MSN Quick View
msngather.exe:						MSN Toolbar
MSNIASVC.EXE:						Microsoft Messenger Service
msniasvc.exe:						MSN Internet Access
msnindex.exe:						MSN Toolbar Suite
msnladmin.exe:						MSN Toolbar Admin
msnlive.exe:						??? Trojan.W32.Mytob ???
msnmsgr.exe:						MSN Messenger
msnserve.exe:						??? W32.Spybot.YQW Trojan ???
msnst32.exe:						??? RBOT Worm Module ???
msntfs.exe:						*** FRIENDLY TOOL - Seek Help ***
msoffice.exe:						Microsoft Office Shortcut Bar
MSOFFICE.EXE:						Microsoft Office?
msohrg.exe:						??? Downloader.W32.IstBar ???
msole32.exe:						??? Fakespy-B Trojan ???
msoobe.exe:						Windows Product Activation
msosync.exe:						MS office
MSOSYNC.exe:						Microsoft Office Document Cache
MSPADMIN.EXE:						Microsoft ISA Server
mspadmin.exe:						Microsoft ISA Server
mspaint.exe:						Microsoft Paint
mspath.exe:						??? BackDoor.SdBot Trojan ???
mspmspsv.exe:						WMDM PMSP Service
MsPMSPSv.exe:						Windows Media Device Manager Pre-Message Security Protocol Service
mspmspv.exe:						??? Chum-A Trojan Virus Trojan ???
mspmspv.exe:						??? Chum-A Trojan ???
mspub.exe:						Microsoft Publisher
MSPVIEW.exe:						Microsoft Office Document Imaging
mspy2002:						Microsoft Input Message Editor Translator
msqry32.exe:						Microsoft Query
msrdljoy.exe:						??? Adware.W32.CashSaver ???
msregstr.exe:						*** VALIDATOR ***
msresearch:						Spy Sheriff Malware
msscd16.sys:						*** VALIDATOR ***
msscli.exe:						!!! McAfee AntiSpyware Component !!!
msscript.ocx:						Microsoft Script Control
mssdmn.exe:						Microsoft Web Server Extensions
mssearch.exe:						MS Index Service
mssearchnet.exe:						??? Trojan.Zlob.D Trojan ???
msseces.exe:						!!! Microsoft Security Essentials !!!
mssecure.exe:						??? Backdoor.W32.Robobot ???
msserver.exe:						Huawei HWMSuite
msshed32.exe:						??? Adtomi Spyware ???
msspnp:						??? Unknown ???
msssort.exe:						Maxtor Drag and Sort
msssrv.exe:						!!! McAfee Anti Spyware !!!
msstat.exe:						Sony MSstat MFC Application
mssvc.exe:						Tucows StealthDisk Service
mssvc32.exe:						??? W32/Gaobot.WU Virus Trojan ???
mssvcc.exe:						??? Backdoor.Win32.Rbot ???
mssvcmn.exe:						*** VALIDATOR ***
mssvr.exe:						??? 2020Downloader Spyware ???
msswchx.exe:						Microsoft Windows Module
mssys.exe:						??? MYSS.B virus Virus ???
mssysmgr.exe:						PhotoShow Deluxe Media Manager
mstask.exe:						Task Scheduler
MSTask.exe:						Task Scheduler
mstasks.exe:						??? W32.Mydoom.FP\@mm Worm ???
mstc.exe:						??? Trojan.W32.Nugache ???
mstcpmon.exe:						??? W32.Monikey\@mm Worm ???
mstcs.exe:						??? Backdoor.W32.IROffer ???
mstinit.exe:						Microsoft Scheduling Agent
mstordb.exe:						Microsoft Clip Organizer
mstore.exe:						Microsoft Clip Organizer
mstsc.exe:						Microsoft Remote Desktop Connection
mstscax.exe:						*** EXPANDINGPULLY ***
msupdate.exe:						CoolWebSearch spyware
MSupdate.exe:						??? CoolWebSearch spyware Spyware ???
msurlcli1.exe:						??? Spyware.W32.ClientMan ???
msuser.exe:						Media Center Receiver Service
msvc32.exe:						??? Spyware.W32.ClientMan ???
msvcmm32.exe:						Movielink.com Updater
msvgr.exe:						??? W32.Mytob.LE\@mm Worm ???
msvxd.exe:						??? W32/Datom-A ???
msw.exe:						??? Adware.W32.DealHelper ???
mswdssvc.exe:						*** VALIDATOR ***
mswinb32.exe:						??? Trojan.W32.RealSearch ???
mswinf32.exe:						??? Trojan.W32.RealSearch ???
mswinsck.ocx:						Microsoft Winsock Control DLL
mswmcls.exe:						Windows Media Connect
msworks.exe:						Microsoft Works Task Launcher
mswsus.exe:						??? W32/Sdbot.worm.gen.y ???
mswsus.exe:						??? W32/Sdbot.worm.gen.y ???
msxct.exe:						??? Adware.W32.BargainBuddy ???
msxml3msms.exe:						Microsoft XML Installation Utility
mt.exe:						??? Backdoor.W32.Emtee ???
mtask.exe:						??? Troj/Banker-GQ Worm ???
mtdacq.exe:						MediaSniffer
mtjuhp.exe:						??? Adware.W32.Capharm ???
MTS Connect.exe:						Huawei MTS Connect
MTS_ScreenSaver.scr:						MTS Company Screensaver
mtx.exe:						Microsoft Transaction Server MTS)
MtxHotPlugService.exe:						Matrox Graphics Card Adapter
muamgr.exe:						Eclipsit MicroAngelo
mubyjm.exe:						??? Adware.W32.DealHelper.com ???
mudsc.exe:						??? Adware.W32.Ezula ???
MultiLex.exe:						Paragon Software MultiLex
MultiMon.exe:						Multiple Monitors Applications
mups.exe:						Belkin Sentry Bulldog
musirc4.71.exe:						??? W32/Randex-QA ???
mvdmodw.exe:						??? Adware.W32.PacerD ???
mwasrv.exe:						HP OpenView
mwd.exe:						??? W32/Graps-A worm ???
Mwecsrv.exe:						HP OpenView
mwfirewall.exe:						??? Trojan.Gamqowi ???
mwsnap.exe:						MWSnap Screen Capture Utility
mwsoemon.exe:						??? MyWebSearch Adware Spyware ???
mwsvm.exe:						??? ADW_SCANPORTAL.A Adware Spyware ???
mxadmin.exe:						Zultys MX Admin Utility
mxoaldr.exe:						Maxtor Corporation.
mxtask.exe:						Mxtask
mxuser.exe:						Zultys MXIE Client
myagttry.exe:						!!! McAfee Total Protection for Small Business !!!
myfastupdate.exe:						My-Fast-Access
mypcsearch.exe:						2nd Thought
mysearch2.0.exe:						??? 8848 Spyware ???
mysetp.exe:						??? Adware.W32.P2PNetworking ???
mysql.exe:						MySQL Command Line Client
mysqld-max-nt.exe:						MySQL Server
mysqld-nt.exe:						MySQL Daemon
mysqld.exe:						MySQL
myurlff.exe:						??? Adware.W32.Network1 ???
myurlsagain.exe:						??? Adware.W32.Network1 ???
n.exe:						??? Trojan.W32.NASCENE ???
n20050308.exe:						??? Adware.W32.TargetSaver ???
nadminp.exe:						Domino Program
nahbluff.exe:						??? Dialer.W32.Downloader ???
nail(1).exe:						ABetterInternet Spyware
nail.exe:						??? Trojan.Win32.Stervis.b ???
nail1).exe:						??? ABetterInternet Spyware ???
NAIlgpip.exe:						!!! McAfee !!!
naimag32.exe:						Naimag32
naimas32.exe:						Naimas32
nalntsrv.exe:						Novell Client Module
namedpipe.exe:						??? W32.Mytob.LO\@mm Worm ???
namgr.exe:						Lotus Notes Agent Manager
Naming_Service.exe:						Huawei iManager T2000 Element Management Software
NAPAdapterServer.exe:						Switch Commander Application
naPrdMgr.exe:						!!! McAfee ePolicy Orchestrator !!!
naprdmgr.exe:						!!! McAfee ePolicy Orchestrator !!!
NapRestarter.ex:						SC process
NapRestarter.exe:						Switch Commander Application
narrator.exe:						Microsoft Narrator
NASvc.exe:						Nero Update
NATnsSrv.exe:						SC process
naturalcolorload.exe:						Natural Color
nav32sp.exe:						??? Backdoor.W32.Rbot ???
navapp.exe:						??? NavExcel Adware Spyware ???
NAVAPSVC.EXE:						!!! Symantec !!!
Navapsvc.exe:						!!! Symantec !!!
navapsvc.exe:						!!! Symantec !!!
NAVAPW32.EXE:						!!! Symantec !!!
navapw32.exe:						!!! Symantec !!!
NaveAP.exe:						NAV for Microsoft Exchange
NaveCtrl.exe:						!!! Symantec !!!
NaveLog.exe:						!!! Symantec !!!
NaveSP.exe:						!!! Symantec !!!
NAVESrv.exe:						NAV for Microsoft Exchange
NaviAgent.exe:						VeriSign software update agent
Navid.exe:						Payampardaz Navid Software
NavShcom.exe:						!!! Symantec !!!
navw32.exe:						!!! Symantec !!!
Navw32.exe:						!!! Symantec !!!
Navwnt.exe:						!!! Symantec !!!
NAW.exe:						Narcis Softwares MFC Application
NBHGui.exe:						Ahead Nero SecurDisc Host
nbj.exe:						Ahead Nero Back It Up Scheduler
NBKeyScan.exe:						Nero 7 Essentials
nbr.exe:						Ahead Nero Back It Up Restore
NBService.exe:						Nero BackItUp
nbthlp.exe:						??? W32.Toxbot.AL Trojan ???
nbtstat.exe:						NBTSTAT.EXE NetBIOS Command
NBTSTAT.EXE:						NBTSTAT.EXE NetBIOS Command
NbWin.exe:						Veritas NetBackup
nc.exe:						Netcat
ncalconn.exe:						Domino Program
ncatalog.exe:						Domino Program
NCDaemon.exe:						!!! Mcafee Scanner for Lotus Notes !!!
NCIArchive.exe:						WINPAK2 Access Control
NCICore.exe:						WINPAK2 Access Control
nclaunch.exe:						Nclaunch
NclRSSrv.exe:						PC Connectivity Solution
NclTray.exe:						Nokia Connection Manager
ncltray.exe:						Nokia Connection Manager
NclUSBSrv.exe:						PC Connectivity Solution Transports
NCM.exe:						Dialogic Host Media Processing
ncmsvc.exe:						*** FRIENDLY TOOL - Seek Help ***
NCPBUDGT.EXE:						WatchGuard Mobile VPN
ncpclcfg.exe:						WatchGuard Mobile VPN
NCProTray.exe:						SEC Natural Color Pro
NCPRWSNT.EXE:						WatchGuard Mobile VPN
NCPSEC.EXE:						WatchGuard Mobile VPN
ncrsvc.exe:						*** FRIENDLY TOOL - Seek Help ***
ncssvc.exe:						*** FRIENDLY TOOL - Seek Help ***
NcsWmiCo.exe:						Intel WMI
NcsWmiEv.exe:						Intel WMI
ndcx3xyq.exe:						??? Adtomi Spyware ???
nddaegnt.exe:						*** MOSSFERN ***
nddeagnt.exe:						Network Dynamic Data Exchange Agent
NDDEAGNT.EXE:						Network DDE Agent
ndesign.exe:						Domino Program
ndetect.exe:						!!! Symantec !!!
ndiiop.exe:						Lotus Domino
ndisuio.sys:						NDIS User Mode I/O NDISUIO) NDIS protocol driver
ndstray.exe:						Toshiba ConfigFree Traybar
NDSTray.exe:						Toshiba ConfigFree Traybar
neactrls.exe:						Open Fast Track Server
NED53J.exe:						Nokia Siemens NED 6.0
NEDTray.exe:						Nokia Siemens NED 6.0
Nemgr_marine.exe:						Huawei T2000
Nemgr_ngwdm.exe:						Huawei T2000 Element Mgmt Software
Nemgr_ptn.exe:						Huawei T2000
Nemgr_rtn.exe:						Huawei T2000
Nemgr_sdh.exe:						Huawei T2000
Nemgr_wdm.exe:						Huawei T2000
neo.exe:						Price Patrol
neocapture.exe:						NeoDVD Module
neoCapture.exe:						NeoDVD Module
neocopy.exe:						NeoDVD Module
neoCopy.exe:						NeoDVD Module
neoDVD.exe:						NeoDVD Module
neodvd.exe:						NeoDVD Module
neodvdstd.exe:						NeoDVD Module
neoDVDstd.exe:						NeoDVD Module
neotrace.exe:						!!! McAfee NeoTrace !!!
neproxy.exe:						Huawei T2000
neproxy.exe:						Huawei T2000 Element Mgmt Software
nero.exe:						Ahead Nero
nerocheck.exe:						Nero Driver Monitor
nerofiltercheck:						Nero Driver Monitor
neronet.exe:						Network-capable Nero CD/DVD burner
nerosmartstart.exe:						Ahead Nero SmartStart
NeroStartSmart.exe:						Nero 7
nerosvc.exe:						Nero Security Service
net.exe:						NET Commands
NET.EXE:						NET Commands
net1.exe:						NET Commands helper
NET1.EXE:						NET Commands helper
netac.exe:						??? Trojan/Backdoor ???
netalertclient.exe:						!!! GoldenDolphin Chinese IDS !!!
netcfg.exe:						!!! Kaspersky Network Configuration Tool !!!
netclient.exe:						Net Administrator Client
netd32.exe:						??? RANDEX.F virus Virus ???
netdde.exe:						Microsoft Windows Network DDE server
NETDDE.EXE:						Network DDE
netddeclnt.exe:						??? Codbot-M Worm ???
NetFlowService.exe:						SolarWinds Orion
netinfo.exe:						??? Tilebot-J Worm Module ???
netlib.exe:						??? Crater-A Trojan/Worm ???
netlimiter.exe:						LockTime NetLimiter
netlink32.exe:						??? Backdoor.W32.Agent ???
netmail.exe:						??? PSW.NetMail.10 Trojan ???
netmeeting.exe:						??? W32.Dinoxi.B Trojan ???
netmon.exe:						+++ Network Monitor +++
NeTmSvNT.exe:						NetTime 2.0
NetPerfMon.exe:						Solarwinds tool
NetPerfMonServi:						Solarwinds
NetPerfMonServi:						Solarwinds
NetPerfMonService.exe:						SolarWinds Network Performance Monitor
netscape.exe:						Netscape Web Browser
NetscapeMTA.exe:						Netscape Messanging Server
netscp.exe:						Netscape Browser
netscp6.exe:						Netscape 6
netserver.exe:						Net Administrator Server
netstat.exe:						+++ Windows Network Statistics +++
netsurf.exe:						??? Optimum Online Spyware ???
NetSvc.exe:						??? Trojan.W32.Mytob ???
netsvc.exe:						??? Trojan.W32.Mytob ???
netsvcs:						COM+ Event System
NetTime.exe:						NetTime 2.0
netwaiting.exe:						netwaiting
Network-Monitor-Maint.exe:						Solarwinds tool
Network-Monitor.exe:						Solarwinds tool
network.exe:						??? Trojan.W32.Vixup ???
NetworkAgent.exe:						Websense Web Security / Web Filter
NetworkLicenseServer.exe:						ABBYY FineReader 9.0
networx.exe:						!!! Networx Bandwidth Monitor !!!
netxray.exe:						+++ NetXRay Network Monitor +++
nevent.exe:						Domino Program
new_zealand.exe:						??? Dialer.W32.newzealand ???
newdevin.exe:						??? ABetterInternet Transponder Spyware ???
newdial.exe:						??? Adware.W32.SpySheriff ???
newdot.exe:						newdotnet malware
newpop447.exe:						??? Adware.W32.Network1 ???
newpop61.exe:						??? Adware.W32.Network1 ???
newpop62.exe:						??? Adware.W32.Network1 ???
newpop63.exe:						??? Adware.W32.Network1 ???
newsupd.exe:						Creative Labs News
newupdate.exe:						??? Adware.W32.BargainBuddy ???
nfomon.exe:						??? Adware.W32.DelFin ???
nfsclnt.exe:						MS NFS Client
nfsiod.exe:						??? Trojan ???
nfUMSagent.exe:						IBM Systems Director
nGAAgentMgr.exe:						NetScout nGenius Real-Time Monitor
ngctw32.exe:						!!! Symantec !!!
ngen.exe:						.Net Native Image Generator
NGeniusNativeSe:						NetScout nGenius Real-Time Monitor
NGeniusService.:						NetScout nGenius Real-Time Monitor
ngserver.exe:						!!! Symantec !!!
nhksrv.exe:						Netropa Hotkey Server task
nhldaemn.exe:						IBM Lotus Notes Daemon
nhostsvc.exe:						NetOp Helper Service for Windows NT
NHOSTSVC.EXE:						NetOp Host for NT Service
nhsrvice.exe:						NetHASP License Manager Service
nhstw32.exe:						NetOp Remote Control Host
ni_nic.exe:						Intel DMI 2.0
nicconfigsvc.exe:						Dell Power Management Module
nicserv.exe:						Wireless Communications Helper
nilaunch.exe:						Net-It Launcher
nimap.exe:						IBM Lotus Notes/Domino
Ninja.exe:						InteLife Keyboard Ninja (Layout Switcher)
nip.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
NIP.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
Nip.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
nipsvc.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
nisoptui.exe:						!!! Symantec !!!
nisserv.exe:						!!! Symantec !!!
NisSrv.exe:						Microsoft Network Inspection System
nisum.exe:						!!! Symantec !!!
nisvcloc.exe:						National Instruments Service Locator
Nixicon.exe:						Nixicon Dictionary
NJeeves.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
njeeves.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
Njeeves.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
nKavMailMonitor.exe:						IBM Lotus Notes/Domino
nKavUpdater.exe:						IBM Lotus Notes/Domino
nkbmonitor.exe:						PictureProject Module
nkvmon.exe:						Nikon Monitor
nl.exe:						??? Iambigbrother Spyware ???
nlbmgr.exe:						Microsoft Network Load Balancer NLB)
NLClient.exe:						!!! Netlimiter Traffic Monitor !!!
nldap.exe:						IBM Lotus Notes/Domino
nldrw32.exe:						NetOP Remote Control
nlnotes.exe:						Domino Notes Program
nlnp49.exe:						??? Adware.W32.BargainBuddy ???
nls.exe:						??? Win32.Agent.y Spyware ???
nlsvc.exe:						!!! LockTime NetLimiter 2 Monitor !!!
NMAGENT.EXE:						!!! Network Monitor Agent !!!
nmain.exe:						!!! Symantec !!!
nmapp.exe:						Pure Networks Network Magic
nmbgmonitor.exe:						Nero Home
NMIndexingService.exe:						Nero Home 7
nmindexstoresvr.exe:						Nero Home
NMIndexStoreSvr.exe:						Nero Home 7
NMIndexStoreSvr.exe:						Nero Home 7
Nml_ason_sdh.exe:						Huawei T2000
Nml_ason_wdm.exe:						Huawei T2000
Nml_common.exe:						Huawei T2000 Element Mgmt Software
Nml_eth.exe:						Huawei T2000 Element Mgmt Software
Nml_otn.exe:						Huawei T2000 Element Mgmt Software
Nml_ptn.exe:						Huawei T2000
Nml_sdh.exe:						Huawei T2000 Element Mgmt Software
nmlsserv.exe:						NetManage ViewNow X Server
nmsaccess.exe:						Realtime Backup Module
NMSAccessU.exe:						CDBurnerXP
nmsd.exe:						CAD Pro Engineer
nmsrvc.exe:						Pure Networks Network Magic
nmssvc.exe:						Network Management Station Service
NMSSvc.Exe:						Intel Network Management Station Service
NMSSvc.exe:						Intel network card SNMP
NMSSvc.exe:						Intel network card SNMP
nmstt.exe:						??? SMALL-DT Trojan ???
nmtc.exe:						IBM Lotus Notes/Domino
NmWebService.exe:						+++ IPswitch Network Monitoring Software +++
nncron.exe:						CRON clone for windows
nnguard.exe:						CRON clone for windows
nnservicectrl.exe:						System tray for Network-capable Nero CD/DVD burner
nnstp_bbi6009.exe:						??? Adware.W32.BargainBuddy ???
nntray.exe:						Net Nanny Tray Icon
noads.exe:						Noads
noat.exe:						??? TROJ_BAGLE.AP Trojan ???
nod32.exe:						!!! Nod32 !!!
nod32krn.exe:						!!! Nod32 !!!
nod32kui.exe:						!!! Nod32 !!!
NOD32view.exe:						!!! NOD32 Update Viewer !!!
nokiaaserver.exe:						Nokia Ovi Suite
NokiaMServer.exe:						Nokia Ovi Suite
NokiaOviSuite.exe:						Nokia Ovi Suite
nomoreporn.exe:						TIBS Dialer
nopat.exe:						??? Mitglieder.N Trojan ???
nopdb.exe:						Nopdb
nor32.exe:						PSEXEC
norton update.exe:						??? W32/Zafi-D Worm ???
noserver.exe:						SpyAnywhere
nostealth.exe:						SpyAnywhere
note.exe:						??? Trojan.W32.Hyborate ???
notedit.exe:						??? Trojan.W32.QQPASS ???
notepad.exe:						Notepad
NOTEPAD.EXE:						NOTEPAD.EXE Notepad
notepro.exe:						NoteTab Pro
notesweb.exe:						??? Backdoor.Trojan ???
notify.exe:						Notify
Notify_Service.exe:						Huawei iManager T2000 Element Management Software
notifyalert.exe:						Dell Notifier
NotifyServer.ex:						SC Notify Service
NotifyServer.exe:						Switch Commander Application
notiman.exe:						Creative Notification Manager
noyriaszutfdxupw.exe:						??? Adware.W32.CashSaver ???
npfmntor.exe:						!!! Symantec !!!
NPFMSG.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
npfmsg.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
Npfmsg2.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
Npfsvice.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
npkcsvc.exe:						??? Trojan-Downloader.Win32.Agent ???
NPMAlertEngine.exe:						Solarwinds tool
npop3.exe:						Domino POP3 Server
nprocmon.exe:						IBM Lotus Notes/Domino
nprotect.exe:						!!! Symantec !!!
NPROTECT.EXE:						!!! Symantec !!!
NPSAgent.exe:						Samsung New PC Studio
npscheck.exe:						!!! Symantec !!!
npssvc.exe:						!!! Symantec !!!
nrcs.exe:						??? Tojan.W32.Ranky ???
nreplica.exe:						Lotus Notes replication process
NRMENCTB.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
nrmenctb.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
nrnrmgr.exe:						IBM Lotus Notes/Domino
nrouter.exe:						Domino Program
nrpc.exe:						??? Downloader.W32.QDown ???
nscagent.exe:						??? Unknown ???
nscheck.exe:						??? Nettsetter Spyware ???
nsched.exe:						Domino Program
NSCM.exe:						Possibly Windows Media Server
nscm.exe:						Possibly Windows Media Server
NSContentStore.:						NetScout nGenius Real-Time Monitor
nscsrvce.exe:						!!! Symantec !!!
nsctop.exe:						!!! Symantec !!!
NscTop.exe:						!!! Symantec !!!
nserver.exe:						Domino Program
nservice.exe:						IBM Lotus Notes/Domino
nsh136.exe:						??? Downloader.W32 ???
nsl.exe:						NetStat Live
nslsvice.exe:						Lotus Notes Component
nSMDemf.exe:						!!! TrendMicro !!!
nSMDmon.exe:						!!! TrendMicro !!!
nSMDreal.exe:						!!! TrendMicro !!!
nSMDsch.exe:						!!! TrendMicro !!!
nsmdtr.exe:						!!! Symantec !!!
NSMdtr.exe:						!!! Symantec !!!
nsmtp.exe:						Domino SMTP Program
NSnGeniusNative:						NetScout nGenius Real-Time Monitor
nspm.exe:						Possibly Windows Media Server
NSPMON.exe:						Windows Media Monitor Service
nsrd.exe:						NetWorker Backup and Recover
nsrexecd.exe:						NetWorker Remote Exec Service
nsrindexd.exe:						NetWorker process
NSRmiregistry.e:						NetScout nGenius Real-Time Monitor
nsrmmd.exe:						NetWorker process
nsrmmdbd.exe:						NetWorker process
nsrpm.exe:						NetWorker Power Monitor
NSSM.exe:						Switch Commander Application
NSSMDllHost.exe:						SC process
nssys32.exe:						??? nsdriver  virus ) Virus ???
nstask32.exe:						??? RANDEX.E virus Virus ???
nstates.exe:						Lotus Domino
NSTomcat.exe:						NetScout nGenius Real-Time Monitor
nsum.exe:						Windows Media Unicast Service
nsupdate.exe:						??? Nsupdate trojan ???
nsupdate.exe:						??? Nsupdate Trojan???
nsvcappflt.exe:						NVIDIA Network Access Manager
nsvr.exe:						Backup Exec 7.x/8.x Notification Server
nsvsvc.exe:						??? Adware.W32.DelFin ???
NSWarehouse.exe:						NetScout nGenius Real-Time Monitor
nt_usdm.exe:						Epox Motherboard Utility
ntaskldr.exe:						IBM Lotus Component
ntbackup.exe:						Windows Backup
NTBACKUP.EXE:						NTBACKUP.EXE Backup Utility
Ntbtrv.exe:						Btrieve for Windows NT Server)
NTBTRV.EXE:						Btrieve for Windows NT Server)
ntcaagent.exe:						!!! Huawei SACC Agent !!!
ntcadaemon.exe:						!!! Huawei SACC Agent !!!
ntcaservice.exe:						!!! Huawei SACC Agent !!!
ntConsoleJava.e:						ColdFusion
ntdetect.exe:						??? Trojan.W32.Small ???
ntfrs.exe:						File Replication Service
ntfs64.exe:						??? WORM_WOOTBOT.FQ Trojan Virus Trojan ???
ntfs64.exe:						??? WORM_WOOTBOT.FQ Trojan ???
ntguard.exe:						Dr Solomons WinGuard for Windows NT
ntmulti.exe:						IBM Lotus Component
ntosa32.exe:						??? W32.HLLW.Anig Trojan ???
NTOSA32.exe:						??? W32.HLLW.Anig Trojan Virus Trojan ???
NTOSA32.exe:						??? W32.HLLW.Anig Trojan ???
ntoskrnl.exe:						Microsoft Boot Up Kernel
NTPClient.exe:						MSC BAM Services
ntpd.exe:						Network Time Protocol (Switch)
ntrayfw.exe:						NVIDIA Firewall Traybar Module
ntrights.exe:						NTRights Public Domain Application
ntrouter.exe:						Novell cc
ntrtscan.exe:						!!! TrendMicro OfficeScan !!!
NTRtScan.exe:						!!! TrendMicro OfficeScan !!!
ntsd.exe:						Symbolic Debugger for Windows
NTService.exe:						SUPERMICRO Supero Doctor III Client
ntsys.exe:						??? Trojan.W32.Beagle ???
ntvdm.exe:						Windows 16-bit Virtual Machine
NTVDM.EXE:						DOS and Win16 Support
nukenabber.exe:						+++ NukeNabber IDS System +++
nukenabber.exe:						+++ NukeNabber IDS System +++
nupdate.exe:						Domino Program
nutsrv4.exe:						NuTCRACKER 4
nvcoas.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
NVCOAS.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
Nvcoas.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
NVCPL.EXE:						??? W32.SpyBot.S Worm Virus Trojan ???
nvcpl.exe:						??? W32.SpyBot.S Worm ???
nvcpldaemon:						NVidia Graphics Library Module
nvcsched.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
NVCSched.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
Nvcsched.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
nvctrl.exe:						??? Trojan.W32.Zlob ???
nvmctray:						See
nvmediacenter:						NVidia MediaCenter
nvmixertray.exe:						NVIDIA NVMixerTray
nvraidservice.exe:						nVidia NVRaid Service
nvsc32.exe:						??? Backdoor.IRC.Bot Trojan ???
nvSCPAPISvr.exe:						NVIDIA 3D Vision
nvstartup:						Nvidia Graphics Helper
nvsvc.exe:						NVIDIA Driver Helper Service
nvsvc32.exe:						Nvidia graphics card driver
nvsvc64.exe:						NVIDIA x64 Display Driver
nvvsvc.exe:						Vista NVIDIA driver helper service
nwereboot:						Ahead Nero CD/DVD Temporary file
nwiz.exe:						NVIDIA nView Wizard
nwtray.exe:						Novell Netware tray application
nymse.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
Nymse.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
nzuvzu.exe:						??? Downloader.W32.Qoologic ???
o2flash.exe:						O2Micro Flash Memory Service
OAMEventService.exe:						Dialogic Host Media Processing
oasclnt.exe:						!!! McAfee VirusScan Module !!!
obllak.exe:						??? Adware.W32.DealHelper.com ???
ObserverService.exe:						Dialogic Host Media Processing
ocraware.exe:						Ocraware
OCS_OCP_Echo.exe:						AP/OCS Switch Control
ocspsvc.exe:						Microsoft OCSP Responder
ocxdll.exe:						??? mIRC virus Virus ???
odcfg.exe:						??? AdClicker Spyware ???
odhost.exe:						Wireless-G Notebook Adapter Process
oeet.exe:						??? Adware.W32.PurityScan ???
oeloader.exe:						??? xupiter.com Spyware ???
OEM02Mon.exe:						Creative Live! Cam Console
oeqt4.exe:						OE Quick Tools
oespamtest.exe:						!!! Kaspersky Anti-Spam for Outlook or Outlook Express !!!
Ofant.exe:						Computer Associates BrightStor Backup Agent
ofcdog.exe:						!!! TrendMicro !!!
ofcpfwsvc.exe:						!!! TrendMicro OfficeScan Personal Firewall !!!
OfcPfwSvc.exe:						!!! TrendMicro Personal Firewall !!!
offers.exe:						??? Adware.W32.Claria ???
office.exe:						??? Lovgate Worm ???
OfficeIntegration.exe:						Directum
OfficeLiveSignIn.exe:						Microsoft Office Live
OFFLB.exe:						MS Office Program Recovery
offprov.exe:						Office Data Provider for WBEM
offun.exe:						??? Adware.W32.PacerD ???
Ofps.exe:						ScanSoft OmniForm Module
ofps.exe:						ScanSoft OmniForm Module
OI.EXE:						NCH Swift Sound Office Intercom
oi.exe:						NCH Swift Sound Office Intercom
ois.exe:						Microsoft Office Picture Manager
okclient.exe:						!!! Cisco Security Agent !!!
okclient.exe:						!!! Cisco Security Agent 5.1 !!!
olehelp.exe:						??? CoolWebSearch Spyware ???
Olehelp.exe:						??? CoolWebSearch Spyware ???
olfsnt40.exe:						!!! Symantec !!!
OLFSNT40.EXE:						!!! Symantec !!!
omaws32.exe:						Dell Openmange
omlpr.exe:						Network LPR Utility
OmniInet.exe:						OmniBack II Inet
omniscient.exe:						??? Search Assistant adware Spyware ???
omniserv.exe:						Softex OmniPass
Omniserv.exe:						Softex OmniPass
omsad32.exe:						Dell Openmange
OMSLogManager.exe:						!!! Secret Net !!!
omtsreco.exe:						Oracle Database
ONENOTEM.exe:						Microsoft Office OneNote
onetouch.exe:						OneTouch backup system Assistant
onfserv.exe:						Onfolio Server
online.exe:						yandex webmail server
ONLINENT.exe:						!!! Omniquad Total Security 3.0.0 !!!
ONLNSVC.exe:						!!! Omniquad Total Security 3.0.0 !!!
ONRSD.EXE:						Oracle Ora Client
onspeedcore.exe:						SlipStream Accelerator Core Services
onsrvr.exe:						??? OnWebMedia Spyware ???
oobechk.exe:						Microsoft 'Manage Your Server' UI
oocinst.exe:						O&O Component Installer Agent
OODAG.EXE:						O&O Defrag
oodag.exe:						O&O Defrag
ooVoo.exe:						Video Chat
op_viewer.exe:						!!! Sophos FIREWALL GUI is OPEN !!!
opc.ua.discoveryserver.exe:						OPC Foundation Dev
opcacta.exe:						HP OpenView
opcapm.exe:						HP OpenView
opcctla.exe:						HP OpenView
opcle.exe:						HP OpenView
opcmon.exe:						HP OpenView
opcmona.exe:						HP OpenView
opcmsga.exe:						HP OpenView
opcmsgi.exe:						HP OpenView
opcntprocs.exe:						HP OpenView
opcwbemi.exe:						HP OpenView
openvpn-gui.exe:						OpenVPN GUI component
openvpn.exe:						OpenVPN daemon
opera.exe:						Opera Browser
Opera.exe:						Opera web browser
oprotsvc.exe:						Ownership Protocol Service
opscan.exe:						!!! Symantec !!!
optimize.exe:						??? Optimize Dialler ???
optimize313.exe:						??? Spyware.W32.DyFuCA ???
optimize314.exe:						??? Spyware.W32.DyFuCA ???
optimize[1].exe:						??? Spyware.W32.DyFuCA ???
OptiQuant.exe:						OptiQuant
OpUtils.exe:						ManageEngine OpUtils Network Management
opware12.exe:						ScanSoft OmniPage Pro 12
opware32.exe:						ScanSoft OmniPage Opware
opwarese2.exe:						ScanSoft OmniPage Module
OpWareSE4.exe:						ScanSoft OmniPage
opxpapp.exe:						Softex OmniPass Component
ORACLE.EXE:						Oracle OraHome 8.1?
oracle.exe:						Oracle
ORACLE73.EXE:						Oracle?
orbitdm.exe:						Orbit Downloader
orbitnet.exe:						Orbit Downloader
orderreminder.exe:						HP cartridge order reminder
orfeesvc.exe:						ORF Enterprise Exchange Spam Filter
orffp.exe:						??? Dialer.W32.Downloader ???
OrionCustomPollingService.exe:						SolarWinds Orion
OrionNetPerfMon:						Solarwinds
OrionNetPerfMon:						Solarwinds
OrionNetPerfMon.exe:						Solarwinds
OSA.EXE:						Office Startup Application
osa.exe:						Microsoft Office Startup Assistant
osa9.exe:						Office Startup Assistant
osagent.exe:						Cisco Works
osalogbe.exe:						??? Trojan.W32.MyDoom ???
osd.exe:						OnScreen Display System Tray icon
osdmenu.exe:						Creative OSD Menu
ose.exe:						Microsoft Office Source Engine
OSE.EXE:						Microsoft Office Source Engine
osk.exe:						??? Spyware ???
oskasetup_demo.exe:						??? Adware.W32.BargainBuddy ???
OSPPSVC.EXE:						Microsoft Office Software Protection Platform
osppsvc.exe:						MS Office
ossproxy.exe:						Marketscore ossproxy
othb.exe:						??? Adware.W32.PurityScan ???
ouc.exe:						Huawei Connect Manager
Outbreak.exe:						Network Associates Outbreak Manager
outlook.exe:						Microsoft Outlook
OUTLOOK.EXE:						Microsoft Outlook
outpost.exe:						!!! Outpost Security !!!
outputfileserver.exe:						BusinessObjects Enterprise 11.5
ovbbccb.exe:						HP OpenView
ovcd.exe:						HP OpenView
ovconfd.exe:						HP OpenView
ovprocrestarter:						SC process
ovspmd.exe:						HP OpenView Process Manager
OvSvcDiscAgt.exe:						HP OpenView Service Discovery Agent
ovtopmd.exe:						HP OpenView process
ovtrapd.exe:						HP OpenView process
ovtrcsvc.exe:						HP OpenView
ovuispmd.exe:						HP OpenView process
ovwdb.exe:						HP OpenView process
owastsvr.exe:						Oracle Web Assistant
owmngr.exe:						??? OnWebMedia Spyware ???
OWSTIMER.EXE:						Office Server Extensions Notification Service
P. IDMan 5.11.8 by yerdenizden.exe:						Portable Internet Download Manager
p2p networking.exe:						??? Adware.W32.P2PNetworking ???
p2p networking2.exe:						??? Adware.W32.P2PNetworking ???
p2p networking3.exe:						??? Adware.W32.P2PNetworking ???
p2pnetworking.exe:						P2P Networking AdWare
p2pnetworking3.exe:						P2P Networking AdWare
P6.exe:						Arabic language tool
p_981116.exe:						Win32 Cabinet Self-Extractor
paamsrv.exe:						!!! Acronis Privacy Expert Suite !!!
pacis.exe:						??? SMALL.ABD Variant Trojan ???
package8032_siac[1].exe:						??? Adware.W32.BargainBuddy ???
PACKAGER.EXE:						Microsoft Packager
packager.exe:						Microsoft Packager
packethsvc.exe:						Virtual Adapter Service
PacketTracer4.exe:						Cisco Packet Tracer
PacketTracer5.exe:						Cisco Packet Tracer (network simulator)
padexe.exe:						Toshiba Touchpad Module
PadFSvr.exe:						!!! Panda !!!
pagent.exe:						!!! Panda Enterprise !!!
Pagent.exe:						!!! Panda Enterprise !!!
pagentwd.exe:						!!! Panda Enterprise !!!
Pagentwd.exe:						!!! Panda Enterprise !!!
pageserver.exe:						BusinessObjects Enterprise 11.5
PArchiveD.exe:						Kodak Prinergy document processing workflow
partseal.exe:						Vaio System Back-Up
parvulus.exe:						??? Backdoor.W32.Lupar ???
pascl32.exe:						Pas-tool
passrv.exe:						Panda Antispam Server Service
PassThruSvr.exe:						HTC Internet Pass-Through
password_manager.exe:						Lenovo Password Manager
PasswordDecrypt.exe:						Solarwinds tool
pastisvc.exe:						STI Simulator
PASystemTray.exe:						!!! Panda !!!
patch.exe:						!!! TrendMicro PC-cillin !!!
PatrolAgent.exe:						BMC Patrol Asset Management)
PatrolPerf.exe:						BMC Patrol Asset Management)
PAutomationD.ex:						Kodak Prinergy document processing workflow
PAutomationD.exe:						Kodak Prinergy document processing workflow
pav.exe:						Per Antivirus
PavBckPT.exe:						!!! Panda Internet Security !!!
pavbckpt.exe:						!!! Panda Internet Security !!!
pavfires.exe:						!!! Panda Anti-Virus !!!
pavfnsvr.exe:						!!! Panda Internet Security !!!
PAVFNSVR.exe:						!!! Panda Internet Security !!!
PavFnSvr.exe:						!!! Panda !!!
pavjobs.exe:						!!! Panda Internet Security !!!
pavkre.exe:						!!! Panda Anti-Virus !!!
Pavkre.exe:						!!! Panda !!!
pavmail.exe:						!!! Panda Anti-Virus !!!
pavprot.exe:						!!! Panda Anti-Virus !!!
PavProt.exe:						!!! Panda !!!
pavprsrv.exe:						!!! Panda Anti-Virus !!!
PavPrSrv.exe:						!!! Panda Internet Security !!!
PavReport.exe:						!!! Panda !!!
pavsched.exe:						!!! Panda Anti-Virus !!!
pavsrv50.exe:						!!! Panda Anti-Virus !!!
pavsrv51.exe:						!!! Panda Anti-Virus !!!
PAVSRV51.exe:						!!! Panda Internet Security !!!
pavsrv52.exe:						!!! Panda Anti-Virus !!!
pavupg.exe:						!!! Panda AdminSecure upgrade utility !!!
paytime.exe:						??? Dialer.W32.TIBS ???
Payvast.Shell.exe:						Payvast Accounting System
PayvastSrv.exe:						Payvast Accounting System
pbds.exe:						PrimeBase Adobe) SQL Database Server
pbeagent.exe:						PowerChute Business Edition Agent Module
pbeserver.exe:						PBE Server
PBESER~1.EXE:						APC PowerChute UPS Monitor
PBESER~1.EXE:						APC PowerChute UPS Monitor
pbl8ey0e.exe:						??? Adtomi Spyware ???
pbx_exchange.exe:						Symantec Public Branch Exchange Process NetBackup/NOM)
PbxCollect.exe:						WinTariff32 PBX
pcard.exe:						360 Degree Web SCardProgram
pcbooster.exe:						PC Booster
pccclient.exe:						!!! TrendMicro PC-cillin !!!
pccguide.exe:						!!! TrendMicro PC-cillin !!!
pcclient.exe:						!!! TrendMicro PC-cillin !!!
PCCMFLPD.EXE:						Panasonic
PCCMFSDM.exe:						Panasonic Device Manager
pccnt.exe:						!!! TrendMicro PC-cillin !!!
pccNT.exe:						!!! TrendMicro !!!
pccntmon.exe:						!!! TrendMicro PC-cillin !!!
PccNTMon.exe:						!!! TrendMicro PC-cillin !!!
pccntupd.exe:						!!! TrendMicro PC-cillin !!!
PccNTUpd.exe:						!!! TrendMicro !!!
PCCompanion.exe:						Sony Ericsson PC Companion
PCCompanionInfo.exe:						Sony Ericsson PC Companion
pccpfw.exe:						!!! TrendMicro PC-cillin !!!
pcctlcom.exe:						!!! TrendMicro !!!
PcCtlCom.exe:						!!! TrendMicro !!!
PCEPSConversion:						Kodak Prinergy document processing workflow
pcfmgr.exe:						PowerPannel
pchbutton.exe:						Hewlett-Packard Instant Support Software
pchealth.exe:						??? W32.Cone ???
pchschd.exe:						Microsoft Windows ME PC Health Client Scheduler
PCINSSUI.exe:						NetSupport School
PCMFSMLM.exe:						Panasonic
pcmm.exe:						PC MightyMax
PCMService.exe:						Dell media experienc
pcmservice.exe:						Dell media experienc
pcns.exe:						PowerChute Network Shutdown APC UPS)
pcnssvc.exe:						Microsoft Password Change Notification
PColorMatcherJT:						Kodak Prinergy document processing workflow
PCreoTrapJTP.ex:						Kodak Prinergy document processing workflow
PCreoTrapJTP.exe:						Kodak Prinergy document processing workflow
pcscan.exe:						!!! TrendMicro PC-cillin !!!
PcScnSrv.exe:						!!! TrendMicro !!!
PCSuite.exe:						Nokia PC Suite 7
pcsvc.exe:						??? The Delfin Project Adware Spyware ???
pcsync.exe:						Nokia PC Suite
pcsync2.exe:						Nokia PC Suite
PCTMTransJTP.ex:						Kodak Prinergy document processing workflow
PCTMTransJTP.exe:						Kodak Prinergy document processing workflow
pctptt.exe:						PCTEL Communications
pctsAuxs.exe:						!!! Spyware Doctor !!!
pctsGui.exe:						!!! Spyware Doctor !!!
pctspk.exe:						PCTEL Communications
pctsSvc.exe:						!!! Spyware Doctor !!!
pctsTray.exe:						!!! Spyware Doctor !!!
pctvoice.exe:						PCTEL Modem
PCTVoice.exe:						PCTEL Modem
PCTWmiQuery.xpc:						BMC Patrol Agent
Pd.exe:						SC Communication Server
pdesk.exe:						Matrox PowerDesk
PDeviceAndServi:						Kodak Prinergy document processing workflow
PDFClient.exe:						Jaws PDF Creator
PDFCreatorMessages.exe:						Jaws PDF Creator
PdfPro6Hook.exe:						PDF Pro
PDFProFiltSrv.exe:						PDF Pro
pdfsty.exe:						PDFComplete PDF Maker
pdfsvc.exe:						PDF Complete
PDiagnosticD.ex:						Kodak Prinergy document processing workflow
PDiagnosticD.exe:						Kodak Prinergy document processing workflow
PDS.EXE:						Intel Ping Discovery Service
pds.exe:						Intel Ping Discovery Service
pdsched.exe:						??? SDBOT.CN WORM Virus Trojan ???
pdservice.exe:						SafeGuard PrivateDisk Service
PDVDDXSrv.exe:						CyberLink PowerDVD DX
pdvdserv.exe:						PowerDVD Remote Control
PDVDServ.exe:						PowerDVD Remote Control
pec.exe:						??? Adware.W32.Windupdates ???
pelmiced.exe:						IBM Mouse Suite 98 Daemon
pep.exe:						!!! CA Jinchen KILL / eTrust Antivirus !!!
perfcl.exe:						??? Downloader.W32.Small ???
PerfDataMonitor:						SC process
PerfDataMonitor.exe:						Switch Commander Application
perflbd.exe:						HP OpenView
PERFMON.EXE:						Performance Monitor
Perl.exe:						PERL.EXE Perl interpreter
perl.exe:						PERL.EXE Perl interpreter
persfw.exe:						!!! Kerio Personal Firewall 2.1.5 !!!
pes4.exe:						Pro Evolution Soccer 4
pes_clh_server.exe:						AP/PES Switch Control
pescleanup.exe:						IBM Cognos Series 7 (Business Mgmt)
pf78.exe:						??? Adware.W32.CasinoClient ???
PFileD.exe:						Kodak Prinergy document processing workflow
PFileSummaryD.e:						Kodak Prinergy document processing workflow
PFileSummaryD.exe:						Kodak Prinergy document processing workflow
pg2.exe:						Peer Guardian 2
pg_ctl.exe:						PostgreSQL Control Process
pgmonitr.exe:						??? PromulGate Spyware ???
PGPmnApp.exe:						PGP Desktop
PGPsdkServ.exe:						PGP Software Development Kit
pgpserv.exe:						PGP Desktop
PGPserv.exe:						PGP Desktop SDK Service
PGPservice.exe:						PGP Service
PGPtray.exe:						Network Associates PGP System Tray Application
pgptray.exe:						Network Associates PGP System Tray Application
ph2ldap.exe:						Eudora WorldMail Ph2Ldap Proxy
phantom.exe:						??? W32.Mytob.KC\@mm Worm ???
PhAutoRun.exe:						Panasonic PHOTOfun STUDIO
phbase.exe:						Arcsoft Photobase
phime2002a:						Input Message Editor
phixin.exe:						??? Adware.W32.PromulGate ???
PHotFolderD.exe:						Kodak Prinergy document processing workflow
photoshop.exe:						Adobe Photoshop
photoshopelementsdeviceconnect.exe:						Adobe Photoshop Elements Module
photoshopelementseditor.exe:						Adobe Photoshop Elements
photoshopelementsfileagent.exe:						Adobe Photoshop Elements
photoshopelementsorganizer.exe:						Adobe Photoshop Elements Organizer
php-win.exe:						PHP Extension for Windows
phqghume.exe:						??? Trojan.W32.Rbot ???
pib.exe:						??? PIB Toolbar Spyware ???
PIB.exe:						??? PIB Toolbar Spyware ???
picasamediadetector.exe:						Picasa Picture Management Module
picsvr.exe:						??? Adware.W32.DelFin ???
pictureshare.exe:						??? Adware.W32.GoGoTools ???
pictureviewer.exe:						??? Trojan.W32.Marlap ???
picx.exe:						??? W32/Mytob-EX Trojan ???
pidgin.exe:						Pidgin instant messaging client
PImpExpJTP.exe:						Kodak Prinergy document processing workflow
pinball.exe:						Microsoft Pinball
Ping.exe:						PING.EXE Ping Command
ping.EXE:						PING.EXE Ping Command
ping.exe:						PING.EXE Ping Command
PING.EXE:						PING.EXE Ping Command
Pinger.exe:						Toshiba software upgrades
pinger.exe:						TOSHIBA Pinger
PingSweep.exe:						Solarwinds tool
PInSiteProxySer:						Kodak Prinergy document processing workflow
pisf.exe:						??? Backdoor.W32.Delf ???
PJobD.exe:						Kodak Prinergy document processing workflow
PJobLauncherD.e:						Kodak Prinergy document processing workflow
PJobLauncherD.exe:						Kodak Prinergy document processing workflow
PJobTicketCreat:						Kodak Prinergy document processing workflow
PJSCHSVC.EXE:						Microsoft Office Project Server 2003
PJSTATE.EXE:						Microsoft Office Project Server 2003
pjtcyd.exe:						??? Adware.W32.DealHelper ???
PJTRCSVC.EXE:						Microsoft Office Project Server 2003
PKIMonitor.exe:						Aladdin eToken PKIClient
pkjobs.exe:						Caere PageKeeper Jobs
plauto.exe:						Casios Photo Loader
plaxohelper.exe:						Plaxo Helper Module
PlaxoHelper_en.exe:						Plaxo Integration for Microsoft Windows Mail
player.exe:						Webmassiva Player
playlist.exe:						Roxio Playlist
plguni.exe:						QuickClean
PLicMonD.exe:						Kodak Prinergy document processing workflow
PLocatorD.exe:						Kodak Prinergy document processing workflow
plsqldev.exe:						PL-SQL Developer
plug_proxy.exe:						Gauntlet Plug Proxy?
plugin compressor.exe:						??? Trojan.W32.AIMVision ???
plugin-container.exe:						Mozilla Firefox
plugnplay32.exe:						??? Trojan.W32.MyTob ???
PMainDirectoryD:						Kodak Prinergy document processing workflow
PMainDirectoryD.exe:						Kodak Prinergy document processing workflow
PMarkJTP.exe:						Kodak Prinergy document processing workflow
PMBDeviceInfoProvider.exe:						Sony Corporation
PMBVolumeWatcher.exe:						Sony Corporation
PMC860sv.exe:						Force Computers GmbH PMC860SV Service
pmd.exe:						HP OpenView process
pmgpipereader.e:						BMC PATROL Log Management
pmgpipereader.e:						BMC PATROL Log Management
pmgpipereader.e:						BMC PATROL Log Management
pmgpipereader.exe:						BMC Patrol Asset Management)
pmgreader.exe:						BMC Patrol Asset Management)
pmon.exe:						!!! Process Monitor !!!
pmproxy.exe:						Analog Devices SoundMAX Module
pmr.exe:						??? Powerstrip Spyware ???
pmshost.exe:						Media Server Host
pmt.exe:						??? Downloader.W32.3945 ???
pmxinit.exe:						Hercules Pmxinit
pnagent.exe:						Citrix Metaframe process
PnkBstrB.exe:						Punk Buster Game
pnmsrv.exe:						!!! Panda Network Manager !!!
PNmSrv.exe:						!!! Panda !!!
PNormalizerJTP.:						Kodak Prinergy document processing workflow
PNormalizerJTP.exe:						Kodak Prinergy document processing workflow
PNSERVER.EXE:						PNServer
pntiomon.exe:						!!! TrendMicro PC-cillin !!!
pntwatch.exe:						Powerware Netwatch
PNXSERVR.exe:						Grass Valley ProCoder 3
point32.exe:						Microsoft Intellimouse Monitor
pointer.exe:						Genius USB Mouse Driver
points manager.exe:						TopSearch Points Manager
pokapoka:						??? EliteBar Adware ???
pokapoka62.exe:						??? EliteBar Adware ???
pokapoka63.exe:						??? EliteBar Adware ???
pokapoka64.exe:						??? EliteBar Adware ???
pokapoka65.exe:						??? EliteBar Adware ???
pokapoka66.exe:						??? EliteBar Adware ???
pokapoka67.exe:						??? EliteBar Adware ???
pokapoka68.exe:						??? EliteBar Adware ???
pokapoka69.exe:						??? EliteBar Adware ???
pokapoka70.exe:						??? EliteBar Adware ???
pokapoka71.exe:						??? EliteBar Adware ???
pokapoka72.exe:						??? EliteBar Adware ???
pokapoka73.exe:						??? EliteBar Adware ???
pokapoka74.exe:						??? EliteBar Adware ???
pokapoka75.exe:						??? EliteBar Adware ???
pokapoka76.exe:						??? EliteBar Adware ???
pokapoka77.exe:						??? EliteBar Adware ???
pokapoka78.exe:						??? EliteBar Adware ???
pokapoka79.exe:						??? EliteBar Adware ???
poker.exe:						??? Downloader.W32.Agent ???
PolyView.exe:						PolyView Progrm
pop3-gw.exe:						Gauntlet POP3 Proxy?
pop3.exe:						MERAK POP3 Server
pop3a.exe:						MailSite Pop3 Service
POP3A.EXE:						MailSite Pop3 Service
POP3D32.exe:						IMail POP3 Server
POP3d32.exe:						IMail POP3 Server
pop3d32.exe:						IMail POP3 Server
pop3pack.exe:						!!! TrendMicro PC-cillin !!!
POP3S.exe:						IMS Pop3 Server
pop3svr.exe:						Sendmail POP3
pop3trap.exe:						!!! TrendMicro PC-cillin !!!
popcorn72.exe:						??? Downloader.W32.Agent ???
POPROXY.EXE:						!!! Symantec !!!
POProxy.exe:						!!! Symantec !!!
poproxy.exe:						!!! Symantec !!!
POptimizerJTP.e:						Kodak Prinergy document processing workflow
POptimizerJTP.exe:						Kodak Prinergy document processing workflow
popup.exe:						RAID Web Console 2 MegaPopup
popuper.exe:						??? Unknown Spyware Component ???
popupkiller.exe:						xFX JumpStart popupkiller
portaol.exe:						Port Magic Component
portmap.exe:						AR Remedy Ticket
portmapper.exe:						Intel network tools
portmapper.exe:						Intel network tools
portmon.exe:						+++ Port Monitor +++
PortScanner.exe:						Solarwinds tool
PortScanner.exe:						Solarwinds tool
portserv.exe:						SIEMENS
Post.Office.exe:						post.office MTA
postgres.exe:						PostgreSQL Master Process
postmaster.exe:						PostgreSQL
pow.exe:						AnalogX Pow
powercheck.exe:						Jetech PowerCheck
powerdvd.exe:						Cyberlink PowerDVD
powergramo.exe:						Power Gramo Skype Recorder
powerkey.exe:						Acer Powerkey
powermgr.exe:						Power Manager
PowerMonitor.exe:						Eaton Corporation PowerMonitor
POWERPNT.EXE:						Microsoft PowerPoint
powerpnt.exe:						Microsoft PowerPoint
powerreg:						PowerReg Scheduler MalWare
powerreg scheduler.exe:						PowerReg Scheduler MalWare
powers.exe:						BioMech Planar Motion Analysis System
powerscan.exe:						??? Integrated Search Technologies Spyware ???
ppactivedetection.exe:						??? PestPatrol Anti-Spyware ???
PPClean.exe:						!!! CA Internet Security Suite 2007 !!!
ppcontrol.exe:						PestPatrol tray application
PPCtlPriv.exe:						!!! CA Internet Security Suite 2008 Antispyware !!!
ppmcativedetection.exe:						!!! eTrust !!!
ppmcativedetection.exe      :						!!! eTrust !!!
ppmemcheck.exe:						PPMemCheck
PpPpWallRun.exe:						!!! Jiangmin AV and FW !!!
PPreflightD.exe:						Kodak Prinergy document processing workflow
PPrinterJTP.exe:						Kodak Prinergy document processing workflow
PPServ.exe:						Protector Plus Service
pptd40nt.exe:						ScanSoft PaperPort
pptview.exe:						Microsoft Powerpoint Viewer
ppwebcap.exe:						Visioneer ScanSoft
pqhelper.exe:						PowerQuest DriveImage Helper
PQIBrowser.exe:						!!! Symantec !!!
pqibrowser.exe:						!!! Symantec !!!
PQIMountSvc.exe:						PowerQuest DriveImage Process
pqimountsvc.exe:						PowerQuest DriveImage Process
pqinit.exe:						PowerQuest DriveImage Process
pqtray.exe:						PowerQuest DriveImage Traybar Icon
pqv2isecurity.exe:						PowerQuest DriveImage Process
PQV2ISECURITY.EXE:						PowerQuest DriveImage Process
pqv2isvc.exe:						!!! Symantec !!!
praetorian.exe:						Yandex Defender BHO
precisiontime.exe:						??? Adware.W32.ClariaPrecision ???
precisiontimesetup.exe:						??? Adware.W32.ClariaPrecision ???
PRegFileD.exe:						Kodak Prinergy document processing workflow
PRegisterJTP.ex:						Kodak Prinergy document processing workflow
PRegisterJTP.exe:						Kodak Prinergy document processing workflow
preload.exe:						Millenium Multi-Function Keyboard driver
PrepaidAlfaBlom.exe:						Alfa Active Services
PresentationFontCache.exe:						Microsoft .NET Framework
preupd.exe:						AntiVir Update Module
prevsrv.exe:						!!! Panda Anti-Virus !!!
prfldsvc.exe:						Microsoft Private Folder
PrintDevice.exe:						!!! GoldenDolphin Chinese IDS !!!
printnow.exe:						Ziff Davis Media Printnow
printray.exe:						Lexmark Printer Console
PRISMSTA.EXE:						Intersil silicon
prismsta.exe:						Intersil silicon
prismsvr.exe:						PRISM Wireless LAN
prismxl.exe:						Lanovation PrismXL Service
PrivacyIconClient.exe:						Intel Management and Security
privoxy.exe:						Privoxy filtering proxy server
prizesurfer.exe:						??? Prizesurfer Spyware ???
prjlist.exe:						Tamin DB software
prmedsvr.exe:						PROMT Machine Translation System
prmt.exe:						??? OpiStat Spyware ???
prmtsvr.exe:						??? OpiStat Spyware ???
prmvr.exe:						??? YahooStock Spyware ???
pro.exe:						Teleport Pro Web site mirroring?)
pro_comm_msg.exe:						CAD Pro Engineer
procdest.exe:						BusinessObjects Enterprise 11.5
procexp.exe:						!!! Sysinternals Process Explorer !!!
procLov.exe:						BusinessObjects Enterprise 11.5
profiler.exe:						Saitek Profiler
proflwiz.exe:						Microsoft Office Profile Tranfser Wizard
ProgramServer.exe:						BusinessObjects Enterprise 11.5
PROGRESS.EXE:						Veritas NetBackup
ProMain.exe:						GTS diplomatic comms system
PROMon.exe:						Intel Modem Systray Icon
promon.exe:						Intel Pro NIC Console
pronomgr.exe:						Pronomgr
PRONoMgr.exe:						Intel PRO ethernet adapter utility
propelac.exe:						Propel Accelerator Component
proquota.exe:						Microsoft Profile Quota Manager
prosched.exe:						Teleport Pro? Web site mirroring?)
prositefinder.exe:						??? Adware.W32.ProSiteFinder ???
prositefinder1.exe:						??? Adware.W32.ProSiteFinder ???
prositefinderh.exe:						??? Adware.W32.ProSiteFinder ???
prosrvc.exe:						CCure 800 Proximity Badge
prot.exe:						??? Adware.W32.SearchMiracle.EliteBar ???
protcore.exe:						BSS Cbank EDS Software
protector.exe:						SpyAnywhere
ProUtil.exe:						!!! BlackIce Firewall !!!
Prox.exe:						IP-TV Player
Proxy-Ping.exe:						Solarwinds tool
proxy.exe:						Val HTTP-proxy?
prpcui.exe:						Power Supply Monitor by Intel
PRTG:						Paessler Router Traffic Grapher - bandwidth management
PRTG Traffic Gr.exe:						+++ PRTG Network Traffic Grapher +++
PRTG Traffic Grapher.exe:						+++ PRTG Network Traffic Grapher +++
prtgwatchdog.exe:						+++ PRTG Network Traffic Grapher +++
pruttct.exe:						Prutect Malware Component
ps.exe:						Punto Switcher
PS.exe:						Punto Switcher - software for Latin/Cyrillic character conversion
ps1.exe:						??? PacerD Media Adware ???
ps2.exe:						Hewlett Packard multimedia
ps_install-grokster.exe:						??? Adware.W32.PurityScan ???
ps_uninstaller.exe:						??? Adware.W32.PurityScan ???
pscanw.exe:						??? Adware.W32.PurityScan ???
psctris.exe:						!!! Panda Enterprise !!!
PsCtrlS.exe:						!!! Panda Internet Security !!!
psdrvcheck.exe:						Pinnacle Driver Check
pserve.exe:						IMail PWD Server
Pserve.exe:						IMail PWD Server
PServe.exe:						IMail PWD Server
PSERVE.exe:						IMail PWD Server
PSESCoreScheduler.exe:						Konica Minolta Pagescope Enterprise
PSESCoreScheduler.exe:						Konica Minolta Pagescope Enterprise Suite
psfree.exe:						Panicware Software Pop-Up Stopper
psh_svc.exe:						!!! Acronis Privacy Expert Suite !!!
PSHost.exe:						!!! Panda Internet Security !!!
psimreal.exe:						!!! Panda Internet Security !!!
psimreal.exe:						!!! Panda Internet Security !!!
psimsvc.exe:						!!! Panda Anti-Virus !!!
PsImSvc.exe:						!!! Panda Internet Security !!!
PSIMSVC.EXE:						!!! Panda !!!
PsiService_2.exe:						Protexis License Service
pskmssvc.exe:						!!! Panda Internet Security !!!
psngive.exe:						3M Post-it Note Software
psnlite.exe:						Post-it Software Notes Lite
psof1.exe:						??? Downloader.W32.3536 ???
psoft1.exe:						??? PacerD_Media Adware ???
PSpoolServerD.e:						Kodak Prinergy document processing workflow
PSpoolServerD.exe:						Kodak Prinergy document processing workflow
psqeelsr.exe:						??? Adware.W32.Claria ???
psqltray.exe:						UPEK Fingerprint Reader
pssvc.exe:						Microsoft Outlook Patch
PSTORES.EXE:						Protected Storage Server
pstores.exe:						Protected Storage Server
pstrip.exe:						EnTech Power Strip
PSXRUN.EXE:						MS POSIX/Interix
PSXSS.EXE:						MS POSIX/Interix
PSystemMonD.exe:						Kodak Prinergy document processing workflow
PTaskD.exe:						Kodak Prinergy document processing workflow
PTaskTemplateD.:						Kodak Prinergy document processing workflow
PTaskTemplateD.exe:						Kodak Prinergy document processing workflow
ptf_0017.exe:						??? Adware.W32.PacerD ???
pthosttr.exe:						HP Protecttools Security Manager
PThumbnailD.exe:						Kodak Prinergy document processing workflow
PThumbPrepJTP.e:						Kodak Prinergy document processing workflow
PThumbPrepJTP.exe:						Kodak Prinergy document processing workflow
ptop.exe:						??? Spyware.W32.Bestsearch ???
pts.exe:						Kodak Picture Transfer Software
ptsnoop.exe:						PCTel Configuration Tool
ptssvc.exe:						Kodaks Picture Transfer Service
ptuninstaller.exe:						??? Adware.W32.ClariaPrecision ???
PTUpdater.exe:						Cisco Packet Tracer (network simulator)
pull.exe:						Push Client
punto.exe:						Yandex Language Switching
purevoice.exe:						QualComm PureVoice
PureVoice.exe:						QualComm PureVoice
purityscan install.exe:						??? Adware.W32.PurityScan ???
purityscan.exe:						??? Adware.W32.PurityScan ???
purityscan2.exe:						??? Adware.W32.PurityScan ???
purityscanuninstall.exe:						??? Adware.W32.PurityScan ???
putty.exe:						Putty
PVectorOutputJT:						Kodak Prinergy document processing workflow
PVectorOutputJTP.exe:						Kodak Prinergy document processing workflow
pview.exe:						!!! Process Explode process viewer !!!
pviewer.exe:						!!! Process Explode process viewer !!!
pvlsvr.exe:						Backup Exec 7.x/8.x Device & Media Service
pvwebsw.exe:						Proventia Webfilter ISA
PwdFiltHelp.exe:						!!! GoldenDolphin Chinese IDS !!!
PWKNTMon.exe:						BMC Patrol Agent
PWKPslApi.exe:						BMC Patrol Agent
PWKPslApi.xpc:						BMC Patrol Agent
PWMessenger.exe:						PostWin Messenger
PwrGate.exe:						Backup Exec Device and Media Service
pwrisovm.exe:						PowerISO Virtual Drive Manager
PWServer2.exe:						PostWin Multiplexor
pxagent.exe:						Prevx Agent Home or Pro
pxconsole.exe:						Prevx Management Console
pxemtftp.exe:						!!! Symantec !!!
PXEMTFTP.exe:						!!! Altiris Process !!!
pxeservice.exe:						!!! Symantec !!!
PYohoMessageSer:						Kodak Prinergy document processing workflow
PYohoProxyServe:						Kodak Prinergy document processing workflow
pyr0.exe:						??? Backdoor.W32.Rbot ???
python.exe:						Python Scripting Tool
PythonService.exe:						Python Service
q17i9a4j.exe:						??? Adware.W32.BargainBuddy ???
Q3ADC.exe:						SC Q3 alarm collector
Q3ComProxyServe:						SC Q3 com proxy server
Q3ComProxyServer.exe:						Switch Commander Application
q3server.exe:						SC Q3 stack service
qaccess.exe:						UniBlue Quick Access
qagent.exe:						Quicken Download Manager
qbdagent2002.exe:						QuickBooks Delivery Agent2002
qbreminder.exe:						Intuit QuickBooks Helper
qbupdate.exe:						Quickbooks Update Agent
qbw32.exe:						Intuit QuickBooks
qclean.exe:						!!! McAfee QuickClean !!!
qconsvc.exe:						IBM Thinkpad Utility Component
qctray.exe:						IBM ThinkPad Traybar Component
qcwlicon.exe:						IBM Wireless
qdcsfs.exe:						!!! Symantec !!!
QDictionary.exe:						Anplex Quick Dictionary for Windows
qerbid.exe:						??? AdLogix Spyware ???
qerbif.exe:						??? AdLogix Spyware ???
qhutst.exe:						??? 180Solutions Spyware ???
qip.exe:						ICQ-like application
QipGuard.exe:						QIP Instant Messenging
QLBCTRL.exe:						HP Quick Launch
qoeloader.exe:						!!! Qurb/CA Internet Security 2008/9 AntiSpam !!!
Qoeloader.exe:						!!! Qurb/CA Internet Security 2008/9 AntiSpam !!!
qool3.exe:						??? Downloader.W32.Qoologic ???
qoologic.exe:						??? 2nd Thought Spyware ???
QosServM.exe:						AVAYA IP Softphone R5 Service
qpservice.exe:						HP QuickPlay
QQ.exe:						QQ Chinese instant messaging client
qrolmnedq.exe:						??? Adware.W32.WinTools ???
qserver.exe:						!!! Symantec !!!
qtaet2s.exe:						Acer Multimedia Keyboard
qtask.exe:						Intuit Qtask
qtihad.exe:						??? 180SearchAssistant Spyware ???
qttask.exe:						Apple QuickTime Tray Icon
qtzgacer.exe:						Acer Launch Manager
quake3.exe:						Quake 3
QueueMgr.exe:						IMail Queue Manager Service
quickbooks:						QuickBooks Delivery Agent
QuickBooks:						QuickBooks Delivery Agent
quickcam.exe:						Logitech QuickCam
QuickCam10.exe:						Logitech QuickCam10
quickdcf.exe:						Quickbooks Exif Launcher
quickpar.exe:						QuickPar Archive Verification Tool
quickres.exe:						Microsoft Quickres
quickset.exe:						Dell Quickset
quicktimeplayer.exe:						Apple Quicktime Player
QuickTV.exe:						AVerTV Media Player
qvp32.exe:						Inso Quick View Plus
qwdlls.exe:						Quicken launch utility
r_server.exe:						Remote Administrator Service
ra_scp.exe:						Remotely Anywhere
ra_sftp.exe:						Remotely Anywhere
ra_ssh.exe:						Remotely Anywhere
raabout.exe:						Remotely Anywhere
racsrvc.exe:						Dell OpenManage Server
RACWinVNC.exe:						Dell VNC Server for Win32
radadnt.exe:						Steel-Belted Radius Administrator
radio.exe:						Radio UserLand
radiosvr.exe:						Wireless LAN Configuration Utility
radius.exe:						Steel-Belted Radius Server
radmin.exe:						Radmin - PC remote control
RadStateServer.:						RadStateServer
ragent.exe:						1C:Enterprise Management Server
ragui.exe:						Remotely Anywhere
raid_tool.exe:						VIA RAID Tool
raidServ.exe:						IBM ServeRAID Manager Agent
RaidServ.exe:						IBM ServeRAID Manager Agent
Rainlendar.exe:						Calendar app
Rainlendar2.exe:						Rainlendar2
ramaint.exe:						RemotelyAnywhere Maintenance Service
ramasst.exe:						CD Burning of Windows XP disabling tool for DVD MULTI Drive
RAMASST.exe:						RAMASST
ramsys.exe:						Advanced StartUp Manager
randomdigits.exe:						??? JONBARR.D VIRUS Virus ???
RandomGenerator:						Random number generator
randreco.exe:						??? 2nd Thought Spyware ???
rapapp.exe:						!!! BlackIce Firewall !!!
RapApp.exe:						!!! BlackIce Firewall !!!
RapApp.exe:						!!! BlackIce Firewall !!!
rapimgr.exe:						Microsoft ActiveSync Module
rapuisvc.exe:						!!! ISS_Proventia_Agent 9.0 from IBM !!!
rar.exe:						WinRar DOS Executable
rareboot.exe:						Remotely Anywhere
ras.exe:						!!! Rising Antispyware !!!
rasadmin.exe:						Remote Access Connection Administrator
rasautou.exe:						Microsoft Remote Access Dialler
rasman.exe:						Microsoft Remote Access Service
RASMAN.EXE:						Remote Access Connection Manager
rassrv.exe:						Remote Access Server
RASSRV.EXE:						Remote Access Server
rasupd.exe:						!!! Rising Antispyware !!!
Rav.exe:						!!! Rising AntiVirus !!!
RavAlert.exe:						!!! Rising AntiVirus !!!
ravmon.exe:						!!! Rising AntiVirus !!!
RavMon.exe:						!!! Rising AntiVirus !!!
ravmond.exe:						!!! Rising AntiVirus !!!
RAVMOND.exe:						!!! Rising AntiVirus !!!
RavMonD.exe:						!!! Rising AntiVirus !!!
RavService.exe:						!!! Rising AntiVirus !!!
ravstub.exe:						!!! Rising AntiVirus !!!
RavStub.exe:						!!! Rising AntiVirus !!!
RavTask.exe:						!!! Rising AntiVirus !!!
RavTray.exe:						!!! Rising AntiVirus !!!
RavUpdate.exe:						!!! Rising AntiVirus !!!
ravxp.exe:						!!! Rising !!!
RAVXP.exe:						!!! Rising !!!
RavXP.exe:						!!! Rising !!!
ray.exe:						??? Ray Trojan ???
ray.exe:						??? Ray Trojan ???
raysat_3dsmax9_32server.exe:						Autodesk 3D MAX
razespyware_installer.exe:						??? Adware.W32.RapidBlaster ???
rb32.exe:						??? RapidBlaster parasite Virus Spyware ???
rbenh.exe:						??? Adware.W32.RapidBlaster ???
rbmonitor.exe:						Uniblue Registry Booster
rcapi.exe:						ELSA CAPI Control Task / LANCAPI Control
RCC.exe:						MC Recording Controller
rcenter.exe:						Creative RemoteCenter
RCONSVC.EXE:						Remote Console Server
rcsvcmon.exe:						!!! GFI EndPointSecurity !!!
rcsync.exe:						??? Rcsync Spyware ???
RDDService.exe :						PGP Desktop
RDISK.EXE:						Repair Disk Utility
rdpclip.exe:						File Copy
rds.exe:						??? TrojanSpy.Win32.Delf Keylogger ???
rds.exe:						??? TrojanSpy.Win32.Delf Keylogger ???
rdshost.exe:						RDSHost Server Module
reader_sl.exe:						Adobe Reader Speed Launch
readericon45g.exe:						Multimedia Card Reader
realevent.exe:						Real event
realjbox.exe:						Real Jukebox
realmon.exe:						!!! CA Jinchen Kill Realtime Monitor !!!
RealMon.exe:						!!! CA Jinchen Kill Realtime Monitor !!!
Realmon.exe:						!!! CA Jinchen Kill Realtime Monitor !!!
realonemessagecenter.exe:						Real Networks Event Launcher
RealPlay.exe:						Real Media Player
realplay.exe:						Real Player
realpopup.exe:						Real Popup
realscan.exe:						ScanMail RealTimeScan
RealScan.exe:						ScanMail RealTimeScan
realsched.exe:						RealNetworks Scheduler
realshed.exe:						RealPlayer Component
realtime.exe:						PCDRealtime
RealTimeInterfaceMonitor.exe:						Solarwinds tool
realtray.exe:						??? Backdoor.Stanex trojan ???
realupd.exe:						??? trojan.w32.MITGLIED ???
realupd32.exe:						??? trojan.w32.MITGLIED ???
reboot.exe:						REBOOT
rebootx.exe:						SIEMENS
recguard.exe:						Recguard
RECL32.EXE:						Lotus Notes?
red32secure.exe:						Lantronix COM Port Redirector
redcross.exe:						??? Downloader.W32.INService ???
RedirSvc.exe:						!!! McAfee Internet Security Suite !!!
redirsvcsc.exe:						Lantronix COM Port Redirector
RedundancyContr:						Siemens WinCC process
RedundancyControl.exe:						Siemens WinCC process run script siemens.eps)
RedundancyState:						Siemens WinCC process
RedundancyState.exe:						Siemens WinCC process
ReflectService.exe:						Macrium backup image creation software
reg.exe:						Registry Console Tool
Reg_serv.exe:						MegaRAID Power Console
regbar.exe:						??? Spyware.W32.123bar ???
regedit.exe:						Registry Editor
register.exe:						??? LameToy 2000 Spyware ???
registration.exe:						??? Adware.W32.GoGoTools ???
registrybooster.exe:						Registry Booster
regloadr.exe:						??? W32.HLLW.GAOBOT.AO virus Virus Trojan ???
regmaping.exe:						??? Trojan.W32.Bagle ???
RegMech.exe:						!!! Spyware Doctor !!!
regmon.exe:						+++ Registry Monitor +++
regperf.exe:						??? Trojan.W32.Zlob ???
regscan.exe:						??? Trojan.W32.Rbot ???
regshave.exe:						Regshave
regshot.exe :						Registry Monitor
regsrv.exe:						??? OPTIXPRO.11 virus Virus Trojan ???
RegSrvc.exe:						Intel Communications Service
regsrvc.exe:						Intel Communications Service
regsvc.exe:						Remote Registry Service
regsvc32.exe:						??? Regsvc32 ???
regsvr32.exe:						Microsoft DLL Registration Service
regsync.exe:						??? SafeSurfing Spyware ???
reinstall_svc.exe:						Acronis Disk Director
relatedsetup.exe:						??? Downloader.W32.3945 ???
remind.exe:						Storm Technology Remind
remind32.exe:						ScanSoft Product Registration
remind_xp.exe:						SoftThinks CD Creator Reminder
Remind_XP.exe:						SoftThinks CD Creator Reminder
reminder.exe:						Microsoft Money Reminder
remote.exe:						??? W32.Fanbot.A@mm ???
RemoteAgent.exe:						CyberLink PowerVCRII
RemotelyAnywher:						RemotelyAnywhere
remotelyanywhere.exe:						Remotely Anywhere
remoterm.exe:						PC TV Remote
removecpl.exe:						Belkin Wireless Setup Utility
removed.exe:						??? GatorCheat adware Spyware ???
removedisplayutility.exe:						??? Adware.W32.Ezula ???
removejk.exe:						??? Trojan.W32.Remojin ???
remupd.exe:						!!! Panda Agent !!!
rep_server.exe:						HP OpenView
RepliGoMon.exe:						Mobile Device Document Transfer
ReportDistributor.exe:						Reksoft Barsoom Billing
ReporterSvc.exe:						!!! Symantec !!!
ReportingServicesService.exe:						Microsoft SQL
ReportingServicesService.exe:						Microsoft SQL Server
reportsvc.exe:						!!! Symantec Reporting Service !!!
requester.11.exe:						??? Trojan.Muquest ???
res.exe:						USB Toolbox
resetservice.exe:						Windows XP Activation Hack
residence.exe:						Sony Camcorder Connection Process
residentAgent.exe:						LANDesk Network Management Utility
ResPCDev.exe:						Panasonic
ResponseTimeCharts.exe:						Solarwinds tool
resrcmon.exe:						Microsoft resource monitor
Restarter.exe:						SC process
RetinaEngine.exe:						eEye Retina Digital Security
retroexpress.exe:						Retrospect Express HD
retrorun.exe:						Dantz Development Retrospect Backup
retrospect.exe:						Retrospect Backup Tool
REXECD.EXE:						Ataman Rexecd Server
rfagent.exe:						Registry First Aid
rftray.exe:						Rftray
rfwmain.exe:						!!! Rising Firewall !!!
rfwproxy.exe:						!!! Rising !!!
rfwsrv.exe:						!!! Rising Firewall !!!
rfwstub.exe:						!!! Rising !!!
rhaphlpr.exe:						Rhapsody Helper
rhnura.exe:						??? Downloader.W32.Qoologic ???
richtx32.ocx:						Microsoft Rich Text OLE Control
richup.exe:						??? Adware.W32.Begin2Search ???
richvideo.exe:						Cyberlink Power Director Video Module
riomsc.exe:						Rio Mass Storage Class Device Manager
rk.exe:						??? RelevantKnowledge Software Component Spyware ???
rlid.exe:						??? LIXY virus Trojan ???
RLOGIND.EXE:						Ataman Rlogind Server
rlvknlg.exe:						??? RelevantKnowledge Adware ???
rm05040901.exe:						??? Adware.W32.PromulGate ???
rm_sv.exe:						Sony GigaPocket
RM_SV.exe:						Sony GigaPocket
RMAP.EXE:						Eudora Remote Management Agent
rmclock.exe:						RightMark CPU Clock Utility
rmctrl.exe:						CyberLink Rmctrl.
rmngr.exe:						1C:Enterprise Management Server
rmserver.exe:						Real Media Server
rmsvc.exe:						Media Center RD RM Service Service
rmsystry.exe:						Microsoft Media Center Traybar Module
rnaapp.exe:						Windows Modem Connection
rnathchk.exe:						Real Networks Rnathchk
rnav.exe:						!!! Symantec !!!
rndal.exe:						Rndal
RNReport.exe:						!!! Rising AntiVirus !!!
robocopy.exe:						Microsoft Robust File Copy Utility
robotaskbaricon.exe:						AI RoboForm
RODOPIServer.ex:						RODOPI Server
rogue.exe:						??? Spyware.W32.DyFuCA ???
roiia.exe:						??? Adware.W32.TargetSaver ???
roiim.exe:						??? Adware.W32.TargetSaver ???
ROMServ.exe:						HP EEPROM Service
rosnmgr.exe:						Reachout Manager
ROSNMGR.EXE:						ReachOut Remote?
rotatelogs.exe:						HP System Management Homepage
ROUTE.EXE:						ROUTE.EXE Command
route.exe:						MS-DOS Executable
RouteMgr.exe:						Infosec Continent Client VPN
Router-CPU-Load.exe:						Solarwinds tool
router.exe:						Lotus Notes?
ROUTER.EXE:						Lotus Notes?
RouterNT.exe:						!!! Sophos Control Center !!!
Routingservice.:						SC Routing Server
Routingservice.exe:						Switch Commander Application
rox watch.exe:						Roxio Media Database Service
roxmediadb.exe:						Roxio Media Database Service
roxwatchtray.exe:						Roxio Media Database Service Traybar Utility
rpcclient.exe:						??? Codbot-L Worm ???
rpcmon.exe:						??? RANDEX Worm Module ???
RPCServ.exe:						!!! McAfee !!!
RPCServ.exe:						!!! McAfee !!!
rpcss.exe:						Remote Procedure Call Service
RpcSs.exe:						Remote Procedure Call Service
RPCSS.EXE:						Remote Procedure Call Service
rpdflchr.exe:						RoboPDF Component
rphost.exe:						1C:Enterprise Management Server
rrpcsb.exe:						Rapid Restore
rscmpt.exe:						NVIDIA GeForce Rscmpt
rsednclient.exe:						Red Swoosh EDN Client
RsEng.exe:						Remote Storage Engine
rserver3.exe:						Famatech Radmin
RsFsa.exe:						Remote Storage File System Agent
rshd.exe:						remote shell daemon
rshd.exe:						Remote shell daemon
rsmsink.exe:						Removable Storage Manager
rsnetsvr.exe:						!!! Rising Anti-Virus !!!
rsrcmtr.exe:						Microsoft Windows Resource Meter
RSSensor.exe:						!!! McAfee Rogue System Sensor !!!
RsServ.exe:						Microsoft Remote Storage Server
RsSub.exe:						Remote Storage Subsystem
rstray.exe:						!!! Rising Anti-Spyware !!!
rstrui.exe:						Microsoft Restore Console
rsvp.exe:						Microsoft RSVP
rsyszx2d.exe:						??? Downloader.W32.Agent ???
RtcHost.exe:						Office Communications Server 2007
RTCSrv.exe:						Office Communications Server 2007
rteng7.exe:						Adaptive Server Anywhere Database Engine
rteng9.exe:						Adaptive Server Anywhere Network Server
rtf32.exe:						??? Spyware.W32.AdClicker ???
RtfServer.exe:						Dialogic Host Media Processing
rthdcpl.exe:						Realtek HD Audio Sound Effect Manager
RtHDVCpl.exe:						Realtek High Definition Audio
rtlrack.exe:						RealTek Audio Player
rtmanager.exe:						Remote Task Manager UI
rtmc.exe:						Remote Task Manager Console
rtmservice.exe:						Remote Task Manager Service
rtos.exe:						Rtos
rtvscan.exe:						!!! Symantec !!!
RTVscan.exe:						!!! Symantec !!!
Rtvscan.exe:						!!! Symantec !!!
rtvscn95.exe:						Real-time virus scanner
rulaunch.exe:						!!! McAfee User Interface !!!
run.exe:						??? Downloader.W32.Small ???
run32dll.exe:						??? PAL PC Spy Spyware ???
rundl32.exe:						??? W32/Agobot-TO Worm ???
rundll.exe:						Microsoft RunDLL
rundll16.exe:						??? Sdbot.F virus Trojan ???
rundll32.exe:						Control Panel Helper
RungeServiceManager.exe:						Runge Site Admin Service Manager
RungeSiteAdmin.exe:						Runge Site Admin Service
runmqchi.exe:						GTS diplomatic comms system
runmqlsr.exe:						GTS diplomatic comms system
runonce.exe:						Runonce
runplugin.exe:						NetSupport School
Runservice.exe:						eLicenses Licensing System
runservice.exe:						LicCrtl
RUSSIA~1.SCR:						Russian Screen Saver
ruxdll32.exe:						??? MAPSON.D virus Virus ???
rvrd.exe:						Cisco Works
RWMTS60.EXE:						Oracle Report Server
RWSRSU.exe:						WatchGuard Mobile VPN
rxmon.exe:						Rxmon
rxtoolbar.exe:						??? Adware.W32.RXToolbar ???
rz.exe:						Remotely Anywhere
s.exe:						??? Trojan.Ducky.C ???
s1p1y_bad.exe:						??? Adware.W32.EasySearch ???
s24evmon.exe:						Event Monitor
s3apphk.exe:						S3 Video Output device
s3hotkey.exe:						S3 Graphics hotkey app
s3tray2.exe:						S3 Video
S3Trayp.exe:						S3 Screen Toys
S3Trayp.exe:						S3 Screen Toys
s7acmgrx.exe:						Siemens Step7 process
s7asysvx.exe:						Siemens Step7 process
S7EPATSX.EXE:						Siemens Set PC/PG Interface run script siemens.eps)
S7kafapx.exe:						Siemens Program Block Editor run script siemens.eps)
S7nnappx.exe:						Siemens NetPro Network Configurator run script siemens.eps)
s7oiehsx.exe:						Siemens Step7 process
S7tgtopx.exe:						Siemens Simatic Manager window run script siemens.eps)
S7TraceServiceX.exe:						SIEMENS
s7traceservicex.exe:						SIEMENS
S7ubTstx.exe:						Siemens Step7 process
s7wndxlx.exe:						Siemens S7 Diagnostics run script siemens.eps)
s7wnfwlx.exe:						Siemens Firmware Loader run script siemens.eps)
s7wnrmsx.exe:						Siemens Simatic Net process
s7wnsmgx.exe:						Siemens Simatic Net process
s7wnsmsx.exe:						Siemens PLC-related process
s7wtsapx.exe:						Siemens TeleService Adapter process run script siemens.eps)
s7wtssvx.exe:						Siemens TeleService Adapter process run script siemens.eps)
s_win32.exe:						??? 2nd Thought Spyware ???
saagent.exe:						Microsoft Automated Deployment Services
saap.exe:						??? 180Solutions Spyware ???
sac.exe:						??? 180SearchAssistant Spyware ???
sacc.exe:						??? Adware.W32.SurfAccuracy ???
saccu.exe:						??? Adware.W32.SurfAccuracy ???
sachostb.exe:						??? Trojan.W32.Looksky ???
sachostc.exe:						??? Trojan.W32.Looksky ???
sachostm.exe:						??? Trojan.W32.Looksky ???
sachostp.exe:						??? Trojan.W32.Looksky ???
sachosts.exe:						??? Trojan.W32.Looksky ???
sachostw.exe:						??? Trojan.W32.Looksky ???
sachostx.exe:						??? Trojan.W32.Looksky ???
safeboxtray.exe:						!!! 360_Safe !!!
safecfg.exe:						SafeNet VPN Client
safemode.exe:						??? Trojan.W32.Renama ???
SAFeService.exe:						!!! McAfee SAFe Common Technology !!!
sage.exe:						Microsoft SystemAgent
sagent2.exe:						Epson Printer Software
sAginst.exe:						Citrix VM Server
sahagent.exe:						??? Sahagent Spyware ???
sahdownloader_.exe:						??? Adware.W32.Cydoor ???
saHookMain.exe:						!!! McAfee SiteAdvisor !!!
saie.exe:						??? DyFuCA.Internet Optimizer Hijacker ???
saie1101.exe:						??? 180Solutions Spyware ???
saimon.exe:						Saimon WriteDVD
sais.exe:						??? 180Solutions Spyware ???
saismart.exe:						Smart Button Special Sauce
salm.delete.exe:						180Solutions spyware
salm.exe:						??? 180Search Assistant Spyware ???
salmbundle.exe:						180SearchAssistant
sapcnsl.exe:						SAP Console
sapisvr.exe:						Windows Speech Recognition
saproxy.exe:						bloomba SpamAssassin Proxy
SAService.exe:						!!! McAfee Internet Security Suite !!!
sass.exe:						Troj/Funsta-A
satmat.exe:						??? aBetterinternet adware Spyware ???
sav32cli.exe:						!!! Sophos Anti-Virus Scanner    !!!
SAVAdminService.exe:						!!! Sophos Anti-Virus !!!
save.exe:						??? WhenU.com Spyware ???
savedump.exe:						NT Memory Dump
savenow.exe:						??? Savenow Spyware ???
SAVFMSECTRL.exe:						Symantec Mail Security
SAVFMSELog.exe:						Symantec Mail Security
SAVFMSESJM.exe:						Symantec Mail Security
SAVFMSESp.exe:						!!! Symantec !!!
SAVFMSESpamStatsManager.exe:						Symantec Mail Security
SAVFMSESrv.exe:						Symantec Mail Security
SAVFMSETask.exe:						Symantec Mail Security
SAVFMSEUI.exe:						Symantec Mail Security
SAVMain.exe:						!!! Sophos Anti-Virus GUI is OPEN !!!
savroam.exe:						!!! Symantec !!!
SavRoam.exe:						!!! Symantec !!!
SAVScan.exe:						!!! Symantec !!!
savscan.exe:						!!! Symantec !!!
SavService.exe:						!!! Sophos Anti-Virus !!!
savservice.exe:						!!! Sophos Anti-Virus !!!
SavUI.exe:						!!! Symantec !!!
Sawmill.exe:						Sawmill 8 Log File Analysis
SawmillService.exe:						Sawmill 8 Log File Analysis
SBAMService.exe:						SIWF BAM Services
sbcmstrt.exe:						Small Business Customer Manager
sbdrvdet.exe:						Creative SoundBlaster Driver Component
sbhc.exe:						Gigatech sbhc.exe
sbscrexe.exe:						Microsoft Small Business Server Licensing Service
sbserv.exe:						!!! Symantec !!!
sbsetup.exe:						Softbars
SBUpdate.exe:						SpeedBit Video Accelerator
sc.exe:						??? Watchdog 2.0 Software Spyware ???
scam32.exe:						??? SIRCAM virus Virus ???
Scan2pc.exe:						Xerox Printer
scan32.exe:						!!! McAfee Virusscan Enterprise !!!
scandisk.exe:						Microsoft Scandisk
scands32.exe:						??? Downloader.W32.Small ???
scanexplicit.exe:						!!! Symantec !!!
scanfrm.exe:						!!! Rising Anti-Virus !!!
ScanMailOutLook.exe:						!!! TrendMicro PC-cillin !!!
scanmailoutlook.exe:						!!! TrendMicro PC-cillin !!!
SCANMSG.exe:						!!! Omniquad Total Security 3.0.0 !!!
scanregistry.exe:						??? TROJ_SVHOOST.A Trojan ???
scanregw.exe:						Microsofts Registry Checker.
scanserver.exe:						Netgear Print Server
ScanTwain.exe:						ABBYY FineReader 10
ScanWia.exe:						ABBYY FineReader 10
SCANWSCS.exe:						!!! Omniquad Total Security 3.0.0 !!!
scards32.exe:						Towitoko Smart Card Reader Driver
scardsvr.exe:						Microsoft Smartcard-Ressource server
scardsvr32.exe:						??? MOFEI.B virus Virus Trojan ???
SCAutoAlign.exe:						SC process
scbar.exe:						??? SearchEnhancement ??
sccenter.exe:						Service Connection Center.
sccertprop:						Common DLL to receive Winlogon notifications
scchost.exe:						??? DONK virus Virus ???
SCFManager.exe:						!!! Sophos FIREWALL !!!
SCFService.exe:						!!! Sophos FIREWALL !!!
SCFTray.exe:						!!! Sophos FIREWALL !!!
schdpl32.exe:						Microsoft Schedule+
SCHDPL32.EXE:						Microsoft Schedule+
schdsrvc.exe:						!!! Sophos Control Center !!!
sched.exe:						AntiVir Scheduler
schedhlp.exe:						Trueimage acronis backup software
schedul2.exe:						Acronis True Image Scheduler
schedule.exe:						Acronis Scheduler
Scheduled.exe:						KWorld Multimedia HyperMediaCenter
scheduler.exe:						Leader PowerReg Scheduler
scheduler_proxy.exe:						Lenovo Scheduler
schedulerv2.exe:						PowerReg SchedulerV2
schedulesrv.exe:						Huawei iManager T2000 Element Management Software
schedulingagent:						??? Backdoor.Msic Trojan ???
schost.exe:						??? W32.HLLW.Torvil@mm virus Virus ???
schsvr.exe:						WinScheduler
schupd.exe:						!!! TrendMicro !!!
schwizex.exe:						Imagine SCHWIZEX
scinformer.exe:						motiw document management
SCInformer.exe:						Motiw Document Manager
scm.exe:						Microsof Service Control Manager
scomc.exe:						Securewave Sanctuary Device Control
scopent.exe:						HP OpenView
scopesrv.exe:						HP OpenView
scorecfg.exe:						Siemens Simatic Net process
scores7.exe:						SIEMENS
scrcons.exe:						Microsoft WMI
screensaver.v.2.1.exe:						??? Adware.W32.Begin2Search ???
scrfs.exe:						Symbian Connect Component
scrigz.exe:						??? W32/Mytob-ER Worm ???
scrnsave.scr:						Microsoft default screen saver
scrss.exe:						??? Troj/HacDef-R Trojan ???
scrsvr.exe:						??? OPASERV virus Virus ???
scrtkfg.exe:						??? WIN32.RBOT Trojan Variant ???
scsiaccess.exe:						Scsiaccess
scsmx.exe:						SIEMENS
SCSMX.exe:						SIEMENS
scureapp.exe:						OmniPass
scvhost.exe:						??? W32/Agobot-S virus Virus Trojan ???
SCVVHSOT.exe:						??? W32/Sality.gen ???
SD3Service.exe:						SUPERMICRO Supero Doctor III Client
SD3Service.exe:						SUPERMICRO Supero Doctor III Client
SDataMan.exe:						SIWF BAM Services
sdhelp.exe:						??? Spyware Doctor Helper ???
sdii.exe:						Microtek Scanner Console
sdmcp.exe:						Stardock Desktop Personalizer
SDMCP.exe:						Stardock Desktop Personalizer
sdstat.exe:						TOSHIBA FlashPath Status
SDTrayApp.exe:						!!! Spyware_Doctor 5 from PC Tools !!!
se.exe:						??? Search-exe.com Spyware ???
se2ppc4you.exe:						??? Downloader.W32.Agent ???
sealmon.exe:						SealedMedia Module
SeAnalyzerTool.exe:						!!! Netgate Spy Emergency !!!
SeaPort.exe:						Microsoft Search Enhancement Pack
search.exe:						??? Search-Exe Adware ???
Search.exe:						??? Search-Exe Adware  Spyware ???
searchindexer.exe:						Microsoft search indexer
SearchIndexer.exe:						Microsoft search indexer
searchnav.exe:						??? SearchNav Spyware ???
searchnavversion.exe:						??? SearchNav Spyware ???
searchnugget.exe:						??? Adware.W32.SearchNugget ???
SearchProtection.exe:						Yahoo Search Protection
searchtoolbar.exe:						??? Adware.W32.SearchNugget ???
searchupdate33.exe:						??? SearchSquire Spyware ???
SearchUpdate33.exe:						??? SearchSquire Spyware ???
searchupgrader.exe:						eUniverse/KeenValue Hijacker
SearchUpgrader.exe:						??? eUniverse/KeenValue Hijacker Spyware ???
secserv.exe:						openFT process
sectoriate.exe:						??? Trojan.W32.Haytap ???
secure.exe:						??? Adware.W32.DealHelper ???
SecureCRT.exe:						Secure Terminal Emulator
SecureCRT.EXE:						Secure Terminal Emulator
securitycenter.exe:						Aluria Security Center
SecurityManager.exe:						MSC BAM Services
sed.exe:						??? Adware.W32.Ezula ???
sedk.exe:						??? Adware.W32.Ezula ???
seekmo.exe:						Seekmo Search Assistant
seestat.exe:						!!! StatWin !!!
seeve.exe:						??? Adware.W32.Network1 ???
sefer.exe:						??? Downloader.W32.Small ???
seii.exe:						??? Adware.W32.PurityScan ???
selfcert.exe:						Microsoft Digital Certificate utility
Seller.exe:						Nienschanz Seller 4.4
semanticinsight.exe:						semanticinsight
sempalong.exe:						??? W32.Rontokbro.K\@mm Worm ???
SemSvc.exe:						!!! Symantec !!!
Send_Message.exe:						SIEMENS
sendmail.EXE:						Sendmail MTA
SendPage.exe:						Solarwinds tool
SENS.EXE:						System Event Notification?
sens.exe:						System Event Notification?
senslogn:						??? AbetterInternet Spyware ???
sentry.exe:						IpInSight Sentry
sentstrt.exe:						Rainbow Technologies
SEPCSuite.exe:						Sony Ericsson PC Suite
sepinst.exe:						??? Adware.W32.Ezula ???
Serv-U.exe:						RhinoSoft.com FTP Server
Serv-U32.exe:						Serv-U FTP Server
servce.exe:						??? W32.Mytob.MR\@mm Trojan ???
server.exe:						Novell server licensing
servercon.exe:						??? Adware.W32.GoGoTools ???
serveur.exe:						Scanner software
servic.exe:						??? Rbot  worm variant ???
service.exe:						Dell Solution Center
service5.exe:						??? W32.HLLW.Gaobot.AG virus Virus ???
Service_AuthSrv:						SiteMinder Site Authorization Service
Service_AuthSrv.exe:						SiteMinder Site Authorization Service
Service_AzSrvr.:						SiteMinder Site Authorization Service
servicelayer.exe:						Nokia Connectivity Library
services.exe:						Windows Service Controller
services32.exe:						??? Downloader.W32.3926 ???
ServMgr.exe:						ZTE
ServUAdmin.exe:						Serv-U FTP Administrator
servudaemon.exe:						FTP Serv-U Daemon
ServUDaemon.exe:						FTP Serv-U Daemon
SERVUT~1.EXE:						Serv-u FTP Server
SescLU.exe:						!!! Symantec !!!
sessmgr.exe:						Remote Desktop Help Session Manager
sethook.exe:						Fellowes MediaFACE
seti@home.exe:						SETI@home (win32 client)
SETI@home.exe:						SETI @ Home Distributed Processing
SETI\@home.exe:						SETI\@ Home Distributed Processing
seti\@home.exe:						SETI\@home win32 client)
seticon.exe:						6-in-1 Media Card Module
setlang.exe:						Microsoft Office Langauge Configuration Utility
setloadorder.exe:						!!! BitDefender Security Suite !!!
setpoint.exe:						Logitech SetPoint Event Manager
setup.exe:						Setup Executable
setup32i.exe:						??? Trojan.W32.Redplut ???
setup4156.exe:						??? 180Solutions Spyware ???
setup_jalapeno.exe:						??? Spyware.W32.ClientMan ???
SetupGUIMngr.exe:						!!! F-Secure Internet Security !!!
setupguimngr.exe:						!!! F-Secure Internet Security !!!
SEVINST.EXE:						!!! Symantec !!!
SExchange.exe:						SIWF BAM Services
sexeducation.exe:						??? Dialer.W32.dialer ???
sf.exe:						??? WIN32.FAVADD.O TROJAN ???
sfc32.exe:						??? W32.Monikey\@mm Worm ???
sfgdulkp.exe:						??? 180SearchAssistant Spyware ???
sfita.exe:						??? SurfEnhance Adware ???
sfmprint.exe:						Microsoft MacPrint Service
sfmsvc.exe:						Windows NT Macintosh Fiel Server Service
SFTPMan.exe:						SIWF BAM Services
sfwqi.exe:						??? Adware.W32.Ezula ???
sgbhp.exe:						SpywareBlaster Internet Security Tool
sgmain.exe:						??? SpywareGuard ???
sgtray.exe:						VERITAS StorageGuard Tray Application
sha.exe:						Intel Server Management
shadowbar.exe:						Hewlett-Packard Utilities
shareaza.exe:						Shareaza P2P
sharedprem.exe:						Sharedprem
shell32.exe:						??? BadSector virus Trojan ???
shell386.exe:						??? Trojan.W32.RealSearch ???
ShellKer.exe:						Carbon Copy 32 Kernel Application
shellmon.exe:						AOL Shellmon
shine.exe:						??? HAPPYLOW virus Virus ???
shmgrate.exe:						NT Data Migration (Check path in processdeep)
shnlog.exe:						??? Troj/Puper-A Trojan ???
shopinst.exe:						??? 180Solutions Spyware ???
shotkey.exe:						Chicony HOTKEY Driver
showbehind.exe:						MicroSmarts Enterprise Component
showwnd.exe:						??? Unclassified Trojan ???
shpc32.exe:						Lexmark Shpc32
shstart.exe:						ON Technology Shell Start Applikation
shstat.exe:						!!! McAfee VirusScan Enterprise !!!
shutdown.exe:						Shutdown Event Tracker
shutdownutility.exe:						??? Trojan.W32.Randsom ???
shwicon.exe:						ALLNET Shwicon
shwicon2k.exe:						Multimedia Card Reader
shwiconem.exe:						Digital Media USB Reader Assistant
si.exe:						??? W32.Yimper ???
sideb.exe:						??? Adware.W32.SearchMiracle.EliteBar ???
sidebar.exe:						Windows Desktop Sidebar
sidedb_install.exe:						??? Adware.W32.SearchMiracle.EliteBar ???
SIFENMClient.exe:						Switch Commander Application
sifxinst.exe:						Lanovation Prism
silent.exe:						Compaq Knowledge Center
silent_setup[1].exe:						??? Adware.W32.SearchMiracle.EliteBar ???
sim9sync.exe:						Siemens Simatic Net process
simailproxyserver.exe:						GIANT Spam Inspector
SIMETER.EXE:						Si Meter
simeter.exe:						Si Meter
simnetpnpman.ex:						Siemens Simatic Net process
simnetpnpman.exe:						Siemens Simatic Net process
SinforPromoteService.exe:						Sinfor SSL VPN Service
SIPServ.exe:						INFOSEC Continent Client
sistray.exe:						Silicon Integrated Systems Sistray
sisusbrg.exe:						SiS Patch
siteadv.exe:						!!! McAfee Internet Security Suite !!!
SiteAdv.exe:						!!! McAfee Internet Security Suite !!!
SixEngine.exe:						Hardware Power Saving
sixtypopsix.exe:						??? Adware.W32.Network1 ???
sk9910dm.exe:						Sk9910dm
ska.exe:						??? Win32/Ska Virus Trojan ???
skeys.exe:						Microsoft Serial Keys Utility
skinkers.exe:						BBC News alerts
sksockserver.exe:						??? Backdoor.W32.SkSocket ???
skynetave.exe:						??? SASSER WORM Virus Trojan ???
skype.exe:						Skype Internet Telephoney
Skype.exe:						Skype Internet Telephoney
skype32.exe:						??? W32.Mytob.ML\@mm Worm ???
skypeclient.exe:						Skype Client
SkypeNames2.exe:						Skype Internet Telephony
skypePM.exe:						Skype Plugin Manager
SkyTel.EXE:						Realtek Voice Manager
Slave.exe:						RA Server?
slave.exe:						TWD Industries Remote-Anything
sldIMScheduler.exe:						CAD Design
SLDWORKS.exe:						SolidWorks CAD Software
slee401.exe:						Steganos Live Encryption Engine
slee81.exe:						Steganos Security Suite Component
slimsvc.exe:						Checkpoint SSL Network Extender (SSL VPN)
sllights.exe:						STMicroelectronics modem
SLmail.exe:						Seattle Lab Mail Server
slmbrsvc.exe:						BMC Service Level Management
slmss.exe:						SeekSeek hijacker  Virus
SLogMan.exe:						SIWF BAM Services
slp_srvreg.exe:						IBM Systems Director
slpmonx.exe:						Seiko SLP Printer Driver
slpservice.exe:						Seiko SLP Printer Service
slpv24s.exe:						SlpV24 Server Application
slrundll.exe:						Smart Link Modem Driver
slserv.exe:						SmartLink Slserv
slserve.exe:						??? W32/SDBOT WORM ???
slserves.exe:						??? W32/SDBOT WORM ???
SLsvc.exe:						Vista Software Licensing Service
sm1bg.exe:						Cypress USB Mass Storage Adapter
SM1BG.EXE:						Cypress USB Mass Storage Adapter
sm56hlpr.exe:						Sm56hlpr
sm_authority.exe:						Cisco Works
sm_server.exe:						Cisco Works
SMAgent.exe:						SoundMax audio driver
smagent.exe:						Analog Devices magent
SMaintain.exe:						SIWF BAM Services
smartagt.exe:						3Com dRMON SmartAgent
SmartCam.exe:						Webcam for Smartphone
smartexplorer.exe:						Smart Explorer Browser
SmartExplorer.exe:						Smart Explorer Browser
SmartFTP.exe:						SmartFTP
smartftp.exe:						SmartFTP
smartscaps.exe:						SmartTrust Smart Card Server
SmaService.exe:						Citrix VM Server
SMax4.exe:						SoundMAX Control Center
smax4.exe:						SoundMAX Control Center
smax4pnp.exe:						SMax4PNP MFC Application
SMax4PNP.exe:						SMax4PNP MFC Application
smbridge.exe:						Avocent SMBridge Remote Management
smc.exe:						!!! Symantec (or possibly Sygate, check path) !!!
smceman.exe:						Sony GigaPocket TV Tuner
SMceMan.exe:						Sony GigaPocket TV Tuner
SmcGui.exe:						!!! Symantec !!!
SMEX_ActiveUpda:						!!! TrendMicro ScanMail for Exchange !!!
SMEX_Master.exe:						!!! TrendMicro ScanMail for Exchange !!!
SMEX_RemoteConf:						!!! TrendMicro ScanMail for Exchange !!!
SMEX_SystemWatc:						!!! TrendMicro ScanMail for Exchange !!!
smhstart.exe:						HP system management homepage service
smirror.exe:						MSC BAM Services
smlogsvc.exe:						Microsoft logs and alerts service
SMML.exe:						SIWF BAM Services
SMmonitor.exe:						IBM Storage Manager
smmss.exe:						??? Adware.W32.Ezula ???
Smon.exe:						Sharp Printer Driver Helper
smoothview.exe:						TOSHIBA Zooming Utility
smOutlookPack.exe:						!!! TrendMicro PC-cillin !!!
smoutlookpack.exe:						!!! TrendMicro PC-cillin !!!
sms.exe:						!!! Symantec !!!
smschk.exe:						??? BKDR_BREPLIBOT.G Trojan ???
SMSECtrl.exe:						!!! Symantec !!!
SMSELog.exe:						!!! Symantec !!!
SmServAuth.exe:						SiteMinder Site Authorization Service
SmServAz.exe:						SiteMinder Site Authorization Service
SMSESJM.exe:						!!! Symantec !!!
SMSESp.exe:						!!! Symantec !!!
smsesp.exe:						!!! Symantec !!!
SMSESrv.exe:						!!! Symantec !!!
SMSETask.exe:						!!! Symantec !!!
SMSEUI.exe:						!!! Symantec !!!
smsmdm.exe:						RDP Miniport
smsmon32.exe:						Microsoft Windows Operating System SMS x.x Client
smsonx32.exe:						??? Backdoor.W32.BREPLIBOT ???
smss.exe:						Session Manager Subsystem
smsss.exe:						??? AGOBOT Worm ???
SMSVC.EXE:						CheckUPS II Advanced
smsx.exe:						Security Technology Solutions SMSexpress
smsystemanalyzer.exe:						iolo System Mechanic
smszac32.exe:						??? BKDR_BREPLIBOT.N Trojan ???
smtp-gw.exe:						Gauntlet SMTP Proxy?
smtp.exe:						Merak Mail SMTP Service
SMTP32.exe:						IMail SMTP Server
smtp32.exe:						IMail SMTP Server
smtpd32.exe:						IMail SMTP Server
SMTPd32.exe:						IMail SMTP Server
SMTPD32.exe:						IMail SMTP Server
smtpda.exe:						MailSite SMTP Delivery Service
SMTPDA.EXE:						MailSite SMTP Delivery Service
smtpds.exe:						IMS SMTP Delivery Agent
smtpra.exe:						MailSite SMTP Receiver Service
SMTPRA.EXE:						MailSite SMTP Receiver Service
SMTPRS.exe:						IMS SMTP Receiver
SMTPRS.EXE:						IMS SMTP Receiver
smtray.exe:						Analog Devices Inc.
SMTray.exe:						Soundcard system tray program
SNAC.EXE:						!!! Symantec Network Access List !!!
SNAC.exe:						!!! Symantec Network Access Control !!!
SnareCore.exe:						SNARE Service
sndmon.exe:						!!! Symantec !!!
SNDMon.exe:						!!! Symantec !!!
sndrec32.exe:						Microsoft Windows Sound Recorder
sndsrvc.exe:						!!! Symantec !!!
SNDSrvc.exe:						!!! Symantec !!!
sndvol32.exe:						Microsoft Windows Volume Control
SnHwSrv.exe:						!!! Secret Net !!!
SnICheckAdm.exe:						!!! Secret Net !!!
SnicheckSrv.exe:						!!! Secret Net !!!
SnIcon.exe:						!!! Secret Net !!!
sniffer.exe:						SystemSoft SystemWizard Sniffer
Sniffer.exe:						??? Sniffer ???
SniperInstoe.exe:						Microsoft Outlook Anti-Spam
snmd adc servic:						SNMD alarm collector
snmd adc service.exe:						Switch Commander Application
SNMP-Brute-Force-Attack.exe:						Solarwinds tool
SNMP-Dictionary-Attack.exe:						Solarwinds tool
SNMP.EXE:						SNMP
snmp.exe:						Microsoft SNMP Agent
snmpc32.exe:						SNMPc Network Manager
snmpdm.exe:						SNMP EMANATE Master Agent
SNMPGraph.exe:						Solarwinds tool
SnmpIpmService.exe:						Switch Commander Application
snmpmagt.exe:						BMC Patrol Agent
SNMPMan.exe:						MSC BAM Services
SNMPSweep.exe:						Solarwinds tool
snmptrap.exe:						Microsoft SNMP Trap Service
SnSrv.exe:						!!! Secret Net !!!
soap.exe:						??? System Soap Pro Spyware ???
sockservercfg.exe:						??? Backdoor.W32.SkSocket ???
soffice.exe:						OpenOffice.org 1.1.0)
soft3.exe:						??? Adware.W32.SpySheriff ???
softManager.exe:						!!! 360_Safe !!!
SoftwareUpdate.exe:						Apple Software Update
sointgr.exe:						Sun StarOffice
sol.exe:						Microsoft Solitaire
SolarWinds TFTP Server.exe:						SolarWinds TFTP
SolarWinds-Toolbar.exe:						Solarwinds tool
SolarWinds.BusinessLayerHost.exe:						SolarWinds Orion
SolidWorksLicensing.exe:						SolidWorks CAD Software
SolidWorksLicTemp.0001:						SolidWorks CAD Software
solproxy.exe:						Dell System Management?
Sonar.exe:						Solarwinds tool
SonicStageMonitoring.exe:						Sony GigaPocket
sonicstagemonitoring.exe:						Sony GigaPocket
sonytray.exe:						Sony Cameras Traybar
soproc.exe:						SoftwareOnline Intelligent Downloader
soundman.exe:						Realtek Avance Logic Inc
SOUNDMAN.EXE:						Realtek audio card system tray icon
soundmand.exe:						Realtek Soundcard Driver
soundtrax.exe:						Ahead Nero Soundtrax
sp.exe:						??? Spy.Passkiller  Virus ???
sp2ctr.exe:						??? DLUCA-M Trojan Module ???
sp2update.exe:						adware sp2update
sp2update00.exe:						??? unclassified trojan ???
Spam-Blacklist.exe:						Solarwinds tool
spamsub.exe:						SpamSubtract Component
spamsubtract.exe:						InterMute SpamSubtract
SpamSubtract.exe:						InterMute SpamSubtract
spbbcsvc.exe:						!!! Symantec !!!
SPBBCSvc.exe:						!!! Symantec !!!
spcss32.exe:						*** EXPANDINGPULLY ***
spd.exe:						cFosSpeed System Service
spedia.exe:						??? 2nd Thought Spyware ???
speedkey.exe:						MS Intellitype Pro
SpeedKey.exe:						MS Intellitype Pro
speedmgr.exe:						T-Online SpeedManager
speedupmypc.exe:						SpeedUpMyPC
spider.exe:						Dr.Web for Windows Module
SpIDerAgent.exe:						!!! Dr Web !!!
spideragent.exe:						!!! DrWeb !!!
spiderml.exe:						!!! DrWeb !!!
SPIDERML.EXE:						!!! DrWeb !!!
spidernt.exe:						!!! DrWeb !!!
SPIDERNT.EXE:						!!! DrWeb !!!
spiderui.exe:						!!! DrWeb !!!
spin32.ocx:						Microsoft SpinButton Control
spkrmon.exe:						SoundMAX SpeakerMonitor Module
splash.exe:						HP VPN Server Appliances Client Deployment Tool
spmgr.exe:						Sony VAIO Power Management Module
spnsrvnt.exe:						SafeNet Sentinel
spntsvc.exe:						!!! TrendMicro ServerProtect !!!
SpntSvc.exe:						!!! TrendMicro ServerProtect !!!
spoler.exe:						??? RANDEX.J virus Virus ???
spollsv.exe:						??? Trojan.W32.LovGate ???
spool.exe:						??? RapidBlaster SpyWare ???
spool32.exe:						Printer Spooler
spoolav.exe:						??? Trojan/Backdoor ???
spooler.exe:						??? WIN32.RBOT Worm Module ???
spools.exe:						??? W32/Kassbot-C trojan ???
spoolsrv.exe:						??? spoolsrv.exe Virus Virus ???
spoolsrv32.exe:						??? TopAntiSpyware Malware ???
SPOOLSS.EXE:						Spooling Service Subsystem
spoolss.exe:						Microsoft Printer Spooler Subsystem
spoolsv.exe:						Microsoft Printer Spooler Service
SPOOLSV.EXE:						Microsoft Printer Spooler Service
spoolsvc.exe:						??? W32.SXTB.A Trojan ???
SpoolSvc.exe:						??? W32.SXTB.A Trojan Virus Trojan ???
SpoolSvc.exe:						??? W32.SXTB.A Trojan ???
spoolsw.exe:						??? Trojan/Cmdpipe-A ???
sppsvc.exe:						Microsoft Software Protection Platform Service
sprite.exe:						??? Adware.W32.BargainBuddy ???
sprtcmd.exe:						Dell Support Center
sprtsvc.exe:						SupportSoft Sprocket Service (Dell Support)
spsadmin.exe:						SharePoint Portal Server
SPSNotificationService.exe:						SharePoint Portal Server
spupdsvc.exe:						Update RunOnce Service
SputnikFlashPlayer.exe:						Mail.ru browser addon
SputnikHelper.exe:						Mail.ru browser addon
SPUVolumeWatcher.exe:						Sony Picture Utility Volume Watcher
spvic.exe:						InstantChess.com
spvspool.exe:						??? Trojan.W32.Dabora ???
spyagent.exe:						SpyAnywhere
spyagent4.exe:						??? SpyTech SpyAgent monitoring software Spyware ???
spyanywhere.exe:						SpyAnywhere
spyaxe.exe:						Parasite.SpyAxe.Process
spyblast.exe:						MOTION spyblast
spybotsd.exe:						Spybot - Search & Destroy
spybuddy.exe:						??? 1Win32Cfg Trojan ???
spybuddy.exe:						??? 1Win32Cfg Trojan ???
SpyEmergency.exe:						!!! Netgate Spy Emergency !!!
SpyEmergencySrv.exe:						!!! Netgate Spy Emergency !!!
spyrename.exe:						SpyAnywhere
SpySer.exe:						Mylex Global Array Manager Server
spysheriff.exe:						??? Adware.W32.SpySheriff ???
spysub.exe:						SpySubtract
spysweeper.exe:						Webroot SpySweeper
spysweeperui.exe:						Spy Sweeper Enterprise Client Executable
spytrooper.exe:						??? Adware.W32.SpyTrooper ???
spyware.exe:						??? Spy Software ???
sq_3394_3222.exesqinstaller.exe:						??? 2nd Thought Spyware ???
sqlagent.exe:						Microsoft SQL Server Agent
sqlagent.EXE:						Microsft SQL Server Agent
SQLAGENT90.EXE:						Microsoft SQL Server
sqlbrowser.exe:						Microsoft SQL Server SQL Browser Service
SQLEXEC.EXE:						SQLServer Exeutive Service
sqlexp.exe:						??? Trojan.W32.Dasher ???
sqlexp1.exe:						??? Trojan.W32.Dasher ???
sqlexp2.exe:						??? Trojan.W32.Dasher ???
sqlexp3.exe:						??? Trojan.W32.Dasher ???
sqlmangr.exe:						Microsoft SQL Server Service Manager.
sqlrep.exe:						??? Trojan.W32.Dasher ???
sqlscan.exe:						??? Trojan.W32.Dasher ???
sqlserver.exe:						??? Trojan.W32.SAMX ???
SQLSERVR.EXE:						SQLServer
sqlservr.exe:						Microsoft SQL Server Suite
sqltob.exe:						??? Trojan.W32.Dasher ???
SqlWb.exe:						SqlServer
sqlwriter.exe:						Microsoft SQL Server
squid.exe:						Proxy Caching Server
sr.exe:						??? Adware.W32.WinFixer ???
sr_gui.exe:						Secure Client Application
SR_Service.exe:						Checkpoint VPN-1 Secure Client Software
sr_watchdog.exe:						Check Point SecuRemote Watchdog
srmclean.exe:						Srmclean
srng.exe:						Search hijacker
srsmain.exe:						Microsoft Exchange Recovery
srtin.exe:						??? Adware.W32.DelFin ???
srv1.exe:						??? Spyware.W32.AdClicker ???
srv2.exe:						??? Adware.W32.AdClicker ???
srv32.exe:						??? OPASERV.J virus Virus ???
srv4.exe:						??? Adware.W32.AdClicker ???
srvany.exe:						Srvany
SRVANY.EXE:						Run Processes as a Service
srvc32.exe:						??? Small.DP Trojan ???
srvcapal.exe:						Menesk APAL Printer Activity Loger
srvcsurg.exe:						Microsoft Remote Administration Service
SrvCtrl.exe:						Fujitsu Siemens ServerView Agent
srvhandle.exe:						??? Trojan.W32.Redplut ???
srvload.exe:						!!! Panda Internet Security !!!
srvmgr.exe:						Microsoft Server Manager
srvmon.exe:						!!! McAfee !!!
ss.exe:						OnlinePCfix SmoothSurfer
ss3dfo.scr:						3D Flying Objects Screen Saver
ss_silent.exe:						??? Adware.W32.SearchMiracle.EliteBar ???
ssaad.exe:						Sonic Stage Module
ssbezier.scr:						Bezier Screen Saver
ssbkgdupdate.exe:						Scansoft Product Update
ssc_service_x.exe:						SIEMENS
sschk.exe:						!!! Simply Super Software Trojan Scanner !!!
ssdpsrv.exe:						Windows SSDP Service
SSecurityManager.exe:						SIWF BAM Services
ssee.exe:						??? Adware.W32.WinBo32 ???
sservcfg.exe:						Siemens Simatic Net process
sservice.exe:						??? Backdoor.Prorat Trojan ???
ssexp.exe:						Visual SourceSafe
ssflwbox.scr:						Screen Saver
ssgrate.exe:						??? Trojan.Mitglieder.C ???
sshd.exe:						Cygwin OpenSSH Secure Shell Daemon
ssk.exe:						??? Adware.W32.SurfSideKick ???
ssk3.exe:						??? Adware.W32.SurfSideKick ???
ssk3_b5 seedcorn 4.exe:						??? Adware.W32.SurfSideKick ???
ssk3_b5.exe:						??? Adware.W32.SurfSideKick ???
ssk3_b5[1].exe:						??? Adware.W32.SurfSideKick ???
ssk3_installerv5.exe:						??? Adware.W32.SurfSideKick ???
ssk3b5doublemedia.exe:						??? Adware.W32.SurfSideKick ???
ssk_b5 ventura marketing 15.exe:						??? Adware.W32.SurfSideKick ???
ssk_b5.exe:						??? Adware.W32.SurfSideKick ???
sskb5.exe:						??? Adware.W32.SurfSideKick ???
sskupdater.exe:						??? Adware.W32.SurfSideKick ???
sskupdater3.exe:						??? Adware.W32.SurfSideKick ???
sskupdater4bp5.exe:						??? Adware.W32.SurfSideKick ???
ssl.exe:						??? W32 Worm Module ???
SSM.exe:						!!! Symantec or Veritas Net Backup !!!
ssmarque.scr:						Marquee Screen Saver
SSMMgr.exe:						Samsung Panel Manager
ssmypics.scr:						Windows My Pictures Slideshow Screensaver
ssmyst.scr:						Mysterious Screen Saver
ssoftsrv.exe:						Cryptainer Encryption Service
ssonsvr.exe:						Citrix MetaFrame Client
SSOSRV.EXE:						Microsoft Single Sign-On
sspipes.scr:						Pipes Screen Saver
ssrms.exe:						??? Backdoor.Naninf.B Trojan ???
SSScheduler.exe:						!!! McAfee Security Scan !!!
ssscsisv.exe:						SonicStage Media Player Scsi I/F Server
ssstars.scr:						Stars Screen Saver
sssvr.exe:						VAIO Media Music Server
SStats.exe:						SIWF BAM Services
sstext3d.scr:						Text 3D Screen Saver
sstray.exe:						NVIDIA nForce2
ssu.exe:						Spy Sweeper Module
ssyssz6r.exe:						??? Adware.W32.ZenoSearch ???
ssyszu2r.exe:						??? Adware.W32.ZenoSearch ???
stacmon.exe:						SigmaTel Audio Assistant
Stacmon.exe:						SigmaTel Audio Assistant
stacsv.exe:						SigmaTel PC Audio
StandAloneSlv.exe:						CAD software
StarBoardControlBox.exe:						Hitachi Starboard Application
StarEngine8.exe:						Microsoft Antigen for Exchange
StarEngine9.exe:						Microsoft Antigen for Exchange
start.exe:						??? Secret-Crush Spyware ???
starta.exe:						AntiVir Security Management Center Agent Module
StartAutorun.exe:						5-button mouse
STARTEAK.exe:						Compaq Multimedia
starteak.exe:						Compaq Multimedia
starter.exe:						Creative Labs Ensoniq Mixer Tray icon
startup5.exe:						??? AdStatus Service Spyware ???
startupcfg.exe:						SNMPc Network Manager
startupmonitor.exe:						StartupMonitor
starwind:						Alcohol 120\% StarWind
starwindservice.exe:						Alcohol 120\% StarWind
StarWindServiceAE.exe:						iSCSI Service (Alcohol Soft)
statemgr.exe:						Microsofts PC State Manager Stub
Stats.exe:						MSC BAM Services
StatsSnapshotSe:						StatsSnapshotService
StatusClient.exe:						Hewlett-Packard Status Client
statusclient.exe:						Hewlett-Packard Status Client
stb.exe:						??? Downloader.W32.Agent ???
StBuddyList.exe:						Lotus
stc.exe:						??? 2nd Thought Spyware ???
stc[1].exe:						??? 2nd Thought Spyware ???
StChatLogging.exe:						Lotus
stcloader.exe:						??? 2nd-Thought Stcloader Spyware ???
StCommlaunch.exe:						Lotus
StCommunity.exe:						Lotus
StConference.exe:						Lotus
StConfiguration.exe:						Lotus
StDirectory.exe:						Lotus
stealth.dcom.exe:						??? PE_THEALS.A Worm ???
stealth.ddos.exe:						??? PE_THEALS.A Worm ???
stealth.exe:						??? PE_THEALS.A Worm ???
stealth.injector.exe:						??? PE_THEALS.A Worm ???
stealth.stat.exe:						??? PE_THEALS.A Worm ???
stealth.wm.exe:						??? PE_THEALS.A Worm ???
stealth.worm.exe:						??? PE_THEALS.A Worm ???
steam.exe:						GameSpy Steam
stillimagemonitor:						Microsoft Still Image Monitor
STImgBrowser.exe:						Stoik Photo Viewer
stimon.exe:						Microsoft Windows 98/MEs Still Image Monitor.
stinger.exe:						!!! McAfee Stinger !!!
stisvc.exe:						Microsoft Still Image Service
StLaunch.exe:						Lotus
StLogger.exe:						Lotus
stmgr.exe:						Microsoft PCHealth
stmtdlr.exe:						??? Dialer.W32.Saristar ???
StMux.exe:						Lotus
StOnlineDir.exe:						Lotus
stopa.exe:						AntiVir Security Management Center Agent Module
stopp.exe:						!!! TrendMicro ServerProtect !!!
StOPP.exe:						!!! TrendMicro ServerProtect !!!
STORE.EXE:						Exchange Information Store
store.exe:						Microsoft Exchange Component
storport.exe:						SCSI Port Driver
StorServ.exe:						Adaptec Storage Manager
StPlaces.exe:						Lotus
STPolling.exe:						Lotus
str.exe:						??? Adware.W32.WinFixer ???
STRTDB73.EXE:						Oracle?
stsconv.exe:						AP/STS Switch Control
stsmain.exe:						AP/STS Switch Control
stsopcf.exe:						AP/STS Switch Control
stsprov.exe:						AP/STS Switch Control
stsystra.exe:						SigmaTel C-Major Audio Tray App
sttray.exe:						SigmaTel Audio Tray Application
stub.exe:						Stub
stubinstaller.exe:						??? 180SearchAssistant Spyware ???
stubinstaller4292.exe:						??? 180SearchAssistant Spyware ???
stubinstaller5975[1].exe:						??? 180SearchAssistant Spyware ???
studio.exe:						Nullsoft WinAmp
stunnel.exe:						Secure Tunnel
StUsers.exe:						Lotus
stwatchdog.exe:						!!! TrendMicro ServerProtect !!!
StWatchDog.exe:						!!! TrendMicro ServerProtect !!!
StyleXPService.exe:						TGTSoft StyleXP
SubnetCalc.exe:						Solarwinds tool
SubnetList.exe:						Solarwinds tool
suchost.exe:						??? Trojan.Treb  Trojan ???
suhoy112.exe:						??? Trojan.W32.Clagger ???
sunasdtserv.exe:						CounterSpy Client
sunasserv.exe:						Sunbelt CounterSpy
sunprotectionserver.exe:						Sunbelt CounterSpy
sunserver.exe:						Sunbelt CounterSpy
SunstarTime.exe:						SunStarTime NTP Client
sunthreatengine.exe:						CounterSpy Threat Audit Engine
superaccesso.exe:						??? Dialer.W32.startpage ???
Supervisor.exe:						IntranetRoot Help Desk Software
support.exe:						Dell Support Assistant
supporter5.exe:						eScorcher anti-virus
supportinstall.exe:						??? Adware.W32.WebRebates ???
supra.exe:						Supra Modem
SupServ.exe:						Sony Ericsson PC Suite
surfsidekick.exe:						??? Adware.W32.SurfSideKick ???
Surveyor.EXE:						Surveyor
surveyor.exe:						Compaq Survey Utility service
SURVEYOR.EXE:						Surveyor
surveysa.exe:						Sony Vaio  Support Module
sus.exe:						Primetech Encryption database
SUService.exe:						Lenovo System Update
susp.exe:						abetterinternet spyware
Susp.exe:						??? abetterinternet spyware Spyware ???
suss.exe:						Microsoft Switch User server
sv_httpd.exe:						Sony HTTP Server
svaplayer.exe:						??? n-Case Spyware ???
svc.exe:						??? MAPFIND Virus Virus Spyware ???
svcbost.exe:						??? Keylog-ZZ Trojan ???
svcbost.exe:						??? Trojan/Keylog-ZZ ???
svcdata.exe:						??? W32.Spybot.ZIF Trojan ???
svcGenericHost:						!!! TrendMicro ScanMail for Exchange !!!
svch0st.exe:						??? Trojan.Gamqowi ???
svcharge.exe:						!!! SiliVaccine Antivirus !!!
SVCharge.exe:						!!! SiliVaccine Antivirus !!!
svchoost.exe:						??? TROJ_SVHOOST.A Trojan ???
svchos1.exe:						??? WORM_AGOBOT.R ???
svchosl.exe:						??? W32/Agobot-Q virus Virus ???
svchost.exe:						Microsoft Service Host Process (Check path in processdeep)
svchostl.exe:						??? Trojan.W32.BLASTER ???
svchosts.exe:						??? Troj/Sdbot-N ???
svchot.exe:						??? Trojan.W32.Amirecivel ???
svcinit.exe:						??? Backdoor.Sinit  Virus Trojan ???
svcmgr.exe:						BusinessObjects Enterprise 11.5
svcntaux.exe:						!!! Spyware_Doctor 5 from PC Tools !!!
svcproc.exe:						??? Trojan.Win32.Stervis.b ???
svdealer.exe:						!!! SiliVaccine Antivirus !!!
SVDealer.exe:						!!! SiliVaccine Antivirus !!!
svframe.exe:						!!! SiliVaccine Antivirus !!!
SVFrame.exe:						!!! SiliVaccine Antivirus !!!
svhost.exe:						??? W32.Mydoom.I\@mm Virus Trojan ???
svhosts.exe:						??? Backdoor.W32.Haxdoor ???
svohcst.exe:						??? Trojan.W32.Kurofoo ???
svpwutil.exe:						Toshiba utility
svshost.exe:						??? Worm.P2P.Spybot.gen virus Virus ???
svshots.exe:						??? Backdoor.W32.VB ???
svtray.exe:						!!! SiliVaccine Antivirus !!!
SVTray.exe:						!!! SiliVaccine Antivirus !!!
svwhost.exe:						??? Trojan.SVWHost.Process ???
swagent.exe:						SonicWall Internet Firewall
SWarn.exe:						SIWF BAM Services
SWCPUGauge.exe:						Solarwinds tool
swdoctor.exe:						??? Spyware Doctor ???
swdsvc.exe:						!!! Spyware_Doctor 5 from PC Tools !!!
sweepsrv.sys:						!!! Sophos Anti-Virus !!!
sweetim.exe:						SweetIM MSN Messenger Enhancer
sweudora.exe:						Eudora Installation Service
swEudora.exe:						Eudora Installation Service
swiftbtn.exe:						Fujitsu Siemens Additional Keyboard Support
SwiftBTN.exe:						Fujitsu Siemens Additional Keyboard Support
SWIHPWMI.exe:						Sierra Wireless
swimsuitnetwork.exe:						??? protected materials Swimsuitnetwork Spyware ???
switcher.exe:						Sony Wireless Switch Setting Utility
SWITCHIT.EXE:						Switch It! Language Utility
SwitchPortMapper.exe:						Solarwinds tool
switpa.exe:						??? OfferAgent Adware ???
SWLauncher.exe:						Solar Windows TFTP Server
swlistsvc.exe:						AP/ACS Switch Control
SWNETSUP.EXE:						!!! Sophos Anti-Virus !!!
swnetsup.exe:						!!! Sophos Anti-Virus !!!
swnxt.exe:						!!! Spyware Nuker !!!
sws.exe:						Microsoft Smooth Working Set
swserver.exe:						!!! StatWin Total !!!
swsoc.exe:						ColdFusion MX ODBC Server
swstrtr.exe:						ColdFusion MX ODBC Server
swupdtmr.exe:						Toshiba Software Update
sxgdsenu.exe:						Yamaha Ssxgdsenu
sxgtkbar.exe:						Yamaha Multiemdia
sxplog32.exe:						Update for CA Software Delivery
sychost.exe:						??? LEOX.B VIRUS  Virus ???
symcint.exe:						SymCiService
symlcsvc.exe:						!!! Symantec !!!
SymmTime.exe:						Symmetricom SymmTime NTP Client
symproxysvc.exe:						!!! Symantec !!!
symsport.exe:						!!! Symantec !!!
SymSPort.exe:						!!! Symantec !!!
symtray.exe:						!!! Symantec !!!
symwsc.exe:						!!! Symantec !!!
sync.exe:						Microsoft Sync
synchost.exe:						??? RIPJAC virus Virus Trojan ???
syncroad.exe:						??? SyncroAd Spyware ???
SyncroAd.exe:						??? SyncroAd Spyware ???
SynToshiba.exe:						Synaptics SynTP or Toshiba Custom Plugin
syntpenh.exe:						Synaptics touchpad tray icon
SynTPHelper.exe:						Synaptics SynTP
syntplpr.exe:						Synaptics TouchPad Driver Helper
SynTPStart.exe:						Synaptics SynTP
sys.exe:						??? Backdoor.ICR Trojan ???
sys_alert.exe:						System Patch Alerter
sysagent.exe:						Netsizzle SYSagent
sysai.exe:						??? Apropos Media Trojan ???
SysAI.exe:						??? Apropos Media Trojan  Trojan ???
sysc.exe:						??? Trojan.W32.Locksky ???
syscfg32.exe:						??? Troj/IRCBot-H virus Virus ???
syscheckbop32.exe:						??? Adware.W32.WinBo32 ???
syscnfg.exe:						??? Syscnfg Virus Virus ???
sysconf.exe:						??? W32/Agobot-FP Trojan ???
sysdoc32.exe:						!!! Symantec !!!
sysdoor.exe:						??? TROJ_MTGLIEDR.BN  Trojan ???
SYSDOWN.EXE:						Compaq System Shutdown Service
sysdown.exe:						Compaq System Shutdown Service
SysEvtCol.exe:						ManageEngine EventLog Analyzer 6
sysfader.exe:						NVidia Graphics Utility
sysfit.exe:						??? AdShooter adware Spyware ???
sysformat.exe:						??? BAGLE.AZ Worm Virus Trojan ???
syshost.exe:						??? W32.Francette.Worm Virus Trojan ???
sysldr32.exe:						??? Trojan.W32.GAOBOT ???
SysLog-Server.exe:						Solarwinds tool
syslog.exe:						??? RapidBlaster Virus Virus ???
syslogagent.exe:						Huawei iManager T2000 Element Management Software
syslogd.exe:						IMail System Logger Service
SysLogd.exe:						IMail System Logger Service
SYSLOGD.exe:						IMail System Logger Service
SYSLOGD.EXE:						IMail System Logger Service
syslogd_service:						syslog
syslogd_service:						syslog
Syslogd_Service.exe:						Kiwi Syslog Daemon
Syslogin.exe:						Family Cyber Alert
SyslogService.exe:						SolarWinds Orion trap catcher
sysmon.exe:						AOpen System Monitor
sysmonidisp.exe:						Huawei T2000 Element Mgmt Software
sysmonitor.exe:						Huawei iManager T2000 Element Management Software
sysmonnt.exe:						Sysmon System Monitor Software
sysocmgr.exe:						System Optional Component Manager
syspol.exe:						??? Trojan.Chuvazada ???
sysreg.exe:						??? SearchSeekFind Spyware ???
syss.exe:						??? Trojan.W32.RealSearch ???
syssfitb.exe:						Searchforit browser hijacker
SYSsfitb.exe:						??? Searchforit browser hijacker Spyware ???
systask32l.exe:						??? Troj/IRCBot-H virus Virus ???
systb.exe:						??? Adware.IEPlugin ???
system:						System Kernel
System:						System Kernel
system idle:						System Idle Process
system idle process:						System Idle Counter
system.exe:						!!! LanAgent Monitoring !!!
system.update.exe.exe:						??? Trojan.W32.MINUSIA ???
system16.exe:						??? Agent-EN Trojan ???
system32.exe:						??? MARI Virus Virus ???
system32win.exe:						??? Downloader.W32.IstBar ???
systemdll.exe:						??? Troj/IRCBot-H virus Virus Trojan ???
SystemEye.exe:						+++ Resource Monitor +++
Systemtm.exe:						MediaLand TCO Client
systemtray.exe:						??? BIGFOOT Trojan ???
systemup.exe:						??? Agent-EN Trojan ???
systime.exe:						??? CoolWebSearch Parasite Virus Spyware ???
systool.exe:						??? Trojan.W32.RealSearch ???
systra.exe:						??? Trojan.W32.LovGate ???
systray.exe:						Microsoft System Tray Services
SysTray.Exe:						System Tray
systray32.exe:						??? ActiveDesktop ???
systune.exe:						??? Ace Spy Spyware ???
Sysupd.exe:						Sysupd.exe  Virus
sysupdate.exe:						??? Adware.W32.Cashback ???
sysvcs.exe:						??? Orse-F  Trojan ???
syswast.exe:						??? Adware.W32.Wast ???
syswin.exe:						??? Dialer.W32.dialer ???
sywsvcs.exe:						??? Trojan.SYWSVCS.Process ???
sz.exe:						Remotely Anywhere
szchost.exe:						??? Trojan.Mercurycas.A ???
Szchost.exe:						??? Trojan.Mercurycas.A Virus Trojan ???
szntsvc.exe:						STOPzilla NT Service
T2000 EmfTopoDm.exe:						Huawei
T2000 Eml_monitomcat.exe:						Huawei
t2kzip.exe:						Huawei T2000 Element Mgmt Software
ta.exe:						??? Downloader.W32 ???
tabbtnu.exe:						Tablet PC Buttons Service
tabctl32.ocx:						TABCTL32 OLE Control DLL
tablet.exe:						Wacom Win32 Tablet Service
tabtip.exe:						Microsoft Tablet PC Module
tabuserw.exe:						Wacom Pen Tablet Module
tahnisetup_demo.exe:						??? Adware.W32.BargainBuddy ???
TAMSvr.exe:						AuthenTec TrueSuite Access Manager
TAPEENG.EXE:						ARCserveIT Tape Engine
tapicfg.exe:						??? Tapicfg ???
TapiServer.exe:						SC Task Server
TAPISRV.EXE:						Telephony Service
tapisrv.exe:						Microsoft TAPI Service
tapport.exe:						TAPRecord Protected
tappsrv.exe:						Toshiba Application Service
tardisnt.exe:						Windows Time Synchronization Utility
targetsaver.exe:						??? Adware.W32.TargetSaver ???
task.exe:						??? W32/Randon-Z worm ???
task32.exe:						??? unidentified mIRC virus Virus ???
taskbar.exe:						??? W32.Frethem.L@mm Virus Virus ???
taskbaricon.exe:						Wanadoo Internet Traybar
taskcntr.exe:						??? W32/Tilebot-S worm ???
taskdrv32.exe:						??? Trojan.W32.KELVIR ???
taskeng.exe:						Vista Task Scheduler Engine
tasker.exe:						??? Mydoom.R Trojan ???
taskg.exe:						??? Trojan.W32.MyTob ???
taskgmr.exe:						??? Trojan.W32.MyTob ???
taskhost.exe:						Windows 7 Generic Host Process
TaskInfo.exe:						Iarsn TaskInfo2003 5.0
taskman.exe:						+++ Task Manager +++
TASKMGR.EXE:						+++ Windows Task Manager +++
taskmngr.exe:						??? RBOT.Y Worm ???
taskmon.exe:						Windows Task Manager
taskmonitor:						Task Manager
taskpanl.exe:						E6TaskPanel
taskswitch.exe:						Microsoft TaskSwitch Utility
tasksys.exe:						??? W32.Botter.A\@mm Worm ???
TAudEff.exe:						TOSHIBA Mic Effect
tb2launch.exe:						Timbuktu Launch
tb2pro.exe:						Timbuktu Pro for Windows
Tb2RCAssist.exe:						Timbuktu Remote Control Assistant
tb_setup.exe:						??? Toolbar Hijacker Spyware ???
tbctray.exe:						Voyetra Turtle Beach Task Tray
tbksche.exe:						TurboBackup Scheduler
tblmouse.exe:						Aiptek HyperPen driver
tbmon.exe:						!!! McAfee VirusScan !!!
TBMon.exe:						!!! McAfee VirusScan !!!
TBMon.exe:						!!! McAfee VirusScan !!!
tbon.exe:						??? Adware.W32.BestOffers ???
tbpanel.exe:						TBPanel
TBPanel.exe:						Gainward graphics card software
TBPS.EXE:						??? WinTools Adware Spyware ???
tbps.exe:						??? Neo Toolbar Spyware ???
tbpssvc.exe:						??? Neo Toolbar Spyware ???
tc.exe:						TimeCalender
tca.exe:						??? Moosoft Trojan Cleaner ???
TCAUDIAG.EXE:						3Com Diagnostic
tcaudiag.exe:						3Com Diagnostics
tclient.exe:						MediaLand TCO Client
tclock.exe:						TClock Utility
tclproc.exe:						!!! ISS RealSecure IDS !!!
tcm.exe:						??? Moosoft Trojan Monitor ???
TCP-Reset.exe:						Solarwinds tool
tcpservice2.exe:						??? Spyware.W32.WStart ???
TCPSVCS.EXE:						TCP Services
tcpsvcs.exe:						TCP/IP Services
tcpview.exe:						+++ TCP viewer +++
TCrdMain.exe:						Toshiba FlashCards
tcserver.exe:						Microsoft Tablet PC Server Component
tctrliohook.exe:						Toshiba Control Utility Hotkey Hook
tdc.ocx:						TDC ActiveX Control
tdimon.exe:						!!! SysInternals TDI Monitor !!!
TeamViewer.exe:						TeamViewer Remote Control
TeamViewer_Service.exe:						TeamViewer Remote Control
TeaTimer.exe:						Spybot S&D Realtime Scanner
teatimer.exe:						Spybot S&D Realtime Scanner
tedtray.exe:						TOSHIBA DualPoint Utility Main Module
teekids.exe:						??? Teekids ???
telnet.EXE:						TELNET.EXE Telnet Command
telnet.exe:						TELNET.EXE Telnet Command
telnetd.exe:						Ataman Telnetd Server
TELNETD.EXE:						Ataman Telnetd Server
temp.exe:						??? Adware.W32.Windupdates ???
temp532.exe:						??? Dialer.W32.Temp532 ???
termsrv.exe:						Terminal Server Service
TERMSRV.EXE:						Terminal Server
Test.exe:						MSC BAM Services
TestAlerts.exe:						Solarwinds tool
testing.exe:						??? W32/Spybot-B virus Virus ???
TFGui.exe:						!!! Threatfire GUI !!!
tfncky.exe:						Tfncky
tfnf5.exe:						TFNF5
TFService.exe:						!!! ThreatFire PSP !!!
tfswctrl.exe:						HP DLA Packet Writing Software
TFTP-Server.exe:						Solarwinds tool
tftp32.exe:						Opensource TFTP Server OR Distinct Corp. Visual Internet Toolkit (check path)
tftpd32_svc.exe:						Tftpd32 SE TFTP Server
TftpService.exe:						WinAgents Tftp Service
tftpsvc.exe:						Turbosoft TurboFTP Sync Service Module OR Distinct Corp. Visual Internet Toolkit (check path)
TFTray.exe:						!!! ThreatFire PSP !!!
TFun.exe:						!!! Threatfire !!!
tgcmd.exe:						Tgcmdprovidersbc
tgfix.exe:						TgAddServer
the weather channel.exe:						Weather Channel Alerter
thebat.exe:						The Bat email client
thgtaskbar.exe:						TortoiseHg MS Shell Extension
thotkey.exe:						THOTKEY
ThpSrv.exe:						TOSHIBA HD DProtection Service
threed32.ocx:						Sheridon 3D controls
thunderbird.exe:						Mozilla Thunderbird
TIASPN~1.EXE:						!!! Traffic Inspector 2.0 !!!
tibs.exe:						??? Dialer.W32.TIBS ???
tibs3.exe:						??? Adult Content Dialer ???
tier1slp.exe:						IBM Systems Director
timershot.exe:						Webcam Timershot
TIMESERV.EXE:						Microsoft time synchronization utility
timessquare.exe:						??? Trojan.Times Square.Process ???
timesynchronize.exe:						??? Adware.W32.DealHelper ???
timeup.exe:						TimeUp - internet online timer
timountermonitor.exe:						Acronis TrueImage Monitor
TIMPlatform.exe:						Part of Chinese QQ IM client
tintsetp.exe:						TINTSETP
tkbell.exe:						Tkbell
TkBellExe:						RealOne Player
tkbellexe:						RealOne Player
tkonnect.exe:						Tiscali Internet Utility
tlbar.exe:						HideWindow
tlntsvr.exe:						Microsoft Win2k telnet server
TLS.exe:						HP Procurve Network Manager
tlsbln.exe:						Terminal Services Balloon Reminder
tmas.exe:						!!! TrendMicro Anti-Spyware !!!
tmeejme.exe:						??? Unknown ???
tmerzctl.exe:						Toshiba TME
tmesbs32.exe:						Toshiba Mobile Extension
tmesrv31.exe:						Toshiba Utility
tmksrvi.exe:						??? The Trojan horse TR/Tmks.2 ???
tmksrvu.exe:						??? TMKSoft.XPlugin Spyware ???
tmlisten.exe:						!!! TrendMicro PC-cillin !!!
TmListen.exe:						!!! TrendMicro !!!
tmntsrv.exe:						!!! TrendMicro PC-cillin !!!
Tmntsrv.exe:						!!! TrendMicro !!!
TMOAgent.exe:						Trend Micro Outbreak Agent
tmoagent.exe:						Trend Micro Outbreak Agent
tmp.exe:						??? Spyware.W32.123bar ???
tmp11e.exe:						??? Adware.W32.P2PNetworking ???
tmp333.exe:						??? Adware.W32.PacerD ???
tmpfw.exe:						!!! TrendMicro !!!
TmPfw.exe:						!!! TrendMicro !!!
tmproxy.exe:						!!! TrendMicro PC-cillin !!!
tmproxy.exe:						!!! TrendMicro !!!
tn-gw.exe:						Gauntlet Telnet Proxy?
TNaviSrv.exe:						Toshiba DVD Player
tnBacSrv.exe:						Siemens TNMS backup server
tnbutil.exe:						!!! F-Secure Internet Security !!!
tnClient.exe:						Siemens TNMS client
TNCremoNT.exe:						Heidenhain tech device measurer
tnNSrvF.exe:						Siemens TNMS NetServer
TNROTATE.exe:						TOSHIBA 180 Degrees Rotation Utility
tnslsnr.exe:						Oracle TNS Listener
TNSLSNR.EXE:						Oracle TNSL Listener
tnSrv.exe:						Siemens TNMS server
tnSysAdm.exe:						Siemens TNMS SysAdmin Application
toadimon.exe:						T-Online Connection Assistant
toc_0008.exe:						??? Downloader.W32.Agent ???
TODDSrv.exe:						Toshiba Backup Server
tomcat.exe:						Tomcat web servlet container
tomcat5.exe:						Computer Associates Tomcat 5.5
tomcat6.exe:						Apache Tomcat 6
TomTomHOMERunner.exe:						TomTom HOME2
tool.exe:						??? Trojan.W32.Mirchack ???
tool2.exe:						??? Paymite-B Trojan ???
tool3.exe:						Spy Sheriff Malware
toolkit.exe:						Huawei Optix Toolkit
ToolkitService.exe:						ToolKit Development Service
ToolTipFixer.exe:						NeoSmart ToolTip Fixer
topdesk.exe:						TopDesk
toposvr.exe:						Huawei iManager T2000 Element Management Software
tor.exe:						Tor anonymous connection client
tosa2dp.exe:						Bluetooth Stack for Windows by Toshiba
TosBtHid.exe:						TOSHIBA Bluetooth Stack
tosbthsp.exe:						Toshiba Bluetooth Stack
tosbtmng.exe:						Toshiba bluetooth stack
tosbtmng1.exe:						Related to Toshiba Bluetooth Stack Software
TosBtSrv.exe:						Toshiba Bluetooth Stack
toscdspd.exe:						Toshiba Laptop CD/DVD Component
TosCoSrv.exe:						Toshiba Power Saver
toshkcw.exe:						Toshiba Wireless Module
Totalcmd.exe:						+++ Total Commander +++
TOTALCMD.EXE:						Total Commander
TOTALCMD.EXE:						Upgraded File Manager
totrecsched.exe:						Total Recorder scheduler
TotRecSched.exe:						Total Recorder Scheduler - record online audio/video
touched.exe:						Toshiba TouchPad Component
TouchED.exe:						Toshiba TouchPad Component
tp4ex.exe:						Tp4ex
tp4mon.exe:						Tp4mon
tp4serv.exe:						Tp4serv
TpChrSrv.exe:						ThinkPad PM
TPCHSrv.exe:						TOSHIBA PC Health Monitor
TPCHWMsg.exe:						TOSHIBA PC Health Monitor
tpfnf7sp.exe:						Lenovo Presentation Director Fn+F7 Handler
tphdexlg.exe:						ThinkVantage Active Protection System
tphkmgr.exe:						ThinkPad Hotkey Manager
tpkmapap.exe:						IBM Thinkpad Keyboard Mapper
tpkmapmn.exe:						IBM Thinkpad Keyboard Mapper
tpkmpsvc.exe:						IBM ThinkPad Utility
TPONSCR.exe:						ThinkPad Hotkey Manager
tponscr.exe:						ThinkPad Hotkey Manager
tppaldr.exe:						TPP Auto Loader Application
tpsbattm.exe:						Toshiba Power Saver
TpScrex.exe:						ThinkPad UltraZoom
tpscrex.exe:						ThinkPad UltraZoom
tpscrlk.exe:						IBM Thinkpad Utility
tpshocks.exe:						IBM Hard Drive Active Protection
tpsmain.exe:						TOSHIBA Power Saver
tpsoddctl.exe:						Toshiba power saver
tpsrv.exe:						!!! Panda Anti-Virus !!!
tptray.exe:						Toshiba Laptops Traybar Process
TPwrMain.exe:						Toshiba Power Saver
tpwrtray.exe:						Tpwrtray
TraceRoute.exe:						Solarwinds tool
tracert.exe:						TRACERT.EXE Trace Route Command
TRACERT.EXE:						TRACERT.EXE Trace Route Command
tracesweeper.exe:						!!! 360_Safe !!!
trackinst.exe:						??? Adware.W32.GoGoTools ???
Trafficd.exe:						HP Procurve Network Manager
Traflnsp.exe:						!!! Traffic Inspector 2.0 !!!
TrafMonitor.exe:						+++ Traf Bandwidth Monitor +++
trans.exe:						??? 2nd Thought Spyware ???
TransitAgent.exe:						IS3 Satcom/Telecom Software
translator.exe:						??? Dialer.W32.intexusdial ???
TrapEditor.exe:						Solarwinds tool
Trapmnnt.exe:						Panasonic Trap Monitoring
TrapReceiver.exe:						Solarwinds tool
TrapTrackerMgr.exe:						!!! EventTracker SNMP Trap service !!!
traybar.exe:						Chicony Camera Assistant Software
trayclnt.exe:						Trayclnt
traymon.exe:						Traymon
traymonitor.exe:						1A
traysaver.exe:						1A
trayserver.exe:						1A
trcboot.exe:						IBM Personnal Communications
TRex.exe:						Hitachi Starboard Application
Triadz.exe:						Triadz! Game
trickler.exe:						??? GAIN Trickler Spyware ???
trickler_bic_gatorpt_4010.exe:						??? Adware.W32.ClariaPrecision ???
trillian.exe:						Trillian Chat Client
trjscan.exe:						!!! Simply Super Software Trojan Scanner !!!
TrueCrypt.exe:						TrueCrypt
Trueimagemonitor.exe:						Acronis backup software
trueimagemonitor.exe:						Acronis TrueImage
trueimageservice.exe:						Acronis TrueImage Service
TrueImageTryStartService.exe:						Acronis TrueImage
trupd.exe:						!!! Simply Super Software Trojan Scanner !!!
TrustedInstaller.exe:						Windows Modules Installer
ts.exe:						??? Travelling Salesman Spyware ???
ts2.exe:						??? Travelling Salesman Spyware ???
tsa.exe:						??? Travelling Salesman Spyware ???
tsadbot.exe:						??? Tsadbot Spyware ???
tsadmin.exe:						Terminal Server Administration
TSAnSrf.exe:						!!! Omniquad Total Security 3.0.0 !!!
TSAtiSy.exe:						!!! Omniquad Total Security 3.0.0 !!!
tsc.exe:						Micro Damage Cleanup Engine Component
tschelp.exe:						SnagIt Component
tsclient.exe:						Remotely Anywhere
TScutyNT.exe:						!!! Omniquad Total Security 3.0.0 !!!
tsinstall_4_0_3_7.exe:						??? Adware.W32.TargetSaver ???
tsinstall_4_0_3_8_b17.exe:						??? Adware.W32.TargetSaver ???
tskdbg.exe:						??? FLOOD.E VIRUS Virus Trojan ???
tskman.exe:						??? Trojan/Backdoor ???
tskman.exe:						??? Trojan/Backdoor ???
tskmgr32.exe:						??? Tskmgr32 Trojan ???
tskmgr32.exe:						??? Tskmgr32 Trojan ???
tsl.exe:						??? Travelling Salesman Spyware ???
tsl2.exe:						??? Travelling Salesman Spyware ???
tsl_rc0_wrap.exe:						??? Adware.W32.sqwire ???
tsm2.exe:						??? Travelling Salesman Spyware ???
TSmpNT.exe:						!!! Omniquad Total Security 3.0.0 !!!
tsmsvc.exe:						T-DSL SpeedManager
TSMSvc.exe:						T-DSL SpeedManager
tsp2.exe:						??? Travelling Salesman Spyware ???
tsrvctl_nt.exe:						MediaLand TCO Client
tssdis.exe:						Microsoft Terminal Services Session Manager
tstool.exe:						Starfish TrueSync
tsuninst.exe:						??? Adware.W32.TargetSaver ???
tsupdate_4_0_3_9_b2.exe:						??? Adware.W32.TargetSaver ???
tsvc.exe:						Tibbo Device Server Toolkit
tsvncache.exe:						TortoiseSVN
tsyssmon.exe:						System Stability Client Application
tsystray.exe:						RealNetworks Systray Software
tsysytd8.exe:						??? Adware.W32.ZenoSearch ???
tt_reco.exe:						??? 2nd Thought Spyware ???
ttd.exe:						HP OpenView
ttermpro.exe:						Tera Term Pro
ttsrv.exe:						HP OpenView
ttupt.exe:						??? Adware.W32.Ezula ???
TurniketFileReceiver.exe:						Tur COM-to-COM File Receiver (homegrown)
Tutor.exe:						ABBYY Lingvo 12
tv media display.exe:						??? Adware.W32.TVMediaDisplay ???
tv_media.exe:						??? Unknown ???
tvm.exe:						??? Adware.W32.TVMediaDisplay ???
Tvm.exe:						??? TVM Hijacker Spyware ???
tvm_b5.exe:						??? Adware.W32.TVMediaDisplay ???
tvm_b5_bundle_17.exe:						??? Adware.W32.TVMediaDisplay ???
tvmd.exe:						??? Tvmd Spyware ???
tvmedia.exe:						??? 2nd Thought Spyware ???
tvmon.exe:						Canon Application Module
tvmupdater.exe:						??? Adware.W32.TVMediaDisplay ???
tvmupdater4bp5.exe:						??? Adware.W32.TVMediaDisplay ???
tvnserver.exe:						TightVNC TVN Control Service
tvp.exe:						Altrise Terminal Video Player
tvstray.exe:						Toshiba Virtual Sound Tray Icon
tvt_reg_monitor_svc.exe:						Lenovo Reg Monitor
tvtmd.exe:						??? Tvtmd Spyware ???
tvtsched.exe:						Lenovo Scheduler
twgescli.exe:						IBM Systems Director
twgipc.exe:						IBM Systems Director
twgipcsv.exe:						IBM Systems Director
twgmonit.exe:						IBM Systems Director
twunk_64.exe:						??? Twunk_64 Spyware ???
TWWINSDR.EXE:						TapeWare automatic backup software
type32.exe:						Microsoft Office Keyboard Console
uaservice7.exe:						SecuROM User Access Service
UAService7.exe:						SecurRom User Access Service
uc.exe:						??? Uc Spyware ???
uc1362.exe:						??? Spyware.W32.WStart ???
UcService.exe:						!!! Symantec !!!
ucsi.exe:						??? Spyware.W32.WStart ???
ucstart.exe:						IBM Update connector
ucstartup.exe:						IBM Update Connector
UdaterUI.exe:						!!! McAfee VirusScan Enterprise !!!
udserve.exe:						Udserve
ufdsvc.exe:						USB Flash Drive
ulcdrsvr.exe:						Ulead DVD workshop Server
ULCDRSvr.exe:						Ulead DVD workshop Server
ULiveServer.exe:						UnrealStreaming ULiveServer
ULiveSrcConfig.exe:						UnrealStreaming ULiveServer
UltiDevCassinWebServer2a.exe:						Cassini Web Server
UMediaServer.exe:						UnrealStreaming ULiveServer
UMM.exe:						CallCenter UMM
umonit.exe:						USB Monitor
umqltg4cl_.exe:						??? Adware.W32.Ezula ???
UmxAgent.exe:						!!! CA Internet Security Suite 2007 !!!
UmxCfg.exe:						!!! CA Internet Security Suite 2007 !!!
UmxFwHlp.exe:						!!! CA Internet Security Suite 2007 !!!
UmxPol.exe:						!!! CA Internet Security Suite 2007 !!!
unadbeh.exe:						??? Downloader.W32.Qoologic ???
unins000.exe:						Un-installation Service
unins001.exe:						??? Adware.W32.GoGoTools ???
uninsc.exe:						??? Adware.W32.GoGoTools ???
uninst.exe:						Un-installation Executable
uninstall.exe:						Various
uninstdsk.exe:						??? Trojan.W32.Alemod ???
UnivAgent.exe:						Computer Associates BrightStor Universal Agent
UnlockerAssistant.exe:						Unlocker Assistant
UnlockerAssistant.exe:						Unlocker Assistant
unpacked-svc.exe:						??? Spyware.W32.ClientMan ???
unrar.exe:						WinRar DOS un)Archiver
UNS.exe:						Intel User Notification Service
unsecapp.exe:						Microsoft Windows Management Instrumentation
unstall.exe:						??? Adware.W32.roings ???
unupdate.exe:						Lotus Domino
unvet32.exe:						!!! CA Internet Security Suite 2007 !!!
unwise.exe:						Wise Un-installer
uopcjly.exe:						??? Adware.W32.ZToolbar ???
Up2date.exe:						!!! Kaspersky Administration Kit !!!
upd.exe:						Uninstall####
upd2.exe:						??? Adware.W32.CASClient ???
updagent.exe:						InfoTech Service Update Agent
update.exe:						*** DMW ***
update_task.exe:						!!! FortiClient Host Security 3.0.459 !!!
updater.exe:						??? AGOBOT-OT Worm Virus Trojan ???
updaterui.exe:						!!! McAfee VirusScan Enterprise !!!
UpdaterUI.exe:						!!! McAfee VirusScan Enterprise !!!
updatestats.exe:						Updatestats
UpdateSystemMIB.exe:						Solarwinds tool
updatexp.exe:						??? W32.Dabora.A\@mm Worms ???
updinst.exe:						??? Adware.W32.Look2Me ???
updmgr.exe:						??? eUniverse.com Spyware ???
updreg.exe:						Creative Register Reminder
updsvc.exe:						Network Associates GroupShield On-Line Update
updtnv28.exe:						!!! Symantec !!!
updtscheduler.exe:						??? Trojan.W32.Kedebe ???
upeksvr.exe:						Upek Thinkvantage Fingerprint Software or Protector Suite QL
upfile.exe:						!!! Rising Antispyware !!!
upgrade.exe:						Upgrade Executable
upgrade1.exe:						??? Adware.W32.RapidBlaster ???
upgrade2.exe:						??? Adware.W32.RapidBlaster ???
upgrade3.exe:						??? Adware.W32.RapidBlaster ???
uphclean.exe:						User Profile Hive Cleanup Service
uplive.exe:						!!! Kingsoft !!!
UploadRecord.exe:						USB thumb drive security
upnpframework.exe:						VAIO Media Video Server
uppicsvr.exe:						??? Adware.W32.DelFin ???
upromise0.exe:						Upromise College Savings
ups.exe:						Uninterruptible
UPS.EXE:						UPS
UPSCHD.exe:						!!! Omniquad Total Security 3.0.0 !!!
upsd.exe:						UPSentry Smart
uptmagnt.exe:						Uptime Software Up.Time Agent
uptodate.exe:						Uptodate
uptodater.exe:						??? Adware.W32.DelFin ???
urhtkgcz.exe:						Hotbar - adware
urllstck.exe:						!!! Symantec !!!
UrlLstCk.exe:						!!! Symantec !!!
urlmap.exe:						Urlmap
usb.exe:						Usb
USBGuard.exe:						USB Disk Security
USBKVM.exe:						USB KVB switch
usbmmkbd.exe:						Usbmmkbd
usbmonit.exe:						Gene USB Monitor Component
usbn.exe:						??? Downloader.W32.Small ???
usbnotify.exe:						AuthenTec TrueSuite Access Manager
USBSafelyRemove.exe:						USB Safely Remove
UsbService.exe:						ZTE
usbsircs.exe:						Sony Giga Pocket Remote Commander Driver
USBSRService.exe:						Crystal Rich USB Safely Remove
USBVaccine.exe:						Panda USB Vaccine
UserActivity.exe:						!!! EventTracker Scheduler !!!
UserAnalysis.exe:						!!! EventTracker Console !!!
usergate.exe:						!!! Entensys UserGate 5 !!!
userinit.exe:						UserInit Process
userint32.exe:						??? W32/Oscabot-C Worm Component ???
UserProfile.exe:						Hitachi Starboard Application
UserProfilerService.exe:						Mobilink Billing Software
UServerConfig.exe:						UnrealStreaming ULiveServer
USM.exe:						LanDesk User Space Manager
usnsvc.exe:						Microsoft Messenger Sharing USN Journal Reader Service
usnsvc.exe:						Microsoft Messenger Sharing USN Journal Reader Service
usofrpyqzgrhcumw.exe:						??? Adware.W32.CashSaver ???
usrbridg.exe:						Extended Systems Infrared Virtual COM Port
usrmgr.exe:						User Manager
USRMGR.EXE:						User Manager
usrmlnka.exe:						Usrmlnka
UsrPrmpt.exe:						!!! Symantec !!!
usrprmpt.exe:						!!! Symantec !!!
usrshuta.exe:						US Robotics Helper
usrshutd.exe:						??? Adware.W32.FindSpyware ???
ustorsrv.exe:						OTi Content Service or UStorage Server Service
utility.exe:						Belkin Wireless PCI Card Configuration Utility
utilman.exe:						Utility manager
uTorrent.exe:						uTorrent
UTSCSI.exe:						USBest PQI Card Driver
UTSCSI.EXE:						USBest PQI Card Driver
utwlsnux.exe:						??? 180Solutions Spyware ???
uvu-channel.exe:						??? Trojan.W32.Hachilem ???
uwa.exe:						??? Adware.W32.sqwire ???
uwdf.exe:						Windows User-Mode Driver Framework
uwfx5.exe:						??? Adware.W32.WinFixer ???
uwfx5lp_0001_0802netinstaller.exe:						??? Adware.W32.WinFixer ???
uzqkst.exe:						UltimateZip
V263CodecMP.exe:						ZTE
v2iconsole.exe:						!!! Symantec !!!
v3clnsrv.exe:						!!! AhnLab !!!
v3exec.exe:						!!! AhnLab V3 Internet Security !!!
v3imscn.exe:						!!! AhnLab V3 Internet Security !!!
V3Medic.exe:						!!! AhnLab !!!
V3Svc.exe:						!!! AhnLab !!!
vabctqp.exe:						??? 180Solutions Spyware ???
vaioent.exe:						VAIO Entertainment
vaioupdt.exe:						Sony Vaio Update
valuesup.exe:						Prism XL Helper
vaserv.exe:						VAIO Action Setup
vasileva_iy.exe:						??? Trojan.Win32.Rabbit / Cutwail ???
vb2.exe:						??? Adware.W32.PacerD ???
vbda.exe:						HP OmniBack (Storage Management Server)
vbouncer.exe:						??? Adware.W32.VirtualBouncer ???
vbouncerinner.exe:						??? Adware.W32.PacerD ???
vbouncerouter1402030731.exe:						??? Adware.W32.VirtualBouncer ???
vbstub.exe:						??? Backdoor.W32.Agent ???
vc5play.exe:						Virtual CD - Player
vc5secs.exe:						Virtual CD - Management Service
vc5tray.exe:						Virtual CD - Quick Start Utility
vc6play.exe:						Virtual CD - Player
VC6Play.exe:						Virtual CD Player
vc6secs.exe:						Virtual CD - Management Service
VC6SecS.exe:						Virtual CD - Management Service
vc6tray.exe:						Virtual CD - Quick Start Utility
vc7play.exe:						Virtual CD - Player
VC7Play.exe:						Virtual CD Player
vc7secs.exe:						Virtual CD - Management Service
VC7SecS.exe:						Virtual CD - Management Service
vc7tray.exe:						Virtual CD - Quick Start Utility
vc9secs.exe:						Virtual CD Software
vcagent.exe:						Compaq process
vcclient.exe:						??? Spyware.W32.SurfSidekick ???
vcddaemon.exe:						Elaborate Bytes Virtual CloneDrive
VCDSecS.exe:						Virtual CD v4 Security Service
vcmnet11.exe:						??? AFA Internet Enhancement Spyware ???
vcmpin.exe:						??? Adware.W32.DelFin ???
vcsFPService.exe:						Fingerprint Sensor Software Suite
vcssecs.exe:						Virtual CD Component
vcsw.exe:						Sony VAIO UPnP Client Adapter
vcualts32.exe:						??? Trojan.W32.Bagle ???
VDeck.exe:						VIA VIAudioi VDeck
vds.exe:						Virtual Disk Service
vdtask.exe:						Component of GameDrive or VirtualDrive by Farstone
VeeamBackupService.exe:						Veeam Backup and FastSCP
ventc.exe:						Venturi
VerbAce-Pro.exe:						VerbAce-Pro Arabic-English Dictionary
versioncuecs2.exe:						Adobe Version Cue CS2
vesmgr.exe:						Sony VAIO Event Service
vetmsg.exe:						!!! CA AntiVirus VET Message Service !!!
vettray.exe:						!!! eTrust !!!
vi_grm.exe:						Vi_grm
Vid.exe:						Logitech Desktop Messenger
vidalia.exe:						Vidalia GUI controller for Tor
vidctrl.exe:						??? Adware.W32.DelFin ???
video.exe:						??? Dialer.W32.Downloader ???
VideoAccelerator.exe:						SpeedBit Video Accelerator
VideoAcceleratorService.exe:						SpeedBit Video Accelerator
videodrv.exe:						??? I-Worm.Mimail virus Virus ???
videoinst.exe:						??? 180Solutions Spyware ???
vidmon.exe:						??? Adware.W32.DelFin ???
view.exe:						View
viewmgr.exe:						ViewPoint Media Player
ViewMgr.exe:						ViewPoint Media Player
viewport.exe:						ATI/Appian HydraVision Desktop Manager
virtualbouncer.exe:						??? Virtualbouncer ???
visio.exe:						Microsoft Visio
Visio32.exe:						Microsoft Visio
VistaDrv.exe:						Vista Drive Icon
viu.exe:						??? AdClicker Spyware ???
VivaldiFramework.exe:						RAID Web Console 2 Framework
VKSaver.exe:						VKSaver tray proxy
vlad_dh.exe:						??? Adware.W32.DealHelper.com ???
vm_sti.exe:						BigDogPath
vmacthlp.exe:						VMWare
vmconnect.exe:						Vodafone Mobile Connect
vmlib.exe:						Troj/LowZone-AQ
vmm.exe:						*** FRIENDLY TOOL - Seek Help ***
vmnat.exe:						VMware NAT Service
vmnetdhcp.exe:						VMnet DHCP service
VMNetDHCP.exe:						VMnet DHCP service
vmount2.exe:						VMware virtual disk mount service
vmss.exe:						??? Delfin Media Viewer Adware Spyware ???
vmstmp.exe:						??? Adware.W32.PromulGate ???
vmtoolsd.exe:						VMware Tools
VMUpgradeHelper.exe:						VMWare
vmware-authd.ex:						VMWare Authentication Module
vmware-authd.exe:						VMWare Authentication Module
vmware-converter-a.exe:						VMWare
vmware-converter.exe:						VMWare
vmware-tray.exe:						VMware Tray Process
vmware-usbarbitrator.exe:						VMware
vmware-vmx.exe:						VMware Player
vmware.exe:						VMware
VMwareService.e:						VMware Services
VMwareService.ex:						VMware Services
VMwareService.exe:						VMware Services
VMwareTray.exe:						VMware tools
VMwareUser.exe:						VMware
VncSBMgr.exe:						Vinca Standby Manager
vncviewer.exe:						VNC Viewer
vnsystask.exe:						VNC Module
vobregcheck.exe:						Vobregcheck
VolCtrl.exe:						HP Quick Launch Buttons
voxdvj.exe:						??? Downloader.W32.Small ???
vpatch.exe:						!!! ISS_Proventia_Agent 9.0 from IBM !!!
VPC32.exe:						!!! Symantec !!!
vpc32.exe:						!!! Symantec !!!
VPDN_LU.exe:						!!! Symantec !!!
VPhone.exe:						Paliha VirtualPhone
VPlus.exe:						ICQ Plus
VPNagent.exe:						Cisco AnyConnect VPN Client
vpnagent.exe:						Cisco AnyConnect VPN Client
vpngui.exe:						Cisco VPN Client
vpop3.exe:						VPOP3 Email Server
vprosvc.exe:						!!! Symantec !!!
VPTray.exe:						!!! Symantec System Tray Icon !!!
vptray.exe:						!!! Symantec System Tray Icon !!!
vrv.exe:						!!! VRV Security Software !!!
vrvmail.exe:						!!! VRV Security Software !!!
vrvmon.exe:						!!! VRV Security Software !!!
vrvnet.exe:						!!! VRV Security Software !!!
VSGate.exe:						ELSAwin - Manuals for VW cars
vshwin32.exe:						!!! McAfee On-access scanner !!!
vsmain.exe:						!!! McAfee VirusScan Main Console !!!
vsmon.exe:						!!! ZoneAlarm Component !!!
vsnpstd.exe:						Olidata WebCam Driver
vsnpstd2.exe:						SmartCam USB Camera Process
vsnpstd3.exe:						CameraMonitor Application
vsserv.exe:						!!! BitDefender Security Suite !!!
VsStat.exe:						!!! McAfee VirusScan On-Access Scanner !!!
VSStat.exe:						!!! McAfee VirusScan On-Access Scanner !!!
vsstat.exe:						!!! McAfee VirusScan On-Access Scanner !!!
vssvc.exe:						Microsoft ShadowCopy
vstskmgr.exe:						!!! McAfee VirusScan Task Manager !!!
VsTskMgr.exe:						!!! McAfee VirusScan Task Manager !!!
vtpreset.exe:						Savage Pro S3 Software
VTTimer.exe:						VIA Graphics Card Driver
vttimer.exe:						S3 Screentoys
vttrayp.exe:						S3 Screentoys Helper
vuzgnwz.exe:						180Solutions Zango
vvsn.exe:						WhenU
VVSN.exe:						??? WhenU adware Spyware ???
vvvfdsqq.exe:						??? W32.Sober.\@mm Worm ???
vwipxspnt.exe:						??? Adware.W32.FindSpyware ???
VWNOTIFY.EXE:						Microsoft Office Project Server 2003
VxSvc.exe:						Dell Array Manager / Disk Management Service
vxsvc.exe:						Dell Openmanage Array Manager Service
vxtaskbarmgr.exe:						Backup Exec Taskbar
vzcdbsvc.exe:						VAIO Entertainment
vzfw.exe:						Sony GigaPocket
VzFw.exe:						Sony GigaPocket
vzopenuiserver.exe:						Verizon Online Desktop Application Manager
w.exe:						??? W32.Benpao.Trojan ???
w11150.exe:						??? Adware.W32.WebRebates ???
w181609.stub.exe:						??? Adware.W32.DelFin ???
w32_systm.exe:						??? Backdoor.W32.Banito ???
w32backdoor-axc.trojan.exe:						??? Backdoor.W32.Delf ???
w32backdoor-axg.trojan.exe:						??? Backdoor.W32.Volk ???
w32backdoor-axh.trojan.exe:						??? Backdoor.W32.Delf ???
w32backdoor-bs.trojan.exe:						??? Backdoor.W32.Agent ???
w32backdoor-dvl.exe:						??? Backdoor.W32.Delf ???
w32backdoor-dxn.exe:						??? Backdoor.W32.VB ???
w32backdoor-egl.exe:						??? Backdoor.W32.Delf ???
w32backdoor-egv.exe:						??? Backdoor.W32.Agent ???
w32backdoor-hd.trojan.exe:						??? Backdoor.W32.VB ???
w32backdoor-jz.trojan.exe:						??? Backdoor.W32.VB ???
w32backdoor-nt.exe:						??? Backdoor.W32.VB ???
w32backdoor-ny.exe:						??? Backdoor.W32.Shellfur ???
w32backdoor-yx.exe:						??? Backdoor.W32.VB ???
w32banito-k.trojan.exe:						??? Backdoor.W32.Banito ???
w32banito-p.exe:						??? Backdoor.W32.Banito ???
w32downloader-ggs.exe:						??? Downloader.W32.Delf ???
w32downloader-gns.exe:						??? Downloader.W32.Delf ???
w32downloader-gpq.exe:						??? Downloader.W32.Delf ???
w32haxdoor-ft.exe:						??? Backdoor.W32.Haxdoor ???
w32hupigon-ar.exe:						??? Backdoor.W32.Hupigon ???
w32hupigon-cj.exe:						??? Backdoor.W32.hupigon ???
w32istbar-la.exe:						??? Downloader.W32.IstBar ???
w32lecna-a.exe:						??? Backdoor.W32.Lecna ???
W32mkde.exe:						Pervasive DB Software
W32MKDE.EXE:						Pervasive DB Software
w32time.exe:						??? Trojan.W32.Mdropper ???
w32topl.exe:						*** EXPANDINGPULLY ***
w3dbsmgr.exe:						Database Service Manager
w3prefch.exe:						Microsoft ISA Server Job Scheduler
w3proxy.exe:						Microsoft ISA Web Server 2000 Proxy
w3sqlmgr.exe:						Relational DB SQL Manager
W3SQLMGR.EXE:						Relational DB SQL Manager
W3u.exe:						eplan
w3wp.exe:						IIS Worker Process
w4e7074a.exe:						@@@ Generic.dx!tvr @@@
wab.exe:						Microsoft Address Book
WaHelper.exe:						HP Connection Manager
waitfor.exe:						Microsoft delay/pause for batch files
WakeOnLAN.exe:						Solarwinds tool
wakeup.exe:						WakeUp
WAN-Killer.exe:						Solarwinds tool
wangimg.exe:						Image Viewer
wanmpsvc.exe:						America Online
waol.exe:						America Online UI
WAPAlfaActiveServices.exe:						Alfa Active Services
wapiit.exe:						??? Adware.W32.PurityScan ???
waplites.exe:						WAPLite Service
WAPLIT~2.EXE:						WAPLite Service
war-ftpd.exe:						WAR FTP server
wareout.exe:						??? Adware.W32.WareOut ???
wareoutupdate.exe:						??? Adware.W32.WareOut ???
warez.exe:						Warez P2P Client
Warn.exe:						MSC BAM Services
washer.exe:						Temporary Internet Files Remover
WasherSvc.exe:						WebWasher
wast.exe:						??? Wast Spyware ???
wast2.exe:						??? Adware.W32.Wast ???
Watch-It.exe:						Solarwinds tool
watch.exe:						System Tray utility
watch_free_porn.exe:						??? Adware.W32.AdRoar ???
watchdog.exe:						Watchdog
wauclt.exe:						??? w32.gaobot.ajd Worm ???
wavdriver.exe:						??? Unknown ???
waveedit.exe:						Ahead Nero Wave Editor
WaveEdit.exe:						Ahead Nero Wave Editor
wbjob.exe:						WinBackup 2 Backup Engine
wbload.exe:						WindowsBlinds Stardock
wbmain.exe:						WinBackup 2.0 User Interface
WBridge.exe:						LANDesk Network Management Utility
wbsched.exe:						UniBlue WinBackup Scheduler
wbscheds.exe:						WinBackup 2 Scheduler
wbss.exe:						WinBackup Scheduler Service
wbtray.exe:						WinBackup 2 Traybar
wbutton.exe:						Acer WButton2k) Wireless Button)
wcescomm.exe:						Microsoft ActiveSync Connection Manager
WCESCOMM.EXE:						ActiveSync Connection Manager
wcesmgr.exe:						Microsoft ActiveSync
WCFServiceDBPool.exe:						Windows Communication Foundation
WCFWinService.exe:						Windows Communication Foundation
wCLNT.exe:						Program Savings Bank Client
wcmdmgr.exe:						Automated Support Engine
wcmdmgrl.exe:						Wcmdmgrl
wcourier.exe:						ASUS Wireless Console
wcpri.exe:						??? Adware.W32.WebRebates ???
WCStandard.exe:						WorldClient Standard
WDaemon.exe:						WorldClient Pro?
wdbtnmgr.exe:						WD Button Manager
WDelMgr20.exe:						Final Data Enterprise 2.0 Data Recovery Suite
wdfmgr.exe:						Windows Driver Foundation Manager
WDFMGR.EXE:						Windows Driver Foundation Manager
wdfmrg.exe:						??? W32/Sdbot-ZN Worm ???
wdsvc.exe:						Dantz Retrospect Component
wdtreset.exe:						LANDesk Network Management Utility
weather.exe:						WEATHER
weathereye.exe:						The Weather Network Alerter
web.exe:						??? W32.Gokar.A\@mm Virus Trojan ???
WEB500GW.EXE:						Eudora Web/LDAP/X.500 Gateway
WebAdmin.exe:						Alt-N mail server web administrator
WEBAlfaActiveServices.exe:						Alfa Active Services
webalizer.exe:						Webalizer Weblog scanner
webbullion.exe:						??? Adware.W32.Webbulion ???
webcamrt.exe:						WebcamRT
webcolct.exe:						Webcolct
WebConfig.exe:						WebConfig for MDaemon
webdav.exe:						??? Webdav Trojan ???
webdav.exe:						??? Webdav Trojan ???
webdmi.exe:						Compaq DMI Web Management Service
webinstall.exe:						123 Zip
weblct.exe:						Huawei T2000
WebLCT.exe:						Huawei iManager T2000 Element Management Software
webpmger.exe:						??? Trojan.W32.QQPASS ???
webpmgr.exe:						??? Trojan.W32.QQPASS ???
webproxy.exe:						!!! Panda Internet Security !!!
WEBPROXY.EXE:						!!! Panda Internet Security !!!
WebProxy.exe:						!!! Panda Internet Security !!!
webrebates.exe:						??? WebRebates Spyware ???
webrebates0.exe:						??? Web Rebates Spyware ???
webrebates1.exe:						??? WebRebates Spyware ???
webs.exe:						GoAhead web server?
WebScanX.exe:						!!! McAfee Web and ActiveX Scanner !!!
webscanx.exe:						!!! McAfee Web and ActiveX Scanner !!!
websecurealertsetup.exe:						??? Adware.W32.Claria ???
WebSENSE-API.ex:						WebSENSE Open Server
WebSENSEAdmin-A:						WebSENSE Administration Server
WebsenseControlService.exe:						Websense Web Security / Web Filter
webshots.scr:						Webshots Desktop Image Downloader
WebshotsTray.exe:						Webshots Desktop Tray Application
websvcnt.exe:						InterChange-WebMail-IVoice Service
webtrapnt.exe:						!!! TrendMicro PC-cillin !!!
webvacuum.exe:						SpyAnywhere
welcome.exe:						Welcome
WerCon.exe:						Microsoft Windows Event Reporting
wfcrun32.exe:						Citrix ICA-client Component
wfdmgr.exe:						??? W32/Mytob-C Worm ???
wfica32.exe:						Citrix ICA Client Engine
wfindv32.exe:						Dr. Solomon Antivirus
wfshell.exe:						Citrix VM Server
wfx5.exe:						??? Adware.W32.WinFixer ???
WFXCTL32.EXE:						!!! Symantec !!!
wfxctl32.exe:						!!! Symantec !!!
wfxmod32.exe:						!!! Symantec !!!
WFXMOD32.EXE:						!!! Symantec !!!
WFXSNT40.EXE:						!!! Symantec !!!
wfxsnt40.exe:						!!! Symantec !!!
WFXSVC.EXE:						WinFax Pro
wfxsvc.exe:						WinFax Service
wfxswtch.exe:						WinFax
wgatray.exe:						Windows Genuine Advantage Notiftication
WgaTray.exe:						Windows Genuine Advantage Notification
wgengmon.exe:						WinGate?
WGSAPPGO.EXE:						Worldgroup Main?
WGSERVER.EXE:						Worldgroup Server
wgvpnmon.exe:						WinGate VPN
whagent.exe:						??? Whagent Spyware ???
WhatsUpG.exe:						Whats Up System Monitor
whg14100.exe:						??? 2nd Thought Spyware ???
WhoIsd32.exe:						IMail WHOIS Server
Whoisd32.exe:						IMail WHOIS Server
whoisd32.exe:						IMail WHOIS Server
whsurvey.exe:						??? WebHancer Spyware ???
whSurvey.exe:						??? WebHancer Spyware ???
wid32.exe:						??? W32.Mytob.LD/LZ\@mm Worm ???
wimanager.exe:						??? Trojan.W32.Bagle ???
win-bugsfix.exe:						??? LOVELETTER virus ???
win.exe:						??? Downloader.W32.Gen ???
win052.exe:						??? Keylogger.Trojan ???
win24.exe:						??? Trojan.W32.Kidala ???
win32.exe:						??? RATEGA virus Virus Trojan ???
win32api.exe:						??? win32api Spyware ???
win32debug.exe:						??? W32.Gudeb Trojan ???
win32imapsvr.exe:						??? W32.Mytob.ME\@mm Trojan ???
win32lib.exe:						??? Trojan.W32.Bagle ???
win32sl.exe:						Win32sl
win32us.exe:						??? All-In-One-Telcom ???
win_upd2.exe:						??? Trojan.BAGLE.AC Virus Trojan ???
winace.exe:						WinAce Archiver
WinAce.exe:						WinAce Archiver
winactive.exe:						??? Winactive Spyware ???
winad.exe:						??? Windows AdTools AdWare Spyware ???
winadalt.exe:						??? Windows AdTools AdWare Spyware ???
winadctl.exe:						??? Windows AdTools AdWare Spyware ???
winadm.exe:						??? Windows AdTools AdWare Spyware ???
winadserv.exe:						??? Windows AdTools AdWare Spyware ???
winadslave.exe:						??? Windows AdTools AdWare Spyware ???
winadtools.exe:						Windows AdTools AdWare
WinAdTools.exe:						??? Windows AdTools AdWare Spyware ???
Winamp.exe:						Microsoft WinAmp
winamp.exe:						Nullsoft WinAmp
Winampa.exe:						Microsoft WinAmp Agent
WINAMPA.EXE:						Microsoft WinAmp Agent
winampa.exe:						Winamp mp3 player) Agent
winaw32.exe:						pcAnywhere User Interface
Winaw32.exe:						pcAnywhere User Interface
winbackup.exe:						WinBackup
winbas12.exe:						??? Adware.W32.AdClicker ???
wincfg32.exe:						??? W32/Mytob-AS Worm ???
WinCinemaMgr.exe:						Intervideo WinCinema Manager Component
wincinemamgr.exe:						InterVideo WinCinema Manager
wincmapp.exe:						??? Adware.W32.CASClient ???
Wincmd32.exe:						Windows Commander Shell
WINCMD32.EXE:						Windows Commander Shell
wincomm.exe:						??? w32.agobot.bg Virus Trojan ???
wincomp.exe:						??? WINTRIM.A Trojan Virus Trojan ???
wincomp.exe:						??? WINTRIM.A Trojan ???
winctlad.exe:						??? WindUpdates Adware Spyware ???
winctladalt.exe:						??? WindUpdates Adware ???
WinCtlAdAlt.exe:						??? WindUpdates Adware Spyware ???
wind2ll2.exe:						??? Trojan.W32.Beagle ???
windash.exe:						??? W32.Dinoxi.B Trojan ???
windbg.exe:						+++ Windows Debugger +++
windbg32.exe:						??? W32.Mytob.MC\@mm Trojan ???
winde.exe:						??? DLUCA virus Virus ???
windefault.exe:						??? DNSX VIRUS Virus ???
windio778.exe:						??? W32.Dinoxi Trojan ???
windir32.exe:						??? WORM_RBOT.BRQ ???
windirect.exe:						??? Trojan.BAGLE.AC ???
WINdirect.exe:						??? Trojan.BAGLE.AC Virus Trojan ???
windll2.exe:						??? W32.Beagle.CN\@mm Worm ???
windll32lib.exe:						??? Trojan.W32.Bagle ???
windows.exe:						??? W32.HLLW.Nulut WORM ???
Windows2000-KB971633-x86-ENU.EXE:						Windows2000 KB971633 Patch
windowsautomaticupdates.exe:						Folding\@Home Client
windowsp.exe:						??? Unknown ???
windowssearch.exe:						Windows Desktop Search Tray
windowssearchindexer.exe:						Msn toolbar search facility
windowsupdated32.exe:						??? Trojan.W32.MyTob ???
winds.exe:						??? Trojan.W32.MyTob ???
windspl.exe:						??? Trojan.W32.Bagle ???
winex.exe:						??? Winex Spyware ???
winexec.exe:						??? WORM_FALSU.A Worm ???
winexec32.exe:						??? Rbot Trojan ???
winfixer:						??? WinFixer Adware ???
winfixer2005setup.exe:						??? Adware.W32.WinFixer ???
winfrw.exe:						??? Backdoor.W32.Wisdoor ???
winfs.exe:						Microsoft Windows Future Storage
winfyww.exe:						@@@ Generic Proxy!v @@@
WinGate.exe:						Qbik WinGate Engine
wingate.exe:						??? LOVGATE.G virus Virus ???
WinGateEngine.e:						Qbik WinGate Engine
wingo.exe:						??? W32/Bagle.bd\@MM Virus Virus Trojan ???
winhelp.exe:						Microsoft Help file viewer
winhlp32.exe:						Microsoft Windows Help
winhost.exe:						??? Win32.Lolaweb Hijacker Virus Trojan ???
winhound.exe:						??? Adware.W32.WinHound ???
wininetd.exe:						??? WINET virus Virus Trojan ???
wininfo.exe:						??? W32.Kwbot.C.Worm virus Virus ???
wininit.exe:						Vista background service launcher
wininit32.exe:						??? Dialer.W32.Agent ???
winkey.exe:						WinKey
winldr.exe:						??? W32.Magflag.B Trojan ???
winldra.exe:						??? Backdoor.W32.Dumador ???
winlock.exe:						??? WinCommX Trojan Virus Trojan ???
winlock.exe:						??? WinCommX Trojan ???
winlog.exe:						Salfeld Personal Security Manager
winlogin.exe:						??? RANDEX.E virus Virus Trojan ???
winlogon.exe:						Microsoft Windows Logon Process
winlogonn.exe:						??? RANDEX.FC Worm ???
winmain.exe:						??? Winmain Trojan ???
WinManager.exe:						TV Tuner (Check path in processdeep)
winmedia32.exe:						??? Trojan.W32.YABE ???
winmgm32.exe:						??? LALA.C virus Virus Trojan ???
winmgmt.exe:						Windows Management Service
WinMgmt.exe:						Windows Management
winmine.exe:						Minesweeper
WinMTSrv.exe:						WinMount Server
WinMTSrv.exe:						WinMount Server
winmx.exe:						WinMX Peer-to-peer Sharing
winmysqladmin.exe:						Windows MySQL administration tool
winnet.exe:						??? CommonName Spyware ???
winnook.exe:						??? Antivirus Gold Adware ???
winnt.exe:						??? Downloader.W32.Haxdoor ???
winoa386.mod:						Microsoft MS-DOS Console
winobj.exe:						+++ Windows Object Viewer +++
winoie789.exe:						??? W32.Dinoxi.B Trojan ???
winoldap.exe:						Microsoft MS-Dos Executer
winole.exe:						??? W32/SDBOT WORM Component ???
winpack.exe:						??? Troj/Dloader-JU Trojan ???
Winpack.exe:						??? Troj/Dloader-JU Trojan Virus Trojan ???
Winpack.exe:						??? Troj/Dloader-JU Trojan ???
winpatrol.exe:						WinPatrol
winpopup.exe:						Intranet chat
winppr32.exe:						??? system.W32.Sobig.F ???
winproc.exe:						*** FOGGYBOTTOM ***
winproc32.exe:						??? Adware.W32.DelFin ???
winproj.exe:						Microsoft Project
winproxy.exe:						Winproxy
WinProxy.exe:						WinProxy
winpsd.exe:						??? Win32.MyDoom.S\@mm Virus Trojan ???
winpup32.exe:						??? ADCLICKER virus Virus ???
winrar.exe:						WinRar Archiver
Winrar.exe:						??? WinRar Archiver  Spyware ???
winrarshell32.exe:						??? PWS-Mafia Password Stealer ???
winratchet.exe:						Windows Adtools
WinRatchet.exe:						??? Windows Adtools Spyware ???
winrecon.exe:						??? NoLoad WinRecon Spyware ???
winresw.exe:						??? Trojan.W32.Bagle ???
winroute.exe:						!!! Kerio Winroute Firewall !!!
WinRoute.exe:						!!! Kerio Winroute Firewall !!!
WinRoute.exe:						!!! Kerio Winroute Firewall !!!
winrpc.exe:						??? Trojan.W32.Spybot ???
WINS.EXE:						Windows Internet Name Service
wins.exe:						Microsoft Windows Internet Name Service
winsched.exe:						??? WindUpdates Adware ???
WinSched.exe:						??? WindUpdates Adware Spyware ???
winserv.exe:						??? IMISERV virus Virus ???
winservad.exe:						??? WINSERVAD Adware Spyware ???
winservices.exe:						Dansguardian - open source web content filter
winservn.exe:						??? ClickSpring Spyware ???
winservs.exe:						??? Winservs Spyware ???
winservsuit.exe:						??? WINSERVAD Adware Spyware ???
winsetup.exe:						??? Trojan.W32.Agent ???
winsfc.exe:						??? Trojan.W32.Wisfc ???
winshost.exe:						??? TROJ_BAGLE.BE Trojan ???
WINSMTP.EXE:						Lotus Notes SMTP?
winsocks.exe:						??? winsocks Spyware ???
winspector.exe:						??? Trojan.W32.Muldrop ???
winspool:						Windows Printer Spooler
winsrv32.exe:						??? ADUENT virus Virus Trojan ???
winss.exe:						Windows OneCare Live
winssk32.exe:						??? system.W32.Sobig.E ???
winssnotify.exe:						Windows OneCare Live Notifier
winstall.exe:						??? Adware.W32.SpySheriff ???
winstart.exe:						??? Winstart Spyware ???
winstart001.exe:						??? Winstart001 Spyware ???
winstat.exe:						??? Kodorjan Trojan Component Virus Trojan ???
winstat.exe:						??? Kodorjan Trojan Component ???
winstatkeep.exe:						??? WinAd Adware Process ???
WinStatKeep.exe:						??? WinAd Adware Process Spyware ???
winstylerthemesvc.exe:						TuneUp Utilities WinStyler
winsupdater.exe:						??? W32.Ahlem.A\@mm worm ???
winsvc.exe:						??? W32.Mytob.KR\@mm Worm ???
winsvc32.exe:						??? Trojan.W32.MyTob ???
winsvr.exe:						??? Unclassified Trojan ???
winsync.exe:						Truetime WinSync
WinSync.exe:						Truetime WinSync
winsys.exe:						??? Winsys Spyware ???
winsys16.exe:						??? Trojan IRC Flood ???
winsys32.exe:						??? Trojan IRC Flood ???
wintask.exe:						??? W32.Navidad.16896 Virus Virus Trojan ???
wintaskad.exe:						??? WindUpdate Adware Spyware ???
wintasks.exe:						LIUtilities WinTasks
wintbp.exe:						??? Zotob.E Worm Module ???
wintems.exe:						??? Trojan.W32.Beagle ???
wintime.exe:						??? Downloader.Harnig ???
Wintime.exe:						??? Downloader.Harnig ???
wintools.exe:						??? Huntbar Adware Component ???
wintoolsa.exe:						??? Adware.W32.WinTools ???
wintsk32.exe:						??? YAHA.U virus Virus ???
wintsvtr.exe:						??? Adware.W32.PurityScan ???
winupdate.exe:						??? RADO virus Virus ???
winupdates.exe:						??? Rbot Worm ???
winupdt.exe:						??? RBOT-FP Worm Virus Trojan ???
winupdtl.exe:						??? SecondThought Adware Spyware ???
winvnc.exe:						VNC-Server
WinVNC.exe:						VNC Server
winvnc4.exe:						RealVNC Server
WinVNC4.exe:						RealVNC Server
WinVNC4.exe:						RealVNC 4
winwan.exe:						??? RapidBlaster parasite ???
winword.exe:						Microsoft Word
winxnet.exe:						??? Trojan.W32.MyTob ???
winxp.exe:						??? W32.Beagle.AG@mm ???
winzip.exe:						??? Trojan.W32.Nyxem ???
WINZIP32.EXE:						WinZip compression program
winzip32.exe:						WinZip Archiver
winzip_tmp.exe:						??? Trojan.W32.Nyxem ???
wircsrv.exe:						IRC Server
wireshark.exe:						+++ Wireshark +++
wiseupdt.exe:						??? Grokster Wiseupdt Spyware ???
WISPTIS.EXE:						Windows Ink Services Platform Tablet Input Subsystem
wisptis.exe:						Windows Ink Services Platform Tablet Input Subsystem
wjview.exe:						Wjview
WKBNAS~1.SCR:						NASA ScreenSaver
wkcalrem.exe:						Microsoft Works Calendar Reminder
wkdetect.exe:						Wkdetect
wkfud.exe:						Microsoft Works Marketting Feature
wkqkpick.exe:						WinZip traybar icon
wkscal.exe:						Microsoft Work Suite Calender
wkssb.exe:						Microsoft Works Portfolio tool
wkssvc.exe:						??? W32.Spybot.YXX Root ???
wkssvc32.exe:						SDBot variant
wkufind.exe:						Microsoft Picture-It
wlan111t.exe:						NetGear Wireless Assistant
wlancfg5.exe:						Netgear Smart Configuration Module
wlanext.exe:						Windows Wireless LAN Framework
wlansta.exe:						WLAN Status Tray Applet
wlanutility.exe:						MicroStar WLANUtility
wlballoon:						Common DLL to receive Winlogon notifications
wlcollector.exe:						WatchGuard Mobile VPN
wlcomm.exe:						Windows Live Communications
wlcrasvc.exe:						Microsoft Windows Live Mesh
wlgjiz.exe:						??? 180SearchAssistant Spyware ???
WLIDSVC.exe:						Windows Live ID Service
WLIDSVCM.exe:						Windows Live ID Service
wlkeeper.exe:						Intel Wireless Lan
wlloginproxy.exe:						Microsoft Windows Live Logon Helper
WLLoginProxy.exe:						Microsoft Windows Live Login Helper
wlservice.exe:						BELKIN USB Wireless Monitor
WLSync.exe:						Microsoft Windows Live Mesh
wltray.exe:						Dell Wireless WLAN Card Wireless Network Tray Applet
wltrysvc.exe:						Broadcom Corporation Wireless Network Tray Applet
wltuser.exe:						Windows Live Toolbar
wm.exe:						Novell Workstation Manager
wmagent.exe:						WebMoney Agent
wmburn.exe:						Microsoft Windows Media Player CD Burning
wmccds.exe:						Windows Media Connect
wmdc.exe:						Windows Mobile
wmdSync.exe:						Windows Mobile
wmedia16.exe:						??? Trojan.W32.MYDOOM ???
wmencagt.exe:						Windows Media Encoder Agent
wmexe.exe:						3Com Communications
wmiadap.exe:						AutoDiscovery/AutoPurge ADAP) Service
WMIADAP.EXE:						AutoDiscovery/AutoPurge ADAP) Service
wmiadapt.exe:						??? Backdoor.W32.Nithsys ???
wmiapsrv.exe:						Microsoft WMI Performance Adapter
wmicimsv.exe:						IBM Systems Director
wmicpa.exe:						IBM Systems Director
wmiexe.exe:						Microsofts Windows Management Instrumentation WMI).
wmippa.exe:						IBM Systems Director
wmiprvse.exe:						Microsoft Windows Management Instrumentation
WmiPrvSE.exe:						Microsoft Windows Management Instrumentation
wmipvse.exe:						Windows Server Service
WMIServer.exe:						HP wbem-to-wmi converter
wmon32.exe:						??? W32.Agobot-IT Virus Trojan ???
WMonAvNScan.exe:						+++ GFI Web Monitor +++
WMonAvScan.exe:						+++ GFI Web Monitor +++
wmonitor.exe:						EarthLink TotalAccess
WMonSrv.exe:						+++ GFI Web Monitor +++
wmpburn.exe:						Nero Fast CD-Burning Plugin
WMPBurn.exe:						Nero Fast CD-Burning Plugin
wmplayer.exe:						Microsoft Windows Media Player
wmpnetwk.exe:						Windows Media Player Network Sharing Service
wmpnscfg.exe:						Windows Media Player Network Sharing Configuration
Wmserver.exe:						Windows Media Services
wnad.exe:						??? WinAd Client Spyware ???
wnrot.exe:						??? Trojan.W32.BAGLE ???
wnscpsvunpacked.exe:						??? Adware.W32.PurityScan ???
wntsf.exe:						??? Rbot variant Trojan Virus Trojan ???
wntsf.exe:						??? Rbot variant Trojan ???
wo.exe:						??? Web Offer Spyware ???
wocount.exe:						??? Adware.W32.WareOut ???
woinstall.exe:						??? Adware.W32.Ezula ???
woinstall[1].exe:						??? Adware.W32.Ezula ???
word.exe:						??? VB-IW Trojan Module ???
wordpad.exe:						Microsoft Wordpad
WORDVIEW.EXE:						Word Viewer
Workbench.exe:						SC GUI
workflow.exe:						Workflow
workflowtray.exe:						OmniPage Assistant
WorldClient.exe:						WorldClient
worldoftanks.exe:						Gms World of Tanks (Game)
wovax.exe:						??? Win32.Daqa.A ???
wow.exe:						World of Warcraft process
wowexec.exe:						Microsoft Windows On Windows Execution Process
WP CmdFile Service.exe:						WINPAK2
WP GuardTour Service.exe:						WINPAK2
WP Muster Service.exe:						WINPAK2
WP Schedule Service.exe:						WINPAK2
wp.exe:						??? FlashTrack Adware ???
wpa.exe:						??? Esbot Worm Module ???
wpaagt.exe:						SNMP EMANATE Adapter
wpabaln.exe:						Microsoft Licensing Agent
wpc11cfg.exe:						Linksys Wireless USB Wireless Network Monitor
wpc54cfg.exe:						Linksys Wireless USB Wireless Network Monitor
wpctrl.exe:						PivotPro WinPortrait
wpctrl95.exe:						PivotPro WinPortrait
wpctrlnt.exe:						PivotPro WinPortrait
wpd.exe:						??? Trojan.W32.Randsom ???
WPFFontCache_v0400.exe:						Microsoft.NET Framework
wptel.exe:						WinPhone x.xx Telephony Library
wr4.exe:						Weather Reader
wr4int.exe:						Weather Reader 4
wrapper.exe:						Maya PLE Help Server
wrapperouter.exe:						??? Adware.W32.VirtualBouncer ???
wrctrl.exe:						!!! Kerio Winroute Firewall !!!
wrgrci.exe:						??? Adware.W32.WebRebates ???
wros.exe:						WinRouter Operating System
wrshdnt.exe:						Remote Shell Daemon
WrSpySetup.exe:						!!! Super WinSpy !!!
wrssdk.exe:						Webroot Spysweeper
wrsssdk.exe:						Webroot Spy Sweeper
WRSSSDK.exe:						Webroot Spysweeper
WrtMon.exe:						Presto PageManager
WrtProc.exe:						Presto PageManager
ws3lib.exe:						??? W32.Secefa.A Trojan ???
wsadv.exe:						Switch Commander Application
WScheduler.exe:						Windows Scheduler
wscntfy.exe:						Microsoft Windows Security Center
wscommcntr1.exe:						Autodesk Communication Center
wscript.exe:						Microsoft Windows Script Host
wsebate2.exe:						2nd Thought spyware
WSFTPWebService:						Ipswitch WS FTP Web Service
WSFTPWebService.exe:						Ipswitch WS FTP Web Service
wshom.ocx:						Windows Script Host Runtime Library
wsinspector.exe:						Windows Startup Inspector
wsn.exe:						WhenU
wspsrv.exe:						WinSock Proxy Service
WSPSRV.EXE:						WinSock Proxy Service
WSSADMIN.EXE:						Microsoft Office SharePoint administration
wssfcmai.exe:						!!! LanAgent Monitoring !!!
wsstracing.exe:						Microsoft Office SharePoint Server tracing
wsup.exe:						??? Ibis Toolbar Spyware ???
wsupdate.exe:						??? Backdoor.W32.RAdmin ???
wsusservice.exe:						Windows System Update Service
wsxsvc.exe:						??? Delfin Media Viewer Adware Spyware ???
wsys.exe:						??? STARR PC and Internet Monitor ???
wt35w0g1.exe:						??? Adtomi Spyware ???
wtftp.exe:						Windows Terminal Ware (WTware)
wtools.exe:						??? WinTools Spyware ???
wtoolsa 1.0.8.11.exe:						??? Adware.W32.WinTools ???
wtoolsa.exe:						??? Adware.W32.WinTools ???
WToolsA.exe:						??? IBIS Toolbar hijacker Spyware ???
wtoolsa1.exe:						??? Adware.W32.WinTools ???
wtoolsaa.exe:						IBIS Toolbar hijacker
wtoolss.exe:						??? Adware.Huntbar Spyware ???
wtsdfi.exe:						??? Adware.W32.DelFin ???
wtsrv.exe:						Tablet Service Driver
wtssvtr.exe:						??? Adware.W32.PurityScan ???
wtta.exe:						??? PurityScan/Clickspring Adware ???
wtusbip.exe:						Windows Terminal Ware (WTware)
wtwizard.exe:						Windows Terminal Ware (WTware)
wuaclt.exe:						Microsoft Windows XP AutoUpdater
wuactl2.exe:						??? Downloader.W32.Agent ???
wuamgrd.exe:						??? WORM_AGOBOT.GY Virus Trojan ???
wuamkop.exe:						??? WORM_AGOBOT Variant ???
wuauboot.exe:						Post Boot Auto-Updater for WindowsME
wuauclt.exe:						Microsoft Windows Update
wuauclt2.exe:						??? Proxy-Agent.e Trojan  module ???
wuaudt.exe:						AutoUpdate for WindowsME
wucrtupd.exe:						Windows Update Critical Update Notification
WUDFHost.exe:						Windows Driver Foundation
wudpcom.exe:						??? W32.Mocbot.A Trojan ???
wuloader.exe:						Windows Update Critical Update loader
wupdate.exe:						??? Wengs adware Spyware ???
wupdated.exe:						??? W32/Spybot-W virus Virus ???
wupdater.exe:						??? TrojanDownloader.Win32.Keenval Virus Trojan ???
wupdates.exe:						??? Trojan.W32.Swepdat ???
wupdmgr.exe:						??? WORM_SPYBOT.B Virus Trojan ???
wupdt.exe:						??? IMISERV virus Virus Trojan ???
wups.exe:						??? Adware.W32.PurityScan ???
wusb54gp.exe:						Linksys Wireless-G USB Wireless Network Monitor
wusb54gs.exe:						Linksys Wireless-G USB Wireless Network Monitor
wusb54gv4.exe:						Linksys Wireless-G USB Wireless Network Monitor
wuser32.exe:						Novell Wuser32
Wuser32.exe:						SMS Remote Control Agent
wusyncsvc.exe:						Windows Update Synchronization Service
WVSScheduler.exe:						Acunetix Web Vulnerability Scanner
ww.exe:						WeatherWatcher
wwdisp.exe:						Webroot Window Washer
wwDisp.exe:						Webroot Window Washer
wweb32.exe:						WordWeb thesaurus/dictionary
wwmon.exe:						WildWire Tiger Modem Helper
wwsecure.exe:						Webroot Window Washer
wzcbdls.exe:						WZCBDLService Launcher
wzcsldr.exe:						WLAN Service Launcher
wzcsldr2.exe:						ANIWZCS2 Launcher for Windows
WZQKPICK.EXE:						WinZip process
wzqkpick.exe:						WinZip System Tray Application
x10nets.exe:						X10 Video Streaming Module
x1exec.exe:						NetZero Internet Accelerator
x234cpiroff.exe:						??? Backdoor.W32.IROffer ???
xcomd.exe:						CA-XCOM Data Transport
xcommsvr.exe:						!!! BitDefender Security Suite !!!
xcopy.exe:						Improved built in DOS copy utility
xctbn.exe:						??? Adware.W32.BargainBuddy ???
xdcla.exe:						Doc Management
XDICT.exe:						Chinese English Xlater
XDMISRV.EXE:						DEC Client Works
xferwan.exe:						Centennial Discovery
xfilter.exe:						!!! Omniquad Total Security 3.0.0 !!!
xfr.exe:						Intel File Transfer
XFR.EXE:						Intel File Transfer
xfullgames.exe:						??? Downloader.W32.PlayGames ???
xhrmy.exe:						??? Xhrmy.exe Adware ???
Xhrmy.exe:						??? Xhrmy.exe Adware ???
xisrv32.exe:						SUPERMICRO Supero Doctor III Client
xl.exe:						License manager
xlight.exe:						Xlight FTP Server
xmailer.exe:						123 hidden sender
xplorer2_UC.exe:						Windows Explorer Replacement
XSman.exe:						MSC BAM Services
xtagent.exe:						NetIdentity Service
xtcfgloader.exe:						??? xtcfgloader.exe Spyware ???
XTE.exe:						Citrix VM Server
xtop.exe:						CAD Pro Engineer
xupiterstartup.exe:						??? Adware.W32.sqwire ???
xupitertoolbarloader.exe:						??? Adware.W32.sqwire ???
xvid-1.0.3-beta3-setup.exe:						??? Backdoor.W32.bifrose ???
xwrm.exe:						??? Trojan.W32.Luder ???
xxx.exe:						??? Downloader.W32.Delf ???
xzciqim.exe:						??? Adware.W32.PacerD ???
xzz.exe:						??? Downloader.W32.Small ???
y!multi messenger.exe:						Y! Multi Messenger
y.exe:						??? w32.small Virus Virus ???
yaemu.exe:						??? Trojan.W32.Flush ???
YahooAUService.exe:						Yahoo Software Update
yahoodesktopsearch.exe:						Yahoo! Desktop Search
yahoomessenger.exe:						Yahoo! Messenger
YahooMessenger.exe:						Yahoo! Messenger
YAHOOM~1.EXE:						Yahoo! Messenger
yahoopal.exe:						Pal for Yahoo! messenger
yahoopops.exe:						Yahoo Mail
yahoowidgetengine.exe:						Yahoo! Widget Engine
yassistse.exe:						Chinese Yahoo AssistSetting
yats32.exe:						YATS32
ybrlenc.exe:						??? Dialer.W32.Downloader ???
ybrowser.exe:						Yahoo! Browser
ybrwicon.exe:						BT Yahoo Browser
ycommon.exe:						Yahoo Common EXE Module
ylive.exe:						Chinese Yahoo instant messenger
ymetray.exe:						Yahoo! Music Traybar
ymsgr_tray.exe:						Yahoo! Messenger Server Traybar
Ymsgr_tray.exe:						Yahoo! Messenger Server Traybar
yop.exe:						SBC Yahoo! Online Protection
ypager.exe:						Yahoo Messenger
YPager.exe:						Yahoo Messenger
ysbagree.exe:						??? W32.Yimper ???
ysbinstall_1004267_1.exe:						??? Adware.W32.AdClicker ???
yserver.exe:						Yahoo! Messenger Server Service
YServer.exe:						Yahoo! Messenger Server Service
ystckao32.exe:						??? Adtomi Spyware ???
ytbb.exe:						??? Yahoo Toolbar or IRC/Backdoor.SdBot.SRB) ???
yum.exe:						Yahoo! Update Manager
yupdate.exe:						Yandex Update
yupdater.exe:						Yahoo! Messenger Updater
Zanda.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
zanda.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
Zanda.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
zango.exe:						??? 180Solutions Zango Spyware ???
zangoinstaller.exe:						180Solutions Zango
zangotbinstaller.exe:						180Solutions Zango
zangotbuninstaller.exe:						180Solutions Zango
zanu.exe:						??? 180Solutions Spyware ???
zapro.exe:						!!! ZoneAlarm IDS !!!
zbase32.exe:						ZBase Database Engine
zcast.exe:						NetZero Internet Accellerator Service
zcbridge.exe:						??? Adware.W32.MediaAccess ???
zcfgsvc.exe:						Intel NIC Configuration Tool
zclientm.exe:						Microsoft Zone Client Software
zClientm.exe:						Microsoft Zone Client Software
zcz.exe:						??? 180SearchAssistant Spyware ???
zeta.exe:						??? Adware.W32.BargainBuddy ???
zhopaizdupla.exe:						??? Trojan.W32.Galapoper ???
zhotkey.exe:						Chicony Keyboard Utility
ZhuDongFangYu.exe:						!!! 360_Safe !!!
zhudongfangyu.exe:						!!! 360_Safe !!!
ziptoa.exe:						Iomega ATAPI Zip to A
zlclient.exe:						!!! ZoneAlarm !!!
zlh.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
ZLH.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
Zlh.exe:						!!! Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1
Zmud.exe:						ZMUD game
zonealarm.exe:						!!! ZoneAlarm IDS !!!
zoominghook.exe:						Zooming Utility Hotkey Hook
zstatus.exe:						Hewlett-Packard LaserJet Component
ZStatus.exe:						Hewlett-Packard LaserJet Component
ZuttoMatte.exe:						Hitachi Starboard Application
zxinst12.exe:						??? Adware.W32.ZenoSearch ???
~565.exe:						??? Backdoor.W32.bifrose ???
~5c.exe:						??? Backdoor.W32.Rbot ???
~5e.exe:						??? Adware.w32.Downloader ???
".split("`r`n")

    $store = @()

    

    foreach ($process in $processlist){
        $process2 = $process | Out-String -Stream | Select-String -NotMatch "ProcessName" | Select-String -NotMatch "-----------"
        $process3 = '' + $process2
        $process3 = $process3.trim()
        $filter = $process3.tolower()
        $filter = $filter + ".exe"
        #Write-Output $process3
        foreach ($proc in $badprocs){
            #$proc.split(":")[1]

            #$proc
            $proc2 = $proc.split(":")[0].replace("\r","").replace("\n","").trim()
            $proc3 = $proc.split(":")[1]
            
            if ($proc3){
                $proc3 = $proc3.replace("`t","")
            }

            #Write-Output "Proc: $proc"
            
            #Write-Output "Filter: $filter"

            if ($proc2.tolower() -like $filter){
                    if ($SecurityOnly){
                        
                        if ($proc3 -like "*!!!*"){
                            $object = New-Object -TypeName PSObject
                            $object | Add-Member -Name "ProcessName" -MemberType NoteProperty -Value $proc2
                            $object | Add-Member -Name "Description" -MemberType NoteProperty -Value $proc3
                            $store += $object
                        }
                    }
                    else {
                        $object = New-Object -TypeName PSObject
                        $object | Add-Member -Name "ProcessName" -MemberType NoteProperty -Value $proc2
                        $object | Add-Member -Name "Description" -MemberType NoteProperty -Value $proc3
                        $store += $object
                    }
                    break
            }
           
        }
    }
    $store | Sort-Object -Property Description | ft
    if ($Path){
    
        $store | Export-Csv $Path -NoTypeInformation

        Write-Output ""
        Write-Output "[*] Data exported to $Path"
    }
    else{
        Write-Output ""
    }

    Write-Output "[*] Module Complete"
} 