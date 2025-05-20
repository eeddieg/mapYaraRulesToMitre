from collections import Counter
from mitreattack.stix20 import MitreAttackData
import analyzeYaraRules as an
import argparse
import json
import os
import pandas as pd
import re
import requests
import shutil
import sys

# Color palette
class Colors:
  reset = '\033[0m'
  blue = "\033[34m"
  blueBold = "\033[1;34m"
  redBold = '\033[1;31m'
  green = '\033[0;32m'
  greenBold = '\033[1;32m'
  yellow = '\033[0;33m'
  yellowBold = '\033[1;33m'
  red = "\033[31m"
  redBold = "\033[1;31m"
  
YaraToMitreMapping = {
    # Lateral Movement
    r"CreateRemoteThread": [("Lateral Movement", "T1055.001", 90)],
    r"Win32_Process::Create.*CreateRemoteThread": [("Lateral Movement", "T1071.001", 85)],
    r"usbspread": [("Lateral Movement", "T1091", 85)],
    r"psexec": [("Lateral Movement", "T1021.002", 85)],
    r"wmic": [("Lateral Movement", "T1047", 90)],
    r"RDP.*3389": [("Lateral Movement", "T1021.001", 85)],
    r"NetShareEnum": [("Lateral Movement", "T1021.002", 80)],

    # Defense Evasion
    r"GetProcAddress.*LoadLibrary": [("Defense Evasion", "T1055", 80)],
    r"VirtualAlloc.*WriteProcessMemory": [("Defense Evasion", "T1055.012", 85)],
    r"NtSetInformationThread": [("Defense Evasion", "T1064", 80)],
    r"wevtutil": [("Defense Evasion", "T1070.001", 85)],
    r"certutil": [("Defense Evasion", "T1105", 90)],
    r"svchost.exe": [("Defense Evasion", "T1055", 85)],
    r"AppData\\Roaming": [("Defense Evasion", "T1036.005", 80)],
    r"ProgramData": [("Defense Evasion", "T1036.005", 80)],
    r"shellcode": [("Defense Evasion", "T1055.001", 85)],
    r"reflective DLL": [("Defense Evasion", "T1055.002", 85)],
    r"comsvcs.dll": [("Defense Evasion", "T1218.009", 80)],
    r"runas": [("Defense Evasion", "T1075", 80)],
    r"PowerShell\s+-ExecutionPolicy\s+Bypass": [("Defense Evasion", "T1089", 90)],
    r"eval\(base64_decode": [("Defense Evasion", "T1027", 90)],
    r"gzinflate\(": [("Defense Evasion", "T1027", 85)],
    r"str_rot13": [("Defense Evasion", "T1027", 85)],
    r"DarkEYEV3-": [("Defense Evasion", "T1027", 80)],
    r"unescape\(y\);this\[\'eval\'\]\(w\);": [("Defense Evasion", "T1027", 80)],
    r"RegSetValue.*Image File Execution Options": [("Defense Evasion", "T1546.012", 85)],
    r"bcdedit\s+/set\s+testsigning\s+on": [("Defense Evasion", "T1542.001", 80)],
    r"taskkill\s+/f\s+/im\s+.*\.exe": [("Defense Evasion", "T1562.001", 80)],
    r"vssadmin\s+delete\s+shadows": [("Defense Evasion", "T1070.004", 90)],
    r"attrib\s+\+s\s+\+h\s+.*": [("Defense Evasion", "T1564.001", 80)],
    r"ntdll\.dll.*ZwUnmapViewOfSection": [("Defense Evasion", "T1055.012", 85)],
    r"reg delete HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run": [("Defense Evasion", "T1112", 80)],

    # Execution
    r"Section\s+\.text": [("Execution", "T1059", 70)],
    r"powershell": [("Execution", "T1059.001", 90)],
    r"cmd\.exe": [("Execution", "T1059.003", 85)],
    r"Invoke-Expression": [("Execution", "T1059.001", 85)],
    r"IEX": [("Execution", "T1059.001", 80)],
    r"explorer.exe": [("Execution", "T1059", 70)],
    r"rundll32.exe": [("Execution", "T1218.011", 85)],
    r"wmic": [("Execution", "T1047", 85)],
    r"msbuild": [("Execution", "T1119", 85)],
    r"vbe": [("Execution", "T1086", 80)],
    r"jscript": [("Execution", "T1086", 85)],
    r"java.*-jar": [("Execution", "T1106", 75)],
    r"AndroidManifest\.xml": [("Execution", "T1406", 75)],
    r"Invoke-Mimikatz": [("Execution", "T1059.001", 90)],
    r"Add-MpPreference\s+-ExclusionPath": [("Execution", "T1059.001", 85)],
    r"cscript\.exe": [("Execution", "T1059.005", 85)],
    r"mshta\.exe": [("Execution", "T1218.005", 85)],
    r"installutil.exe": [("Execution", "T1218.004", 85)],
    r"control\.exe": [("Execution", "T1218.002", 80)],
    r"regsvcs\.exe": [("Execution", "T1218.009", 85)],

    # Command and Control
    r"Invoke-WebRequest": [("Command and Control", "T1071.001", 80)],
    r"powershell\s+iex": [("Command and Control", "T1059.001", 85)],
    r"nc.exe": [("Command and Control", "T1105", 90)],
    r"python\s+http.server": [("Command and Control", "T1071.001", 80)],
    r"telnet": [("Command and Control", "T1071.001", 80)],
    r"msfvenom": [("Command and Control", "T1105", 80)],
    r"ngrok": [("Command and Control", "T1105", 85)],
    r"nginx.exe": [("Command and Control", "T1105", 80)],
    r"pipe": [("Command and Control", "T1573.002", 70)],
    r"RAT": [("Initial Access", "T1071", 80)],
    r"Empire": [("Command and Control", "T1071.001", 90)],
    r"Ammyy Admin": [("Command and Control", "T1071.001", 85)],
    r"gate\.php\?token=": [("Command and Control", "T1102", 85)],
    r"HostId-%Rand%": [("Command and Control", "T1105", 80)],
    r"ping 192\.0\.2\.2": [("Command and Control", "T1105", 80)],
    r"bot_id": [("Command and Control", "T1105", 80)],
    r"getSrvPort": [("Command and Control", "T1105", 75)],
    r"playmarketcheck\.com": [("Command and Control", "T1105", 75)],
    r"abra-k0dabra\.com": [("Command and Control", "T1105", 75)],
    r"\.php\?.*?:[a-zA-Z0-9:]{6,}?&.*?&": [("Command and Control", "T1102", 75)],
    r"https?://.*?\.onion": [("Command and Control", "T1090.003", 90)],
    r"https?://.*?dropboxusercontent.com": [("Command and Control", "T1102", 85)],
    r"https?://pastebin\.com/raw/": [("Command and Control", "T1102", 85)],
    r"user-agent.*Mozilla": [("Command and Control", "T1071.001", 75)],
    r"GET\s+/connect": [("Command and Control", "T1071.001", 80)],
    r"client_id=": [("Command and Control", "T1105", 80)],

    # Credential Access
    r"LogonUI": [("Credential Access", "T1072", 85)],
    r"secretsdump": [("Credential Access", "T1003", 90)],
    r"hashdump": [("Credential Access", "T1003.003", 80)],
    r"mimikatz": [("Credential Access", "T1003.003", 80)],
    r"lsass.exe": [("Credential Access", "T1003.001", 90)],
    r"lsadump": [("Credential Access", "T1003.001", 85)],
    r"kerberos": [("Credential Access", "T1076", 80)],
    r"kerberos.*ASREPRoast": [("Credential Access", "T1203", 85)],
    r"type_password2": [("Credential Access", "T1414", 85)],
    r"Track1": [("Credential Access", "T1555", 85)],
    r"Track2": [("Credential Access", "T1555", 85)],
    r"[0-9]{13,16}": [("Credential Access", "T1555", 80)],
    r"\\d{15,19}=\\d{13,}": [("Credential Access", "T1555", 85)],
    r"security.sav": [("Credential Access", "T1003.001", 80)],
    r"NTDS.dit": [("Credential Access", "T1003.003", 90)],
    r"vaultcmd.exe": [("Credential Access", "T1555.004", 80)],
    r"creddump": [("Credential Access", "T1003", 80)],
    r"CredentialManager": [("Credential Access", "T1555.004", 85)],
    r"token::elevate": [("Credential Access", "T1003.001", 80)],

    # Discovery
    r"dir": [("Discovery", "T1083", 70)],
    r"whoami": [("Discovery", "T1033", 80)],
    r"netstat": [("Discovery", "T1049", 75)],
    r"findstr": [("Discovery", "T1087", 80)],
    r"tasklist": [("Discovery", "T1057", 80)],
    r"systeminfo": [("Discovery", "T1082", 80)],
    r"quser": [("Discovery", "T1033", 70)],
    r"sc\s+query": [("Discovery", "T1007", 75)],
    r"ps": [("Discovery", "T1070.003", 85)],
    r"arp": [("Discovery", "T1085", 70)],
    r"mozsqlite3": [("Discovery", "T1082", 75)],
    r"GetRawInputData": [("Discovery", "T1082", 75)],

    # Privilege Escalation
    r"bypassuac": [("Privilege Escalation", "T1548.002", 80)],
    r"seclogon": [("Privilege Escalation", "T1078.001", 85)],
    r"at": [("Privilege Escalation", "T1072.001", 85)],

    # Persistence
    r"regsvr32": [("Persistence", "T1218.011", 90)],
    r"run\s*\.exe": [("Persistence", "T1547.001", 80)],
    r"SetUp\.exe": [("Persistence", "T1218.010", 80)],
    r"schtasks": [("Persistence", "T1053.005", 85)],
    r"at\s+/create": [("Persistence", "T1053.005", 80)],
    r"winlogon.exe": [("Persistence", "T1547.004", 85)],
    r"autorun.inf": [("Persistence", "T1091", 80)],
    r"persist": [("Persistence", "T1071.001", 80)],
    r"rc2d": [("Persistence", "T1073.002", 80)],
    r"install": [("Persistence", "T1060", 85)],
    r"autostart": [("Persistence", "T1071.001", 75)],
    r"schtasks\s+/create": [("Persistence", "T1053.005", 85)],
    r"winlogon\\shell": [("Persistence", "T1547.004", 85)],
    r"Run\\": [("Persistence", "T1547.001", 80)],
    r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run": [("Persistence", "T1547.001", 85)],
    r"startup folder": [("Persistence", "T1547.001", 80)],
    r"Windows\\CurrentVersion\\RunOnce": [("Persistence", "T1547.001", 80)],

    # Exfiltration
    r"curl": [("Exfiltration", "T1041", 80)],
    r"scp": [("Exfiltration", "T1041", 85)],
    r"wget": [("Exfiltration", "T1041", 80)],
    r"ftp": [("Exfiltration", "T1041", 85)],
    r"webshell": [("Exfiltration", "T1041", 90)],
    r"iexplore": [("Exfiltration", "T1041", 75)],
    r"ftps": [("Exfiltration", "T1041", 75)],

    # Impact
    r"diskpart": [("Impact", "T1490", 80)],
    r"rm\s+-rf": [("Impact", "T1485", 75)],
    r"format\s+C:": [("Impact", "T1485", 85)],
    r"wipe": [("Impact", "T1485", 85)],
    r"clean": [("Impact", "T1485", 70)],
    r"shutdown\s+/f": [("Impact", "T1486", 85)],
    r"poweroff": [("Impact", "T1486", 85)],
    r"scrub": [("Impact", "T1485", 75)],
    r"Erase": [("Impact", "T1485", 70)],
    r"backup": [("Impact", "T1485", 80)],
    r"diskwipe": [("Impact", "T1490", 80)],
    r"vssadmin delete shadows": [("Impact", "T1490", 90)],
    r"bcdedit\s+/deletevalue\s+safeboot": [("Impact", "T1490", 85)],
    r"cipher\s+/w:": [("Impact", "T1486", 80)],
    r"icacls.*\/reset": [("Impact", "T1489", 75)],
    r"takeown\s+/f\s+.*": [("Impact", "T1485", 75)],
    r"net\s+stop\s+\"?Volume Shadow Copy\"?": [("Impact", "T1490", 80)],
}

categoryToMitreMapping = {}

uncategorizedMap =  {
  "HotelAlfa": [
    ["TA1027", "Obfuscation", "T1027", "Obfuscated Files or Information", None, None],
    ["TA1055", "Persistence", "T1055", "Process Injection", None, None],
    ["TA1083", "Discovery", "T1083", "File and Directory Discovery", None, None],
  ],
  "IndiaDelta": [
    ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None],
    ["TA0007", "Discovery", "T1071", "Application Layer Protocol", None, None],
    ["TA1071", "Command and Control", "T1071", "Application Layer Protocol", None, None],
  ],
  "IndiaEcho": [
    ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None],
    ["TA0007", "Discovery", "T1083", "File and Directory Discovery", None, None],
    ["TA1071", "Command and Control", "T1071", "Application Layer Protocol", None, None],
  ],
  "IndiaGolf": [
    ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None],
    ["TA0006", "Credential Access", "T1071", "Application Layer Protocol", None, None],
    ["TA1071", "Command and Control", "T1071", "Application Layer Protocol", None, None],
  ],
  "IndiaHotel": [
    ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None],
    ["TA0007", "Discovery", "T1071", "Application Layer Protocol", None, None],
    ["TA1062", "Execution", "T1059", "Command and Scripting Interpreter", None, None],
  ],
  "IndiaJuliett_1": [
    ["TA0010", "Exfiltration", "T1048", "Exfiltration Over Alternative Protocol", None, None],
    ["TA0006", "Credential Access", "T1555", "Credentials from Password Stores", None, None],
    ["TA0040", "Impact", "T1489", "Service Stop", None, None],
    ["TA0005", "Defense Evasion", "T1070.004", "Indicator Removal on Host: File Deletion", None, None],
  ],
  "LimaCharlie": [
    ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None],
    ["TA0002", "Execution", "T1059", "Command and Scripting Interpreter", None, None],
    ["TA0003", "Persistence", "T1547", "Boot or Logon Autostart Execution", None, None],
  ],
  "PapaAlfa": [
    ["TA0011", "Command and Control", "T1102", "Web Service", None, None],
    ["TA0005", "Defense Evasion", "T1036", "Masquerading", None, None],
    ["TA0006", "Credential Access", "T1557", "Adversary-in-the-Middle", None, None],
  ],
  "RomeoAlfa": [
    ["TA0002", "Execution", "T1053.005", "Scheduled Task/Job: Scheduled Task", None, None],
  ],
  "RomeoDelta": [
    ["TA0001", "Execution", "T1071.001", "Application Layer Protocol: Application Layer Protocol", None, None],
  ],
  "RomeoEcho": [
    ["TA0001", "Execution", "T1071.001", "Application Layer Protocol: Application Layer Protocol", None, None],
  ],
  "RomeoFoxtrot_mod": [
    ["TA0001", "Initial Access", "T1071", "Application Layer Protocol", None, None],
    ["TA0002", "Execution", "T1059", "Command and Scripting Interpreter", None, None],
    ["TA0003", "Persistence", "T1053", "Scheduled Task/Job", None, None],
    ["TA0011", "Command and Control", "T1071.001", "Application Layer Protocol: Web Shell", None, None],
    ["TA0010", "Exfiltration", "T1048", "Exfiltration Over Alternative Protocol", None, None],
    ["TA0005", "Exfiltration", "T1105", "Remote File Copy", None, None],
    ["TA0003", "Persistence", "T1203", "Exploitation for Client Execution", None, None],
  ],
  "RomeoGolf": [
    ["TA1027", "Obfuscation", "T1027", "Obfuscated Files or Information", None, None],
    ["TA1071", "Command and Control", "T1071", "Application Layer Protocol", None, None],
    ["TA1082", "Discovery", "T1082", "System Information Discovery", None, None],
    ["TA1105", "Command and Control", "T1105", "Remote File Copy", None, None]
  ],
  "RomeoHotel": [
    ["TA0001", "Initial Access", "T1071", "Application Layer Protocol", None, None],
    ["TA0002", "Execution", "T1059", "Command and Scripting Interpreter", None, None],
    ["TA0005", "Exfiltration", "T1041", "Exfiltration Over Command and Control Channel", None, None],
    ["TA0003", "Persistence", "T1072", "Standard Application Layer Protocol", None, None],
    ["TA0011", "Command and Control", "T1071.001", "Application Layer Protocol: Web Shell", None, None],
    ["TA0009", "Collection", "T1075", "Data from Local System", None, None],
    ["TA0006", "Credential Dumping", "T1003", "OS Credential Dumping", None, None],
    ["TA0004", "Privilege Escalation", "T1082", "System Information Discovery", None, None],
  ],
  "RomeoJuliettMikeTwo": [
    ["TA0002", "Execution", "T1059", "Command and Scripting Interpreter", None, None],
    ["TA0007", "Discovery", "T1083", "File and Directory Discovery", None, None],
    ["TA0009", "Collection", "T1005", "Data from Local System", None, None],
    ["TA0011", "Command and Control", "T1071", "Application Layer Protocol", None, None],
    ["TA0003", "Persistence", "T1072", "Standard Application Layer Protocol", None, None],
    ["TA0006", "Credential Access", "T1081", "Credentials from Password Stores", None, None],
    ["TA0010", "Exfiltration", "T1020", "Automated Exfiltration", None, None],
  ],
  "SierraJuliettMikeOne": [
    ["TA0002", "Execution", "T1059", "Command and Scripting Interpreter", None, None],
    ["TA0007", "Discovery", "T1083", "File and Directory Discovery", None, None],
    ["TA0009", "Collection", "T1005", "Data from Local System", None, None],
    ["TA0011", "Command and Control", "T1071", "Application Layer Protocol", None, None],
    ["TA0003", "Persistence", "T1072", "Standard Application Layer Protocol", None, None],
  ],
  "SuicideScriptL1": [
    ["TA0002", "Execution", "T1059.003", "Command and Scripting Interpreter: Windows Command Shell", None, None],
  ],
  "SuicideScriptR1_Multi": [
    ["TA0002", "Execution", "T1059.003", "Command and Scripting Interpreter: Windows Command Shell", None, None],
  ],
  "SuicideScriptR": [
    ["TA0002", "Execution", "T1059.003", "Command and Scripting Interpreter: Windows Command Shell", None, None],
  ],
  "TangoAlfa": [
    ["TA0002", "Execution", "T1059.003", "Command and Scripting Interpreter: Windows Command Shell", None, None],
    ["TA0011", "Exfiltration", "T1041", "Exfiltration Over Command and Control Channel", None, None],
  ],
  "TangoBravo": [
    ["TA0002", "Execution", "T1059.005", "Command and Scripting Interpreter: JavaScript", None, None],
    ["TA0001", "Execution", "T1071.001", "Application Layer Protocol: Application Layer Protocol", None, None],
  ],
  "UniformAlfa": [
    ["TA0007", "Persistence", "T1543.003", "Registry Run Keys / Startup Folder: Windows Service", None, None],
    ["TA0007", "Persistence", "T1543.001", "Registry Run Keys / Startup Folder: New Service", None, None],
    ["TA0003", "Persistence", "T1071.001", "Application Layer Protocol: Application Layer Protocol", None, None],
  ],
  "UniformJuliett": [
    ["TA0007", "Persistence", "T1543.003", "Registry Run Keys / Startup Folder: Windows Service", None, None],
    ["TA0007", "Persistence", "T1543.001", "Registry Run Keys / Startup Folder: New Service", None, None],
    ["TA0005", "Defense Evasion", "T1089", "Disabling Security Tools", None, None],
    ["TA0003", "Persistence", "T1071.001", "Application Layer Protocol: Application Layer Protocol", None, None],
  ],
  "WhiskeyDelta": [
    ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None],
    ["TA0005", "Defense Evasion", "T1036", "Masquerading", None, None],
    ["TA0007", "Persistence", "T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", None, None],
  ],
}

def createDictionary():

  malware = {
    "malware": [
      ["TA0001", "Initial Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0002", "Execution", "T1059.005", "Command and Scripting Interpreter: Visual Basic", None, None],
      ["TA0002", "Execution", "T1203", "Exploitation for Client Execution", None, None],
      ["TA0002", "Execution", "T1071", "Application Layer Protocol", None, None],
      ["TA0003", "Persistence", "T1071", "Application Layer Protocol", None, None],
      ["TA0004", "Privilege Escalation", "T1068", "Exploitation for Privilege Escalation", None, None],
      ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None],
      ["TA0005", "Defense Evasion", "T1071", "Application Layer Protocol", None, None],
      ["TA0006", "Credential Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0007", "Discovery", "T1071", "Application Layer Protocol", None, None],
      ["TA0011", "Exfiltration", "T1041", "Exfiltration Over Command and Control Channel", None, None],
      ["TA0040", "Impact", "T1486", "Data Encrypted for Impact", None, None],
      ["TA0009", "Collection", "T1114", "Email Collection", None, None]
    ],
    "trojan": [
      ["TA0001", "Initial Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0002", "Execution", "T1059.005", "Command and Scripting Interpreter: Visual Basic", None, None],
      ["TA0002", "Execution", "T1203", "Exploitation for Client Execution", None, None],
      ["TA0002", "Execution", "T1071", "Application Layer Protocol", None, None],
      ["TA0003", "Persistence", "T1071", "Application Layer Protocol", None, None],
      ["TA0004", "Privilege Escalation", "T1068", "Exploitation for Privilege Escalation", None, None],
      ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None],
      ["TA0005", "Defense Evasion", "T1071", "Application Layer Protocol", None, None],
      ["TA0006", "Credential Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0007", "Discovery", "T1071", "Application Layer Protocol", None, None],
      ["TA0011", "Exfiltration", "T1041", "Exfiltration Over Command and Control Channel", None, None],
      ["TA0040", "Impact", "T1486", "Data Encrypted for Impact", None, None],
      ["TA0009", "Collection", "T1114", "Email Collection", None, None]    ],
    "ransomware": [
      ["TA0001", "Initial Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0002", "Execution", "T1059.005", "Command and Scripting Interpreter: Visual Basic", None, None],
      ["TA0002", "Execution", "T1203", "Exploitation for Client Execution", None, None],
      ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None],
      ["TA0006", "Credential Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0007", "Discovery", "T1071", "Application Layer Protocol", None, None],
      ["TA0011", "Exfiltration", "T1041", "Exfiltration Over Command and Control Channel", None, None],
      ["TA0040", "Impact", "T1486", "Data Encrypted for Impact", None, None],
      ["TA0042", "Resource Development", "T1587", "Exploitation for Resource Development", None, None]
    ],
    "virus": [
      ["TA0001", "Initial Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0002", "Execution", "T1059.005", "Command and Scripting Interpreter: Visual Basic", None, None],
      ["TA0002", "Execution", "T1203", "Exploitation for Client Execution", None, None],
      ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None],
      ["TA0006", "Credential Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0007", "Discovery", "T1071", "Application Layer Protocol", None, None],
      ["TA0011", "Exfiltration", "T1041", "Exfiltration Over Command and Control Channel", None, None],
      ["TA0040", "Impact", "T1486", "Data Encrypted for Impact", None, None],
      ["TA0042", "Resource Development", "T1587", "Exploitation for Resource Development", None, None]
    ],
    "worm": [
      ["TA0001", "Initial Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0002", "Execution", "T1059.005", "Command and Scripting Interpreter: Visual Basic", None, None],
      ["TA0002", "Execution", "T1203", "Exploitation for Client Execution", None, None],
      ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None],
      ["TA0006", "Credential Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0007", "Discovery", "T1071", "Application Layer Protocol", None, None],
      ["TA0011", "Exfiltration", "T1041", "Exfiltration Over Command and Control Channel", None, None],
      ["TA0040", "Impact", "T1486", "Data Encrypted for Impact", None, None],
      ["TA0042", "Resource Development", "T1587", "Exploitation for Resource Development", None, None]
    ],
    "infostealer": [
      ["TA0009", "Collection", "T1114", "Email Collection", None, None],
      ["TA0011", "Exfiltration", "T1041", "Exfiltration Over Command and Control Channel", None, None]
    ]
  }

  exploit = {
    "exploit": [
      ["TA0001", "Initial Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None],
      ["TA0040", "Impact", "T1486", "Data Encrypted for Impact", None, None]
    ],
    "vulnerability": [
      ["TA0001", "Initial Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None],
      ["TA0040", "Impact", "T1486", "Data Encrypted for Impact", None, None]
    ],
    "attack": [
      ["TA0001", "Initial Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None],
      ["TA0040", "Impact", "T1486", "Data Encrypted for Impact", None, None]
    ],
    "privilege": [
      ["TA0004", "Privilege Escalation", "T1068", "Exploitation for Privilege Escalation", None, None]
    ],
    "escalation": [
      ["TA0004", "Privilege Escalation", "T1068", "Exploitation for Privilege Escalation", None, None]
    ],
    "cve": [
      ["TA0001", "Initial Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None],
      ["TA0040", "Impact", "T1486", "Data Encrypted for Impact", None, None]
    ]
  }

  network = {
    "network": [
      ["TA0006", "Credential Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0011", "Exfiltration", "T1041", "Exfiltration Over Command and Control Channel", None, None]
    ],
    "traffic": [
      ["TA0006", "Credential Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0011", "Exfiltration", "T1041", "Exfiltration Over Command and Control Channel", None, None]
    ],
    "packet": [
      ["TA0006", "Credential Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0011", "Exfiltration", "T1041", "Exfiltration Over Command and Control Channel", None, None]
    ],
    "dns": [
      ["TA0006", "Credential Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0011", "Exfiltration", "T1041", "Exfiltration Over Command and Control Channel", None, None]
    ],
    "http": [
      ["TA0006", "Credential Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0011", "Exfiltration", "T1041", "Exfiltration Over Command and Control Channel", None, None]
    ],
    "ssl": [
      ["TA0006", "Credential Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0011", "Exfiltration", "T1041", "Exfiltration Over Command and Control Channel", None, None]
    ],
    "c2": [
      ["TA0006", "Credential Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0011", "Exfiltration", "T1041", "Exfiltration Over Command and Control Channel", None, None]
    ],
    "commandAndControl": [
      ["TA0006", "Credential Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0011", "Exfiltration", "T1041", "Exfiltration Over Command and Control Channel", None, None]
    ]
  }

  document = {
    "document": [
      ["TA0001", "Initial Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0001", "Initial Access", "T1566.001", "Phishing: Spearphishing Attachment", None, None],
      ["TA0002", "Execution", "T1059.005", "Command and Scripting Interpreter: Visual Basic", None, None],
      ["TA0002", "Execution", "T1203", "Exploitation for Client Execution", None, None],
      ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None],
      ["TA0040", "Impact", "T1486", "Data Encrypted for Impact", None, None]
    ],
    "pdf": [
      ["TA0001", "Initial Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0001", "Initial Access", "T1566.001", "Phishing: Spearphishing Attachment", None, None],
      ["TA0002", "Execution", "T1203", "Exploitation for Client Execution", None, None],
      ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None]
    ],
    "doc": [
      ["TA0001", "Initial Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0001", "Initial Access", "T1566.001", "Phishing: Spearphishing Attachment", None, None],
      ["TA0002", "Execution", "T1059.005", "Command and Scripting Interpreter: Visual Basic", None, None],
      ["TA0002", "Execution", "T1203", "Exploitation for Client Execution", None, None],
      ["TA0002", "Execution", "T1203", "Exploitation for Client Execution", None, None],
      ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None]
    ],
    "docx": [
      ["TA0001", "Initial Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0001", "Initial Access", "T1566.001", "Phishing: Spearphishing Attachment", None, None],
      ["TA0002", "Execution", "T1059.005", "Command and Scripting Interpreter: Visual Basic", None, None],
      ["TA0002", "Execution", "T1203", "Exploitation for Client Execution", None, None],
      ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None]
    ],
    "office": [
      ["TA0001", "Initial Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0001", "Initial Access", "T1566.001", "Phishing: Spearphishing Attachment", None, None],
      ["TA0002", "Execution", "T1059.005", "Command and Scripting Interpreter: Visual Basic", None, None],
      ["TA0002", "Execution", "T1203", "Exploitation for Client Execution", None, None],
      ["TA0002", "Execution", "T1203", "Exploitation for Client Execution", None, None],
      ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None]
    ],
    "macro": [
      ["TA0001", "Initial Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0001", "Initial Access", "T1566.001", "Phishing: Spearphishing Attachment", None, None],
      ["TA0002", "Execution", "T1059.005", "Command and Scripting Interpreter: Visual Basic", None, None],
      ["TA0002", "Execution", "T1203", "Exploitation for Client Execution", None, None],
      ["TA0002", "Execution", "T1203", "Exploitation for Client Execution", None, None],
      ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None]
    ],
    "xls": [
      ["TA0001", "Initial Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0001", "Initial Access", "T1566.001", "Phishing: Spearphishing Attachment", None, None],
      ["TA0002", "Execution", "T1059.005", "Command and Scripting Interpreter: Visual Basic", None, None],
      ["TA0002", "Execution", "T1203", "Exploitation for Client Execution", None, None],
      ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None]
    ],
    "ppt": [
      ["TA0001", "Initial Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0001", "Initial Access", "T1566.001", "Phishing: Spearphishing Attachment", None, None],
      ["TA0002", "Execution", "T1203", "Exploitation for Client Execution", None, None],
      ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None]
    ]
  }

  packer = {
    "packer": [
      ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None],
      ["TA0007", "Discovery", "T1071", "Application Layer Protocol", None, None],
      ["TA0042", "Resource Development", "T1587", "Exploitation for Resource Development", None, None]
    ],
    "obfuscation": [
      ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None]
    ],
    "cryptor": [
      ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None]
    ],
    "encoded": [
      ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None]
    ],
    "polymorphic": [
      ["TA0005", "Defense Evasion", "T1027", "Obfuscated Files or Information", None, None]
    ]
  }

  crypto = {
    "crypto": [
      ["TA0001", "Initial Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0011", "Exfiltration", "T1041", "Exfiltration Over Command and Control Channel", None, None]
    ],
    "bitcoin": [
      ["TA0001", "Initial Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0011", "Exfiltration", "T1041", "Exfiltration Over Command and Control Channel", None, None]
    ],
    "wallet": [
      ["TA0001", "Initial Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0011", "Exfiltration", "T1041", "Exfiltration Over Command and Control Channel", None, None]
    ],
    "blockchain": [
      ["TA0001", "Initial Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0011", "Exfiltration", "T1041", "Exfiltration Over Command and Control Channel", None, None]
    ],
    "ethereum": [
      ["TA0001", "Initial Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0011", "Exfiltration", "T1041", "Exfiltration Over Command and Control Channel", None, None]
    ],
    "monero": [
      ["TA0001", "Initial Access", "T1071", "Application Layer Protocol", None, None],
      ["TA0011", "Exfiltration", "T1041", "Exfiltration Over Command and Control Channel", None, None]
    ]
  }

  keylogger = {
    "keylogger": [
      ["TA0009", "Collection", "T1116", "Input Capture", None, None]
    ],
    "keystroke": [
      ["TA0009", "Collection", "T1116", "Input Capture", None, None]
    ],
    "credentials": [
      ["TA0009", "Collection", "T1071", "Application Layer Protocol", None, None],
      ["TA0004", "Privilege Escalation", "T1075", "Exploitation of Privilege Escalation", None, None]
    ]
  }

  execution = {
    "binary": ["TA0002", "Execution", "T1204.002", "User Execution: Malicious File"],
    "cmd": ["TA0002", "Execution", "T1059.003", "Command and Scripting Interpreter: Windows Command Shell"],
    "js": ["TA0002", "Execution", "T1059.007", "Command and Scripting Interpreter: JavaScript"],
    "python": ["TA0002", "Execution", "T1059.006", "Command and Scripting Interpreter: Python"],
    "ps": ["TA0002", "Execution", "T1059.001", "Command and Scripting Interpreter: PowerShell"],
    "scheduledTask": ["TA0002", "Execution", "T1053.005", "Scheduled Task/Job: Scheduled Task"],
    "script": ["TA0002", "Execution", "T1059", "Command and Scripting Interpreter"],
  }

  categoryToMitreMapping["crypto"] = crypto
  categoryToMitreMapping["document"] = document
  categoryToMitreMapping["execution"] = execution
  categoryToMitreMapping["exploit"] = exploit
  categoryToMitreMapping["keylogger"] = keylogger
  categoryToMitreMapping["malware"] = malware
  categoryToMitreMapping["network"] = network
  categoryToMitreMapping["packer"] = packer

  return categoryToMitreMapping

def reset():
  dir1 = "checkedRules"
  dir2 = "mappings"
  duplicateFile = "yara.rules.duplicate.txt"

  print(f"Clearing files and folders...")
  
  try:
    if os.path.isfile(duplicateFile):
      os.remove(duplicateFile)
  except:
    print(f"File {Colors.blue}{duplicateFile}{Colors.reset} not found!")


  # try:
  #   if os.path.isdir(dir1):
  #     shutil.rmtree(dir1)
  # except:
  #   print(f"Directory {Colors.blue}{dir1}{Colors.reset} not found!")

  try:
    if os.path.isdir(dir2):
      shutil.rmtree(dir2)  
  except:
    print(f"Directory {Colors.blue}{dir2}{Colors.reset} not found!")

  os.system("clear")

def ensureDirectoryExists(path):
  if not os.path.isdir(path):
    print(f"Error: Directory {Colors.blue}{path}{Colors.reset} not found!")
    sys.exit(1)

def fetchMitreAttackInfo():
  file = "enterprise-attack.json"
  url = f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/enterprise-attack/{file}"
  r = requests.get(url)
  jsonFile = r.json()

  with open(file, "w") as f:
    json.dump(jsonFile, f)

  print(f"\nMITRE: {Colors.blue}{file}{Colors.reset} has been downloaded successfully!\n")

  mitreAttackData = MitreAttackData(file)

  allTactics = mitreAttackData.get_tactics(remove_revoked_deprecated=True)
  allTechniques = mitreAttackData.get_techniques(remove_revoked_deprecated=True)

  print(f"ATT&CK tactics retrieved   : {Colors.redBold}{len(allTactics)}{Colors.reset}")
  print(f"ATT&CK techniques retrieved: {Colors.redBold}{len(allTechniques)}{Colors.reset}\n")

  return allTactics, allTechniques

def mapTacticsWithTechniques(allTactics):
  tacticMap = {}
  for tactic in allTactics:
    tacticId = tactic["external_references"][0]["external_id"]
    name = tactic["name"]
    tacticMap[tacticId] = name.title()
  return tacticMap

def mapTechniquesWithSubtechniques(allTechniques, tacticMap):
  techniqueMap = {}
  for technique in allTechniques:
    techniqueId = technique["external_references"][0]["external_id"]
    name = technique["name"]
    killChainPhases = technique["kill_chain_phases"]
    tactics = [phase["phase_name"] for phase in killChainPhases if phase["kill_chain_name"] == "mitre-attack"]
    tactics = [tactic.title().replace("-", " ") for tactic in tactics]
    tacticsCodes = sorted([code for code, tname in tacticMap.items() if tname in tactics])
    tacticsList = [(code, tacticMap[code]) for code in tacticsCodes]
    if "." in techniqueId:
      techniqueMap[techniqueId] = {
        "techniqueId": techniqueId.split(".")[0],
        "subtechniqueId": techniqueId,
        "name": name,
        "tactics": tacticsList,
        "confidence": 75,
      }
    else:
      techniqueMap[techniqueId] = {
        "techniqueId": techniqueId,
        "subtechniqueId": None,
        "name": name,
        "tactics": tacticsList,
        "confidence": 90,
      }
  return techniqueMap


  return allMatches, unmatchedRules, totalRules, matchedCount, unmatchedCount

def readYaraFilesByCategory(directory):
  yaraByCategory = {}

  for root, _, files in os.walk(directory):
    for file in files:
      filePath = os.path.join(root, file)
      category = os.path.splitext(filePath)[0]

      with open(filePath, "r", encoding="utf-8") as f:
        content = f.read()

        # ruleMatches = re.findall(r"rule\s+.*?\{.*?\}", content, re.DOTALL)
        ruleMatches = re.findall(r"rule\s+.*?\{.*?\}", content, re.DOTALL)
        # ruleMatches = re.findall(r"^\s*(?:private|global)?\s*(?:private|global)?\s*rule\s+([a-zA-Z0-9_]+)", content, re.DOTALL)

        if category not in yaraByCategory:
          yaraByCategory[category] = []

        for rule in ruleMatches:
          yaraByCategory[category].append(rule)

  return yaraByCategory

def mapYaraToMitre(yaraByCategory, yaraToAttack, mitreMapping):
  mappedResults = []
  unmatchedRules = []

  counters = {
    'filesRead': 0,
    'rulesProcessed': 0,
    'rulesMatched': 0,
    'rulesUnmatched': 0,
  }

  for categoryPath, rules in yaraByCategory.items():
    counters['filesRead'] += 1
    # folderCategory = categoryPath.split(os.sep)[-1]  # Extract the folder name
    folderCategory = categoryPath.split(os.sep)[-2]  # Extract the folder name
    # print(f"{Colors.red}{folderCategory}{Colors.reset}")

    for ruleContent in rules:
      counters['rulesProcessed'] += 1
      ttpMatches = []

      # Extract category and matchedKeyword from the rule's meta
      category = ""
      matchedKeyword = ""
      confidenceScore = ""

      ruleCategoryMatch = re.search(r'category\s*=\s*\"([^\"]+)\"', ruleContent, re.DOTALL)
      ruleMatchedKeywordMatch = re.search(r'matchedKeyword\s*=\s*\"([^\"]+)\"', ruleContent, re.DOTALL)
      ruleConfidenceScoreMatch = re.search(r'confidence\s*=\s*\"([^\"]+)\"', ruleContent, re.DOTALL)
      
      if ruleCategoryMatch:
        category = ruleCategoryMatch.group(1)
      if ruleMatchedKeywordMatch:
        matchedKeyword = ruleMatchedKeywordMatch.group(1)
      if ruleConfidenceScoreMatch:
        confidenceScore = ruleConfidenceScoreMatch.group(1)

      # Check if category exists in categoryToMitreMapping
      if category in mitreMapping:
        categoryMapping = mitreMapping[category]
        for keyword, mitreEntries in categoryMapping.items():
          if re.search(matchedKeyword, keyword, re.IGNORECASE):
            for entry in mitreEntries:
              tacticId, tactic, techniqueId, technique, subtechniqueId, subtechnique = entry
              ttpMatches.append({
                "matchSource": "MitreMapping dictionary",
                "category": category,
                "matchedKeyword": matchedKeyword,
                "tacticId": tacticId,
                "tactic": tactic,
                "techniqueId": techniqueId,
                "technique": technique,
                "subtechniqueId": subtechniqueId,
                "subtechnique": subtechnique,
                "confidence": confidenceScore
              })

        counters['rulesMatched'] += 1

      if not ttpMatches:
        counters['rulesUnmatched'] += 1
        unmatchedRules.append(ruleContent)

      mappedResults.append({
        "category": categoryPath,
        "rule": ruleContent,
        # "rule": ruleContent[:300],
        "mappedTTPs": ttpMatches if ttpMatches else None
      })

  return mappedResults, unmatchedRules, counters

def resolveUncategorized(mappedSet, unmappedSet, counters, uncategorizedMap):
  unmatchedRules = []

  # Pattern to match rule name
  rulePattern = re.compile(r'^\s*rule\s+([a-zA-Z0-9_]+)')
  # rulePattern = re.compile(r'^\s*rule\s+([a-zA-Z0-9_]+)\s*\{', re.MULTILINE)

  
  # Convert the uncategorizedMap keys to lowercase
  uncategorizedMapLowercase = {key.lower(): value for key, value in uncategorizedMap.items()}
  
  for rule in unmappedSet:
    rule = "\n".join([line for line in rule.splitlines() if not line.strip().startswith("//")])

    match = rulePattern.match(rule)
    
    if match:
      ttpMatches = []
      ruleName = match.group(1).lower()
      category = ""
      matchedKeyword = ""

      # Extract category from rule's meta
      ruleCategoryMatch = re.search(r'category\s*=\s*\"([^\"]+)\"', rule, re.DOTALL)
      if ruleCategoryMatch:
        # Extract category
        category = ruleCategoryMatch.group(1).split("/")[1]

      # Extract matchedKeyword from rule's meta
      ruleMatchedKeywordMatch = re.search(r'matchedKeyword\s*=\s*\"([^\"]+)\"', rule, re.DOTALL)
      if ruleMatchedKeywordMatch:
        matchedKeyword = ruleMatchedKeywordMatch.group(1)

      # Try to match ruleName against uncategorizedMap (now using lowercase for comparison)
      if ruleName in uncategorizedMapLowercase:
        uncategorizedEntries = uncategorizedMapLowercase[ruleName]
        for entry in uncategorizedEntries:
          tacticId, tactic, techniqueId, technique, subtechniqueId, subtechnique = entry
          ttpMatches.append({
            "matchSource": "uncategorizedMap dictionary",
            "category": category,
            "matchedKeyword": matchedKeyword,
            "tacticId": tacticId,
            "tactic": tactic,
            "techniqueId": techniqueId,
            "technique": technique,
            "subtechniqueId": subtechniqueId,
            "subtechnique": subtechnique,
            "confidence": 50
          })

        # If a match is found, reduce unmatched counter
        counters['rulesUnmatched'] -= 1
        counters['rulesMatched'] += 1
    
        # Add the rule to mappedSet with its TTP matches (if any)
        mappedSet.append({
          "category": category,
          "rule": rule,
          # "rule": rule[:300],
          "mappedTTPs": ttpMatches if ttpMatches else None
        })

    # If no match is found, log it
    if not ttpMatches:
      unmatchedRules.append(rule)

  return mappedSet, unmatchedRules, counters

def main():
  # File paths
  outputCategoryDir = "categorizedRules"
  outputMappingDir = "mappings"
  outputCsv = "yara.rules.to.mitre.mapping.csv"
  outputJson = "yara.rules.to.mitre.mapping.json"
  unmatchedLog = "unmatched.rules.log"
  unmatchedFilesLog = "unmatched.files.log"
  duplicateFile = "yara.rules.duplicate.txt"

  # Set up argument parser
  parser = argparse.ArgumentParser(
    description="Map YARA Rules to MITRE ATT&CK",
    epilog="\nExample: python yaraToMitre.py -D ./rules"
  )

  # Define arguments
  parser.add_argument("-D", "--directory", help="Directory with YARA rule files", required=True)
  parser.add_argument("-o", "--output", help="Output directory for categorized rules", default=f"{outputMappingDir}")

  # Parse arguments
  args = parser.parse_args()

  # Assign arguments to variables
  rulesDir = args.directory
  outputMappingDir = args.output

  # Ensure the input directory exists
  if not os.path.exists(rulesDir):
    print(f"{Colors.red}{rulesDir}{Colors.reset} directory not found!\n")
    exit(1)

  reset()

  os.makedirs(outputMappingDir, exist_ok=True)

  # Categorize YARA rules based on provided dictionary
  if not os.path.exists(outputCategoryDir) or not os.listdir(outputCategoryDir):
    print(f"Processing YARA rules into categories in {outputCategoryDir}")
    an.processYaraRules(rulesDir, outputCategoryDir, duplicateFile)

  outputCsvPath = os.path.join(outputMappingDir, outputCsv)
  outputJsonPath = os.path.join(outputMappingDir, outputJson)
  logPath = os.path.join(outputMappingDir, unmatchedLog)
  unmatchedFilesLogPath = os.path.join(outputMappingDir, unmatchedFilesLog)

  # Fetch MITRE tactics and techniques
  tactics, techniques = fetchMitreAttackInfo()
  tacticMap = mapTacticsWithTechniques(tactics)
  techniqueMap = mapTechniquesWithSubtechniques(techniques, tacticMap)

  # Construct the dictionary
  categoryToMitreMapping = createDictionary()

  # Read rules
  print(f"Reading YARA rules from directory {Colors.blue}{outputCategoryDir}{Colors.reset}...")
  yaraByCategory = readYaraFilesByCategory(outputCategoryDir)

  if not yaraByCategory:
    print(f"No categorized YARA rules found. Please check the input directory.")
    exit(1)

  # Map them to MITRE TTPs and get the counters
  mappedResults, unmatchedRules,counters = mapYaraToMitre(
    yaraByCategory,
    YaraToMitreMapping,
    categoryToMitreMapping 
  )
  
  # Try to resolve unmatched rules
  mappedResults, unmatchedRules,counters = resolveUncategorized(
    mappedResults,
    unmatchedRules,
    counters,
    uncategorizedMap 
  )

  if counters['rulesUnmatched'] == 0:
    print(f"\n{Colors.greenBold}Mapping complete! All rules are mapped successfully!{Colors.reset}\n")
  else:
    print(f"\n{Colors.greenBold}Mapping complete!{Colors.red} There are unmatched rules!{Colors.reset}\n")

  print(f"\n{Colors.blueBold}Summary:{Colors.reset}")
  print(f"Files Read       : {Colors.blue}{counters['filesRead']}{Colors.reset}")
  print(f"Rules Processed  : {Colors.yellow}{counters['rulesProcessed']}{Colors.reset}")
  print(f"Rules Matched    : {Colors.green}{counters['rulesMatched']}{Colors.reset}")
  print(f"Rules Unmatched  : {Colors.red}{counters['rulesUnmatched']}{Colors.reset}\n")

  # # Convert the set of unique results back to a list and create DataFrame
  # uniqueResultsList = [item for item in mappedResults]  # No need to parse JSON again
  # df = pd.DataFrame(uniqueResultsList)

  # if df.empty:
  #     print("No data to write to CSV.")
  # else:
  #     df.to_csv(outputCsvPath, index=False, sep=",", quoting=1, quotechar='"')
  #     print(f"Mapped rules are stored in {Colors.blueBold}{outputCsvPath}{Colors.reset}\n")


  # Save results as JSON
  with open(outputJsonPath, "w") as f:
    json.dump(mappedResults, f, indent=2) 
  print(f"Mapped rules are stored in {Colors.blueBold}{outputJsonPath}{Colors.reset}n")

  # Write unmatched rules to a file
  with open(logPath, "w") as f:
    json.dump(unmatchedRules, f, indent=2)
  print(f"Unmapped rules are stored in {Colors.blueBold}{logPath}{Colors.reset}\n")

if __name__ == "__main__":
    main()