# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/MuhammadAsif6/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md))

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "masif" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-11-28T02:04:02.4207925Z`. These events began at `2025-11-27T23:13:17.2865604Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "masif1"
| where InitiatingProcessAccountName == "masif"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-11-27T23:13:17.2865604Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
<img width="1150" height="666" alt="image" src="https://github.com/user-attachments/assets/80c7fb9a-87da-40ca-ba64-9d2bf12dcf61" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-15.0.2.exe". Based on the logs returned, at `2024-11-08T22:16:47.4484567Z`, an employee on the "masif" device ran the file `tor-browser-windows-x86_64-portable-15.0.2.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "masif1"
| where ProcessCommandLine contains "tor-browser-windows"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1585" height="196" alt="image" src="https://github.com/user-attachments/assets/87039987-1193-4990-9713-d087013edc1d" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "masif" actually opened the TOR browser. There was evidence that they did open it at `2025-11-27T23:55:42.1314655Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "masif1"
| where FileName has_any ("tor-browser.exe", "firefox.exe", "tor.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
<img width="1692" height="884" alt="image" src="https://github.com/user-attachments/assets/2e345f54-4b30-4563-aced-fa729307e714" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "masif1"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName has_any ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150, 443, 80)
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc
```

<img width="1510" height="551" alt="image" src="https://github.com/user-attachments/assets/2182fdf4-2dfd-45cc-b642-581562c844ad" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

---

## 1. File Download – Tor Installer
**Timestamp:** 2025-11-27T23:13:17.2865604Z  
**Event:** The user `masif` downloaded the file `tor-browser-windows-x86_64-portable-15.0.2.exe` into the Downloads folder.  
**Action:** File download detected.  
**File Path:**  
`C:\Users\masif\Downloads\tor-browser-windows-x86_64-portable-15.0.2.exe`

---

## 2. Process Execution – Tor Browser Installation
**Timestamp:** 2025-11-27T23:55:01.5444447Z  
**Event:** The user executed `tor-browser-windows-x86_64-portable-15.0.2.exe` in silent mode, initiating background installation.  
**Action:** Process creation detected.  
**Command:**  
`tor-browser-windows-x86_64-portable-15.0.2.exe /S`  
**File Path:**  
`C:\Users\masif\Downloads\tor-browser-windows-x86_64-portable-15.0.2.exe`

---

## 3. Process Execution – Tor Browser Launch
**Timestamp:** 2025-11-27T23:55:42.1314655Z  
**Event:** The user opened Tor Browser. Additional processes (`firefox.exe`, `tor.exe`) were launched.  
**Action:** Tor Browser–related process creation detected.  
**File Path:**  
`C:\Users\masif\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

---

## 4. Network Connection – Tor Network
**Timestamp:** 2025-11-27T23:57:45.1172813Z  
**Event:** User `masif` established a Tor network connection to `212.227.230.211:9001` using `tor.exe`.  
**Action:** Connection successful.  
**Process:** `tor.exe`  
**File Path:**  
`C:\Users\masif\desktop\tor browser\browser\torbrowser\tor\tor.exe`

---

## 5. Additional Network Connections – Ongoing Tor Activity
**Timestamps & Connections:**
- **2025-11-27T23:57:41.8778121Z** – Connected to `64.65.1.169:443`  
- **2025-11-27T23:56:20.2593178Z** – Local connection to `127.0.0.1:9150`  

**Event:** Additional Tor network connections detected.  
**Action:** Multiple successful connections.

---

## 6. File Creation – Tor Shopping List
**Timestamp:** 2025-11-28T02:04:02.5725551Z  
**Event:** User `employee` created a file named `tor-shopping-list.txt` on the desktop.  
**Action:** File creation detected.  
**File Path:**  
`C:\Users\masif\Desktop\tor-shopping-list.txt`

---
---

## Summary

The user "masif" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `masif` by the user `masif`. The device was isolated, and the user's direct manager was notified.

---
