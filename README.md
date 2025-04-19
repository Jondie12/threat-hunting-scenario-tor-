<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Investigation of Unauthorized Tor Browser Usage on Employee Device

This report documents the investigation process and findings regarding the use of the Tor Browser by the user "Jondie_86" on the device named "jondie-vm." The investigation utilized multiple data sources, including DeviceFileEvents, DeviceProcessEvents, and DeviceNetworkEvents tables, to track file downloads, process executions, and network connections related to Tor Browser activity.
- [Scenario Creation](https://github.com/Jondie12/threat-hunting-scenario-tor-/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

## Step 1: Identification of Tor-Related Files Download and Creation
 
This step confirmed the presence and creation of Tor Browser-related files on the employee's device, indicating the installation and setup of the Tor Browser environment.


- **Action:** Searched the `DeviceFileEvents` table for any files containing the string "tor" on the device "jondie-vm."
- **Findings:**  
  - User "Jondie_86" downloaded a Tor Browser installer named `tor-browser-windows-x86_64-portable-14.5.exe` in the Downloads folder.  
  - Multiple Tor-related files were copied to the desktop, including `tor.exe`, license files, and shortcuts.  
  - A file named `tor-shopping-list.txt` was created on the desktop and in the Documents folder.  
- **Event Start Time:** 2025-04-18T11:00:58.2970376Z  
**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName startswith "tor"
| where DeviceName == "jondie-vm"
| where Timestamp >= datetime(2025-04-18T11:00:58.2970376Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/71402e84-8767-44f8-908c-1805be31122d">

---

## Step 2: Verification of Tor Browser Installation Execution

This step confirmed that the Tor Browser was installed silently by the user, which could imply an intention to conceal the installation process. The unique SHA256 hash allows verification of the installer’s legitimacy.


- **Action:** Queried the `DeviceProcessEvents` table for any process command lines containing the Tor Browser installer filename.  
- **Findings:**  
- At 2025-04-18T11:00:58.2970376Z, user "Jondie_86" executed the Tor Browser installer with the silent install flag `/S`.  
- The installation was performed without user interaction pop-ups and saved in the Downloads folder.  
- The installer file hash (SHA256: `3a678091f74517da5d9accd391107ec3732a5707770a61e22c20c5c17e37d19a`) was recorded for verification.  

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "jondie-vm"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

---

## Step 3: Confirmation of Tor Browser Execution

This step verified that the Tor Browser was actively used by the employee, not just installed. The multiple process instances suggest typical browser activity and Tor network operation.


- **Action:** Searched the `DeviceProcessEvents` table for execution of Tor-related processes such as `tor.exe`, `firefox.exe` (Tor Browser’s Firefox), and `tor-browser.exe`.  
- **Findings:**  
- User "Jondie_86" launched the Tor Browser at 2025-04-18T11:05:56.0783815Z.  
- Multiple instances of Firefox and Tor processes were spawned shortly after.
  
**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "jondie-vm"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

---

## Step 4: Detection of Network Connections via Tor Browser

This step demonstrated that the Tor Browser was used to establish network connections through the Tor network, potentially anonymizing the user's internet activity.


- **Action:** Investigated `DeviceNetworkEvents` for connections initiated by Tor Browser processes using known Tor network ports (9001, 9030, 9050, 9051, 9150).  
- **Findings:**  
- At 2025-04-18T19:06:10 (7:06 PM), the device successfully connected to a Tor hidden service website `https://www.g2nevwtn6te44k.com`.  
- The connection used IP address 116.203.17.238 on port 9001, a port commonly used by Tor for relay traffic.  
- The initiating process was `tor.exe` located in the Tor Browser directory on the desktop.  

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "jondie-vm"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
text
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## Chronological Event Timeline

### 1. File Download - TOR Installer
- **Timestamp:** Apr 18, 2025 7:00:58 PM
- **Event:** The Tor Browser installer `tor-browser-windows-x86_64-portable-14.5.exe` was downloaded.
- **Details:** The file was renamed in the Downloads folder, and its SHA256 hash (3a678091f74517da5d9accd391107ec3732a5707770a61e22c20c5c17e37d19a) was recorded.

### 2. Process Execution - TOR Browser Installation
- **Timestamp:** Apr 18, 2025 7:01:19 PM
- **Event:** The Tor Browser installer was executed with the `/S` flag for silent installation.
- **Details:** The installation occurred without any user prompts or windows.

### 3. Process Execution - TOR Browser Launch
- **Timestamp:** Apr 18, 2025 7:05:59 PM
- **Event:** The Tor Browser was launched, initiating `firefox.exe` and `tor.exe` processes.
- **Details:** This indicates that the user actively started the Tor Browser application.

### 4. Network Connection - TOR Network
- **Timestamp:** Apr 18, 2025 7:06:10 PM
- **Event:** A network connection was established with a Tor hidden service.
- **Details:** The device connected to `https://www.g2nevwtn6te44k.com` using IP address `116.203.17.238` on port `9001`, a standard Tor port. The `tor.exe` process initiated the connection.

### 5. Additional Network Connections - TOR Browser Activity
- **Timestamp:** Apr 18, 2025 7:06:18 PM
- **Event:** Firefox (part of Tor Browser) connected to localhost.
- **Details:** Firefox connected to IP address 127.0.0.1 on port 9150, related to Socks proxy.

### 6. File Creation - TOR Shopping List
- **Timestamp:** Apr 18, 2025 7:15:25 PM
- **Event:** The file `tor-shopping-list.txt` was created in the user's Documents folder.
- **Details:**  A shortcut (`tor-shopping-list.lnk`) was also created in the Recent folder.

---

## Summary

The user "employee" on the "jondie-vm" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `jondie-vm` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
