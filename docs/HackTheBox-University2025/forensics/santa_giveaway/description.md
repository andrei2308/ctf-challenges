
---

# Santa Giveaway

> **Description:** At Wintercrest Workshop, an employee ran a cheerful holiday giveaway helper that left behind a shimmerdust‑thin trail no one noticed at first. That single action set off a quiet compromise beneath the system’s surface. You are provided only with a full memory dump. Reconstruct the incident using volatile artifacts: identify the process that began the chain, uncover the in‑memory traces it left behind, and extract the command line showing how the intruder secured its foothold.

## Initial Analysis

We are provided with a memory snapshot (`.vmem` and `.vmsn`). We start by identifying the system profile using Volatility 3 to ensure we use the correct profiles/symbols.

```bash
vol -f Challenge-Snapshot.vmem windows.info

```

**Output:**

```text
Variable        Value
Kernel Base     0xf8035941e000
DTB             0x1ab000
Is64Bit         True
Layer_name      0 WindowsIntel32e
NtSystemRoot    C:\Windows
NtMajorVersion  10
NtMinorVersion  0
SystemTime      2025-11-22 15:12:38+00:00

```

## 1. Process Identification

To identify the malicious activity, we list the running processes. We are looking for anything suspicious or out of place.

```bash
vol -f Challenge-Snapshot.vmem windows.pslist

```

**Output:**

```text
PID     PPID    ImageFileName   Offset(V)       CreateTime                   
...
6520    2008    rgbux.exe       0xe786d4c2e080  2025-11-22 15:08:01.000000 UTC

```

We identify `rgbux.exe` as the suspicious process. Searching for this executable name online links it to the **Amadey** malware family (likely the intended answer for the "Malware Family" question, noted as *amaley* in the logs).

* **Malicious Process:** `rgbux.exe`
* **PID:** `6520`

## 2. File Artifacts & Launch Location

Next, we determine where the malware was executed from by scanning for file objects in memory containing "download" strings.

```bash
vol -f Challenge-Snapshot.vmem windows.filescan | grep -i "download"

```

**Output Snippet:**

```text
0xe786d38b3780  \Users\user\Downloads\DiscordGiveaway.exe

```

This reveals the original executable name and path.

* **Launch Path:** `\Users\user\Downloads\DiscordGiveaway.exe`

## 3. Network Analysis

We check the network connections associated with the memory dump to find the Command and Control (C2) server.

```bash
vol -f Challenge-Snapshot.vmem windows.netscan

```

Reviewing the output for PID `6520` (rgbux.exe), we find an active connection.

* **C2 Address:** `89.58.51.107:80`

## 4. Initial Compromise Vector

To find the source URL where the user downloaded the malware, we use `strings` on the memory dump and grep for the executable name found earlier (`DiscordGiveaway`) and HTTP protocols.

```bash
strings Challenge-Snapshot.vmem | grep -i "discordgiveaway" | grep -i "http"

```

**Output:**

```text
http://graveyard.htb:8000/DiscordGiveaway.exe

```

* **Download URL:** `http://graveyard.htb:8000/DiscordGiveaway.exe`

### Timestamp Analysis

To determine when the download occurred, we look for HTTP headers or metadata surrounding the URL in the memory dump.

```bash
strings Challenge-Snapshot.vmem | grep -B 20 "graveyard.htb:8000/DiscordGiveaway.exe" | grep -E "15:0[0-9]:[0-9]{2}|2025-11-22"

```

**Output:**

```text
Date: Sat, 22 Nov 2025 15:07:21 GMT

```

* **Download Time:** `2025-11-22 15:07:21`

## 5. Persistence Mechanisms

Finally, we investigate persistence. The malware created a scheduled task. We can explore the Windows Registry hives in memory to find the task details.

```bash
# List tasks in the Schedule Tree
vol -f Challenge-Snapshot.vmem windows.registry.printkey --key "Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"

```

We see a key named `rgbux.exe`. To find its GUID, we query that specific key:

```bash
vol -f Challenge-Snapshot.vmem windows.registry.printkey --key "Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\rgbux.exe"

```

**Output:**

```text
Key: rgbux.exe
Values:
...
Id: {81A3950E-EE73-4DB9-B670-DF3979056B48}

```

* **Scheduled Task GUID:** `{81A3950E-EE73-4DB9-B670-DF3979056B48}`

---

### Summary of Findings

| Question | Answer |
| --- | --- |
| **Download URL** | `http://graveyard.htb:8000/DiscordGiveaway.exe` |
| **Malicious Process (PID)** | `6520` (rgbux.exe) |
| **Launch Path** | `\Users\user\Downloads\DiscordGiveaway.exe` |
| **C2 IP:Port** | `89.58.51.107:80` |
| **Task GUID** | `{81A3950E-EE73-4DB9-B670-DF3979056B48}` |
| **Download Date** | `2025-11-22 15:07:21` |
| **Malware Family** | Amadey |