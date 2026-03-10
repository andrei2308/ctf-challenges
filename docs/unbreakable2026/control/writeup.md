# ES Challenge — Full Writeup

## Summary

This challenge presents a Windows endpoint compromise captured through Sysmon telemetry ingested into Elasticsearch. The attack begins when the user `bob.bobby` downloads a malicious Control Panel applet (`MicrosoftUpdate.cpl`) from an attacker-controlled web server at `10.13.52.111:8888`. Upon double-clicking the file, Windows processes the `.cpl` extension through the chain `explorer.exe → control.exe → rundll32.exe`, which loads the payload and establishes a C2 connection back to the attacker's Kali machine on port 50000. The attacker then migrates into `msedge.exe` for a more stable and stealthy foothold, sets up persistence via a Run registry key, and enumerates local users with `powershell.exe -Command Get-LocalUser`. After discovering credentials (likely in a file on the system), the attacker performs lateral movement to user `steve.stevens` using `RunasCs.exe` with a password reuse attack. From that user's context, the attacker exploits `SeImpersonatePrivilege` via `GodPotato-NET4.exe` to escalate to SYSTEM. Finally, credentials are dumped from LSASS memory using a tool disguised as `C:\Users\Public\explorer.exe` (a mimikatz variant executing `live lsa`).

---

## Environment Setup

The provided `docker-compose.yml` spins up Elasticsearch 9.3.0 and Kibana 9.3.0. After `docker compose up`, the data from `index_new.json` is loaded into Elasticsearch. Kibana becomes available at `http://localhost:5601`, and from there a Data View is created over the `winlogbeat-*` index pattern to begin querying Sysmon events.

---

## Detailed Solve — Question by Question

### Q1. The user downloaded a malicious file with an uncommon extension from an attacker-controlled instance. What is the name of the file?

**Answer:** `MicrosoftUpdate.cpl`

In Kibana Discover, I filtered for Sysmon **FileCreate** events (Event ID 15 — file stream created, which logs the Zone.Identifier alternate data stream written by the browser upon download) combined with the `Downloads` folder:

**Kibana filter:**
```
winlog.event_id: "15" AND message: "*Downloads*"
```

This surfaces a `FileCreateStreamHash` event showing `C:\Users\bob.bobby\Downloads\MicrosoftUpdate.cpl` with a Zone.Identifier ADS — the telltale sign of a browser download. The `.cpl` extension is uncommon and stands out immediately; it is a Control Panel applet, which is essentially a renamed DLL that Windows will execute via `rundll32.exe` when double-clicked.

Additionally, filtering on Edge's quarantine utility subprocess confirms the download timing:

```
winlog.event_id: "1" AND message: "*quarantine*"
```

Two `msedge.exe` processes with `--utility-sub-type=quarantine.mojom.Quarantine` appear at `01:54:39` and `01:54:44`, bracketing the download of `MicrosoftUpdate.cpl`.

---

### Q2. What is the IP and port of the web server the file was downloaded from?

**Answer:** `10.13.52.111:8888`

I looked at DNS query events to identify attacker infrastructure, and cross-referenced with network connection events:

**Kibana filter:**
```
winlog.event_id: "22"
```

This shows DNS query events. However, the download was from a raw IP. Pivoting to the network connections tagged with a C2 rule:

**Kibana filter:**
```
winlog.event_id: "3"
```

Only 3 network connection events exist in the dataset — all connecting to `10.13.52.111` (hostname: `kali`). The C2 connections go to port `50000`, but the initial file download occurred over a separate HTTP listener. Cross-referencing with the Edge browser history and download metadata visible in the `AppCompatFlags` registry event:

**Kibana filter:**
```
winlog.event_id: "13" AND message: "*MicrosoftUpdate.cpl*" AND message: "*AppCompat*"
```

The file was served from `10.13.52.111:8888` (the attacker's HTTP staging server, separate from the C2 port).

---

### Q3. The user double-clicked on the file, but a series of commands were run behind the scenes until the file was finally executed. What is the chain of processes?

**Answer:** `explorer.exe-control.exe-rundll32.exe`

I searched for the process creation events surrounding the initial execution of the `.cpl` file:

**Kibana filter:**
```
winlog.event_id: "1" AND message: "*MicrosoftUpdate.cpl*"
```

This reveals the chain clearly from the `ParentImage` and `Image` fields in each Process Create event:

1. **`explorer.exe`** (PID 9268) — the Windows shell that handles the double-click on the `.cpl` file.
   - Spawns `control.exe` with command line: `"C:\WINDOWS\System32\control.exe" "C:\Users\bob.bobby\Downloads\MicrosoftUpdate.cpl"`

2. **`control.exe`** (PID 12360) — the Control Panel host process that processes `.cpl` files.
   - Spawns `rundll32.exe` with command line: `"C:\WINDOWS\system32\rundll32.exe" Shell32.dll,Control_RunDLL "C:\Users\bob.bobby\Downloads\MicrosoftUpdate.cpl"`

3. **`rundll32.exe`** (PID 9696) — actually loads and executes the malicious `.cpl` DLL payload.

The chain is: **`explorer.exe → control.exe → rundll32.exe`**

This is the standard Windows mechanism for handling `.cpl` files — `explorer.exe` delegates to `control.exe`, which in turn calls `rundll32.exe` with `Shell32.dll,Control_RunDLL` to load the Control Panel applet.

---

### Q4. The attacker migrated to another process to maintain a stable connection. What is the name of the process that was injected into?

**Answer:** `msedge.exe`

After the initial beacon via `rundll32.exe` (PID 9696), the attacker needs a more stable, long-lived process. I identified the migration target by examining which process became the parent of all subsequent post-exploitation commands:

**Kibana filter:**
```
winlog.event_id: "1" AND message: "*cmd.exe*" AND message: "*msedge.exe*"
```

Multiple `cmd.exe` processes are spawned with `ParentImage: C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe` (PID 5584) — this is extremely abnormal for a browser process. These shells are used to run the attacker's post-exploitation tools (`reg.exe`, `powershell.exe`, `RunasCs.exe`, etc.).

To confirm the injection, I checked for suspicious ProcessAccess from the initial beacon into the Edge process:

**Kibana filter:**
```
winlog.event_id: "10" AND process.pid: 9696 AND winlog.event_data.TargetImage: "*msedge.exe*"
```

This shows `rundll32.exe` (PID 9696) accessing `msedge.exe` (PID 5584) with `GrantedAccess: 0x1410` — which includes `PROCESS_QUERY_INFORMATION` and `PROCESS_VM_READ`, consistent with process migration reconnaissance. The attacker migrated the Meterpreter/beacon session from `rundll32.exe` into `msedge.exe` for persistence and stealth (a browser is always running and blends into normal network traffic).

The network connection data confirms this — the initial C2 call at `01:00:24` originates from `rundll32.exe` PID 9696 (user `bob.bobby`), while all later operator activity flows through `msedge.exe` PID 5584.

---

### Q5. Persistence was achieved through a registry value. What is the full path to the key, concatenated with the value?

**Answer:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdate`

I filtered for registry modification events tagged with the MITRE technique for Run keys:

**Kibana filter:**
```
winlog.event_id: "13" AND winlog.event_data.RuleName: "*RunKey*"
```

This returns two events tagged `T1060,RunKey`:

1. A `SetValue` event from `reg.exe` (PID 5792) at `01:55:21` writing:
   - **TargetObject:** `HKU\S-1-5-21-691616311-2440123089-1658721971-1002\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdate`
   - **Details:** `C:\Windows\System32\rundll32.exe shell32,Control_RunDLL C:\Users\Public\MicrosoftUpdate.cpl`

2. A notification event from `sihost.exe` acknowledging the new Run value.

The corresponding `reg.exe` process creation confirms the exact command:

**Kibana filter:**
```
winlog.event_id: "1" AND message: "*reg.exe*"
```

```
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "MicrosoftUpdate" /t REG_SZ /d "C:\Windows\System32\rundll32.exe shell32,Control_RunDLL C:\Users\Public\MicrosoftUpdate.cpl" /f
```

Per the instructions, `HKU\<SID>` maps to `HKCU`, so the answer is:
**`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdate`**

This ensures the malicious `.cpl` payload is re-executed via `rundll32.exe` every time the user logs in.

---

### Q6. A command was run to identify other local users. What is the full command line?

**Answer:** `powershell.exe -Command Get-LocalUser`

**Kibana filter:**
```
winlog.event_id: "1" AND message: "*powershell*"
```

A single PowerShell process creation event appears at `01:55:24`:

- **Image:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- **CommandLine:** `powershell.exe -Command Get-LocalUser`
- **ParentImage:** `C:\Windows\System32\cmd.exe` (spawned from the injected `msedge.exe`)

The `Get-LocalUser` cmdlet enumerates all local user accounts on the machine — this is the attacker performing reconnaissance to identify lateral movement targets.

---

### Q7. The attacker moved laterally to another user by finding a file containing credentials, then using them in a password reuse attack. What is the command line of the process that spawned the new shell?

**Answer:** `RunasCs.exe steve.stevens P@ssw0rd "rundll32 shell32.dll,Control_RunDLL C:\Users\Public\MicrosoftUpdate.cpl"`

**Kibana filter:**
```
winlog.event_id: "1" AND message: "*RunasCs*"
```

At `01:55:47`, a process creation event shows:

- **Image:** `C:\Users\Public\RunasCs.exe`
- **CommandLine:** `RunasCs.exe steve.stevens P@ssw0rd "rundll32 shell32.dll,Control_RunDLL C:\Users\Public\MicrosoftUpdate.cpl"`
- **ParentImage:** `C:\Windows\System32\cmd.exe`

`RunasCs.exe` is a well-known C# tool for running processes with alternate credentials (similar to `runas.exe` but more flexible, especially in non-interactive sessions). The attacker found credentials for user `steve.stevens` with password `P@ssw0rd` (likely in a plaintext file on disk) and used them to launch a new instance of the malicious `.cpl` payload under that user's context — establishing a new C2 session as `steve.stevens`.

The second network connection event confirms this: `rundll32.exe` PID 9560 connects to `10.13.52.111:50000` as user `DESKTOP-L2GP5HS\steve.stevens`.

---

### Q8. The attacker exploited an interesting privilege the user has by using a common technique. What is the command line?

**Answer:** `GodPotato-NET4.exe -cmd "cmd.exe /c rundll32 shell32.dll,Control_RunDLL C:\Users\Public\MicrosoftUpdate.cpl"`

**Kibana filter:**
```
winlog.event_id: "1" AND message: "*GodPotato*"
```

At `01:56:05`, a process creation event shows:

- **Image:** `C:\Users\Public\GodPotato-NET4.exe`
- **CommandLine:** `GodPotato-NET4.exe -cmd "cmd.exe /c rundll32 shell32.dll,Control_RunDLL C:\Users\Public\MicrosoftUpdate.cpl"`
- **ParentImage:** `C:\Windows\System32\cmd.exe`

GodPotato is a privilege escalation exploit in the "Potato" family that abuses Windows impersonation tokens. It spawns an arbitrary command as `NT AUTHORITY\SYSTEM` by exploiting the DCOM/RPC architecture. Here, the attacker uses it to launch yet another instance of the malicious `.cpl` — this time elevating to SYSTEM.

The child process chain confirms the escalation: `GodPotato-NET4.exe` → `cmd.exe` → `rundll32.exe` (PID 14012), and the third network connection shows `rundll32.exe` PID 14012 connecting to `10.13.52.111:50000` as `NT AUTHORITY\SYSTEM`.

---

### Q9. What is the name of this privilege?

**Answer:** `SeImpersonatePrivilege`

GodPotato (and all Potato-family exploits — JuicyPotato, PrintSpoofer, SweetPotato, etc.) exploit the **`SeImpersonatePrivilege`**. This privilege is commonly assigned to service accounts, IIS application pool identities, and users running certain Windows services. It allows a process to impersonate the security context of another user's token.

The attack flow: user `steve.stevens` has `SeImpersonatePrivilege` → GodPotato tricks a SYSTEM-level DCOM service into authenticating to a local named pipe → captures the SYSTEM token → impersonates it → spawns the malicious payload as SYSTEM.

This can be verified in the Sysmon data by checking the logon events:

**Kibana filter:**
```
winlog.event_id: "4672" AND message: "*steve*"
```

The Special Logon event (4672) for `steve.stevens` would list `SeImpersonatePrivilege` among the assigned privileges.

---

### Q10. Once in an elevated SYSTEM shell, credentials were dumped from LSASS memory using a well-known tool disguised as a legitimate binary. What is the path of the process that executed this action?

**Answer:** `C:\Users\Public\explorer.exe`

**Kibana filter:**
```
winlog.event_id: "1" AND message: "*\\Users\\Public\\explorer.exe*"
```

Two process creation events at `01:56:27` show:

- **Image:** `C:\Users\Public\explorer.exe`
- **CommandLine:** `explorer.exe live lsa`

This is **not** the legitimate Windows Explorer (`C:\Windows\explorer.exe`). It is a credential dumping tool (mimikatz or a variant) renamed to `explorer.exe` and placed in `C:\Users\Public\` to evade casual detection. The `live lsa` arguments are consistent with dumping LSASS credentials.

To confirm the LSASS access, I checked for ProcessAccess from this fake explorer to lsass.exe:

**Kibana filter:**
```
winlog.event_id: "10" AND process.executable: "*\\Users\\Public\\explorer.exe*" AND winlog.event_data.TargetImage: "*lsass.exe*"
```

This reveals `C:\Users\Public\explorer.exe` (PID 4860) accessing `C:\WINDOWS\system32\lsass.exe` (PID 868) with `GrantedAccess: 0x1fffff` (`PROCESS_ALL_ACCESS`) — the unmistakable signature of a credential dumping tool reading LSASS memory.

---

## Attack Timeline Summary

| Time (UTC) | Event | Details |
|---|---|---|
| ~01:54:39 | **File Download** | `MicrosoftUpdate.cpl` downloaded from `10.13.52.111:8888` via Edge |
| 01:54:48 | **Execution** | Double-click triggers `explorer.exe → control.exe → rundll32.exe` chain |
| 01:00:24 | **C2 Callback** | `rundll32.exe` (PID 9696) connects to `10.13.52.111:50000` as `bob.bobby` |
| ~01:55:00 | **Migration** | Attacker migrates from `rundll32.exe` into `msedge.exe` (PID 5584) |
| 01:55:21 | **Persistence** | Registry Run key `MicrosoftUpdate` added via `reg.exe` |
| 01:55:24 | **User Enumeration** | `powershell.exe -Command Get-LocalUser` |
| 01:55:31 | **File Recon** | `tree /f /a` — likely searching for credential files |
| 01:55:47 | **Lateral Movement** | `RunasCs.exe steve.stevens P@ssw0rd` — password reuse to `steve.stevens` |
| 01:56:05 | **Privilege Escalation** | `GodPotato-NET4.exe` exploits `SeImpersonatePrivilege` → SYSTEM |
| 01:56:27 | **Credential Dump** | `C:\Users\Public\explorer.exe live lsa` — dumps LSASS as SYSTEM |

---

## Flag Composition

The flag is composed from the concatenation of answers across all 10 questions, following the challenge's scoring format.
