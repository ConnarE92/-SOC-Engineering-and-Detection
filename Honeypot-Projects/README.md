# Multi-Honeypot Threat Collection Lab: T-Pot Deployment & Attack Simulation

## Summary

I deployed T-Pot (a multi-honeypot framework) on an Ubuntu Desktop VM, diagnosed and resolved a port conflict that was preventing the stack from starting, then ran a set of controlled attacks from a Kali VM to validate that the honeypot's sensors actually capture and log attacker behavior end-to-end.

**Scope note:** this report demonstrates the ability to deploy, diagnose, and validate honeypot infrastructure — not detection engineering or SIEM alert tuning, which is covered in a separate report in this portfolio. Where Suricata alerts are discussed below, it's in service of proving the pipeline works, not as a detection-tuning exercise.

**Key finding:** the honeypot stack intermittently failed to start because Ubuntu Desktop's CUPS printing service claims port 631 via socket activation at boot — the same port required by T-Pot's `ipphoney` container. Because CUPS's socket unit binds before Docker starts, the conflict is timing-dependent: it doesn't reproduce from a simple service restart, only from a full reboot, which is what the original failure actually was.

---

## 1. Environment

| Component | Detail |
|---|---|
| Host | Ubuntu Desktop, VMware Workstation |
| Platform | T-Pot 24.04.1 |
| Network | Bridged — obtained an address on the home LAN's subnet rather than an isolated virtual network |
| Attacker | Kali Linux VM, same bridged network (confirmed IP: 192.168.0.94) |
| Sensors used | Cowrie, Dionaea, Heralding, Suricata, p0f |

![T-Pot dashboard, connected/healthy](images/tpot_dashboard_fixed.png)
*T-Pot dashboard in its working state, confirming all services (Attack Map, Kibana, Elasticvue, Spiderfoot, etc.) reachable.*

![VM network settings — Bridged adapter](images/vm_network_settings.png)
*VMware network configuration showing the Bridged adapter used for this lab.*

> **Note on network isolation:** this lab used Bridged networking rather than Host-only, meaning the T-Pot instance and the Kali attacker VM were both reachable on the actual home network during testing, not confined to a private virtual segment. Since T-Pot is designed to log connections from anything that reaches it, the honeypot could, in principle, have logged interactions from other devices on the home network too — not exclusively the Kali VM. This isn't a theoretical caveat: Section 5's SMB probe was deliberately run against the full `/24` subnet rather than just the honeypot host, and the results (Section 6) show other home-network devices responding alongside the T-Pot host itself, which is direct evidence of what this networking choice actually exposes. Every piece of evidence attributed to Kali below is confirmed by matching source IP (192.168.0.94, verified via `ip a` on the Kali VM — see Section 6). The isolation posture here is intentionally different from the malware analysis lab elsewhere in this portfolio, where Host-only was required because that lab involved live malware samples rather than passive service emulation.

---

## 2. How It Works: Architecture

T-Pot runs each honeypot as a separate Docker container, so a single host can present dozens of fake services at once without them interfering with each other. The pipeline has four stages:

1. **Deception** — each container emulates a real service (Cowrie pretends to be SSH/Telnet, Dionaea emulates vulnerable/malware-drop behavior including SMB, Heralding harvests credentials across multiple protocols, etc.).
2. **Interaction & logging** — each container logs everything a connecting client does.
3. **Processing** — Logstash ships container logs into Elasticsearch for indexing.
4. **Visualization** — Kibana dashboards and T-Pot's attack map render the indexed data.

Suricata inspects raw network traffic for known malicious signatures, and p0f passively fingerprints connecting hosts, both feeding the same pipeline.

**Why this matters for a SOC context:** because every "service" is fake, there's a much lower noise-to-signal ratio than in production — there's no legitimate business traffic to separate from attacker traffic. This isn't absolute, though: mass internet scanners, research crawlers (e.g. Shodan/Censys), and — as demonstrated in this lab — other devices on the same network segment can all generate interactions that aren't necessarily malicious. The value of a honeypot is that everything logged is *worth looking at*, not that everything logged is *hostile*.

---

## 3. The Problem: Port Conflict on Deployment

**Root cause:** Ubuntu Desktop ships with CUPS bound to port 631 (IPP), the same port T-Pot's `ipphoney` honeypot needs. This conflict turned out to be more subtle than a simple "service is running" check reveals.

CUPS on Ubuntu is socket-activated: `cupsd` can show as `active (running)` in `systemctl status` without actually holding the listening socket at that moment, since the socket unit (`cups.socket`) is what claims the port, and it typically does this at boot. This means the conflict is timing-dependent — restarting the `tpot` service on a running system doesn't reliably reproduce it, because Docker's `ipphoney` container can win the race for the port if CUPS's socket hasn't been triggered yet. The original failure happened at boot, so reproducing it required an actual reboot, not just a service restart.

**Reproducing the fault (post-reboot):**

```
tpo1@connar-VMware-Virtual-Platform:~/Desktop$ docker ps -a
CONTAINER ID   IMAGE                              STATUS                    NAMES
3b3327bfec53   snare:24.04.1                      Created                   snare
bdec7a106512   tanner:24.04.1                     Created                   tanner
020bfeefc027   kibana:24.04.1                     Created                   kibana
ffad5f725110   logstash:24.04.1                   Created                   logstash
...
e00859b60b85   ipphoney:24.04.1                   Created                   ipphoney
...
6b6e3fc58fd1   tpotinit:24.04.1                   Up 13 seconds (healthy)   tpotinit
```

The majority of containers — including `ipphoney` itself — are stuck in `Created`, never actually starting, while only a handful (`miniprint`, `nginx`, `p0f`, `cowrie`, `fatt`, `suricata`, `honeytrap`, `tpotinit`) reached `Up`. This shows the failure isn't isolated to one container: because `ipphoney` couldn't bind to its port, Docker Compose's startup ordering stalled a large batch of dependent containers behind it in `Created` limbo.

**Confirming the root cause:**

```
tpo1@connar-VMware-Virtual-Platform:~/Desktop$ sudo ss -tulpn | grep 631
tcp   LISTEN 0      4096       127.0.0.1:631        0.0.0.0:*    users:(("cupsd",pid=1438,fd=7))
tcp   LISTEN 0      4096           [::1]:631           [::]:*    users:(("cupsd",pid=1438,fd=6))
```

`cupsd` (PID 1438) is confirmed by name as the process holding port 631 — not inferred, but directly named in the socket table. Note that CUPS is bound to loopback (`127.0.0.1`/`::1`) here rather than `0.0.0.0` — the conflict still occurs because Docker's port-mapping for `ipphoney` requires binding `0.0.0.0:631` on the host, and the port number is already claimed at the OS level regardless of which interface CUPS itself listens on.

**Fix:**

```bash
sudo systemctl stop cups cups-browsed
sudo systemctl disable cups cups-browsed
sudo systemctl mask cups cups-browsed
sudo systemctl restart tpot
```

**Verification:**

![CUPS fix applied and stack recovering](images/cups_fix_and_recovery.png)
*Full remediation sequence captured in one terminal session: `mask` applied, `tpot` restarted, `docker ps` showing containers healthy, and `ss -tulpn | grep 631` confirming `docker-proxy` (not `cupsd`) now owns the port.*

One detail worth noting from this output: the `disable` command returned a warning that the CUPS unit files "have no installation config" and are "not meant to be enabled or disabled using systemctl" — this is expected for socket-activated units and is not a failure. `mask`, which ran immediately after and completed silently, is the command that actually prevents the unit from being triggered again. Reading past a warning like this rather than assuming a command failed (or ignoring it) is worth calling out, since it's easy to misinterpret systemd output at a glance.

Post-fix, `ss -tulpn | grep 631` shows the port owned by `docker-proxy` again, and `docker ps` shows the full container set `Up` with `tpotinit` reporting `(healthy)`.

---

## 4. Deployment Constraints: Why This Is an Internal Simulation, Not Live Internet Traffic

This instance is deployed on a residential Virgin Media connection. Virgin Media blocks a set of common inbound ports by default and doesn't provide a straightforward path to forward the wider range of ports T-Pot needs for genuine internet-facing exposure. Even where a port isn't blocked, residential ISPs generally aren't a suitable place to expose a real honeypot to the open internet — CGNAT, dynamic IPs, and ISP acceptable-use terms all work against it.

Given this, exposing this instance to live, unsolicited internet traffic wasn't a viable option — not a limitation I hit and worked around, but a deliberate call made up front. Attempting it would have meant tolerating a real ToS violation and an unstable public-facing target, for evidence I could get more reliably a different way. Instead, I validated the full pipeline using controlled traffic generated from my own Kali VM on the same bridged network — a repeatable, source-verifiable way to prove the mechanism works end-to-end before investing in real internet-facing exposure.

Every log, alert, and screenshot in this report from Section 6 onward is from that internal simulation, captured on my own instance and confirmed by matching source IP back to the Kali VM (192.168.0.94).

**Next step:** deploy this same T-Pot configuration to a low-cost cloud VPS (DigitalOcean/Vultr) with a public IP and no port restrictions, to capture genuine internet-sourced attacker traffic. See Section 8.1.

---

## 5. Attack Simulation

Ran from the Kali VM against the T-Pot instance:

| Test | Command | Target sensor(s) |
|---|---|---|
| Full port scan with version detection | `nmap -sV -p- 192.168.0.16` | Suricata, p0f |
| SSH brute-force | `hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.0.16` | Cowrie |
| FTP credential brute-force | `hydra -l admin -P /usr/share/wordlists/rockyou.txt -s 21 ftp://192.168.0.16` | Dionaea / Heralding |
| SMB probe (full subnet) | `sudo nmap -sV -p445 192.168.0.0/24` | Suricata, Dionaea |

![Nmap scan command](images/nmap_scan_command.png)
![SSH Hydra brute-force](images/hydra_ssh_scan.png)
![FTP Hydra brute-force](images/hydra_ftp_scan.png)
![SMB subnet probe command](images/smb_probe_command.png)

Note that the SMB probe was deliberately run against the whole `/24` subnet, not just the honeypot host — this was intentional, to generate direct evidence for the bridged-network caveat in Section 1, rather than leaving it as an untested assumption.

---

## 6. Evidence

### 6.1 SSH brute-force → Cowrie

Hydra found a valid credential (`root:iloveyou`) against the emulated SSH service in a single attempt at 11:35:41 (BST).

![Hydra SSH result](images/hydra_ssh_scan.png)

Cowrie's logs show a cluster of `session.closed` events at 11:35:41.7xx, each around 1.1 seconds in duration:

![Cowrie session log — repeated short sessions](images/cowrie_ssh_sessions.png)

The timing (11:35:28–11:35:41, matching Hydra's run window) and the uniform, short session durations are consistent with automated brute-force connection behavior rather than a human operator — each attempt opens, authenticates or fails, and closes in about a second.

### 6.2 FTP brute-force → Dionaea/Heralding (matched credential)

Hydra found a valid FTP credential (`admin:1234567`) at 12:16:31–32:

![Hydra FTP result](images/hydra_ftp_results.png)

The honeypot's own log for the same second shows the identical password submitted and accepted:

```
@timestamp:  Jul 11, 2026 @ 12:16:32.783
dest_ip:     192.168.0.16
dest_port:   21
event_type:  ftp
ftp.command:       PASS
ftp.command_data:  1234567
ftp.completion_code: 230
ftp.reply:   User logged in, proceed
```

This is the strongest piece of correlated evidence in this lab: the same password, the same second, matched at the field level between the attacker tool's output and the honeypot's own capture. It confirms the honeypot logged the live attack as it happened, rather than the log and the attack being coincidentally similar.

### 6.3 Nmap scan → Suricata alert

The `nmap -sV -p-` scan (started 11:22) generated three Suricata alerts, at 11:27:04, 11:28:34, and 11:30:04 — several minutes after the scan began, and only three alerts across an ~8-minute full port scan, rather than continuous alerting:

![Suricata Nmap alert](images/nmap_suricata_alert.png)

Two things are worth flagging honestly rather than glossing over:

- **The signature name doesn't match the flag used.** The alert is `ET SCAN NMAP -sA (1)` — an ACK-scan signature — even though the scan actually run was `-sV` (version detection). This is because ET signatures for Nmap detection often key off underlying packet/probe behavior shared across scan types, rather than the specific flag passed on the command line. It's a useful reminder that a signature name doesn't always describe the exact technique used against it.
- **Sparse alerting relative to scan duration.** Three alerts across roughly 8 minutes of scanning suggests Suricata is either rate-limiting repeated matches from the same source, or the signature only fires on specific probe patterns within the scan rather than on every packet. Confirming which would require inspecting the rule itself — flagged here as an observation, not a conclusion.

### 6.4 SMB probe → Dionaea negotiation + Suricata alerts

**Subnet exposure (Section 1 caveat, demonstrated):** the probe was run against the full `/24`, and results show other home-network devices (`.1`, `.12`) responding on port 445 alongside the T-Pot host (`.16`):

![SMB probe results across subnet](images/smb_probe_results.png)

This is the direct, practical example behind the Section 1 disclosure — under a bridged network, a scan aimed broadly at "the network" surfaces real devices, not just the honeypot, and that's worth being explicit about rather than treating as a hypothetical risk.

**Protocol-level negotiation (Dionaea):** the honeypot didn't just accept a TCP connection on 445 — it completed a full SMB1 negotiate-protocol exchange:

![SMB dialect negotiation detail](images/smb_dialect_negotiation.png)

Key fields:
```
smb.command:        SMB1_COMMAND_NEGOTIATE_PROTOCOL
smb.client_dialects: [MICROSOFT NETWORKS 3.0, LANMAN1.0, LM1.2X002, DOS LANMAN2.1,
                       LANMAN2.1, Samba, NT LANMAN 1.0, NT LM 0.12, SMB 2.002, SMB 2.???]
smb.status:          STATUS_SUCCESS
t-pot_ip_int:        192.168.0.16
src_ip:              192.168.0.94   (confirmed as the Kali VM's own address — see below)
```

This confirms Dionaea is doing genuine protocol-level emulation — negotiating a realistic dialect list and returning success — rather than a bare port listener, which is a meaningfully more convincing deception than just "the port was open."

**Suricata's response — two near-simultaneous alerts:**

![SMB alert detail 1 (12:25:22.232)](images/smb_alert_1.png)
![SMB alert detail 2 (12:25:22.236)](images/smb_alert_2.png)

Two alerts fired 4 milliseconds apart for this SMB traffic, both classified identically:

```
alert.category:                     Misc activity
alert.action:                       allowed
alert.metadata.affected_product:    Windows_XP_Vista_7_8_10_Server_32_64_Bit
alert.metadata.confidence:          Medium
alert.metadata.signature_severity:  Informational
alert.metadata.performance_impact:  Significant
alert.metadata.deployment:          [Perimeter, Internal]
```

Both alerts agree on classification (no contradiction between them), which suggests the negotiate sequence matched more than one rule rather than the same event being logged twice. A couple of details worth a mention: the signature is tagged `deployment: [Perimeter, Internal]`, meaning it's designed to fire regardless of network position — relevant given this lab's own internal/bridged placement (Section 1). It's also tagged `performance_impact: Significant` despite being informational severity, which is a real operational tradeoff a SOC would weigh when deciding which signatures to run continuously at scale.

**Source attribution:**

```
tpo1@connar-VMware-Virtual-Platform:~$ ip a  (run on Kali)
eth0: inet 192.168.0.94/24
```

![Kali IP confirmation](images/kali_ip_confirmation.png)

`192.168.0.94` matches the `src_ip` field in the SMB flow log exactly, confirming this traffic came from the Kali VM as intended, rather than an unrelated device on the LAN.

---

## 7. Analysis

Taken together, the evidence in Section 6 demonstrates the full pipeline working end-to-end, not just individual pieces in isolation:

- **The FTP correlation (6.2)** is the clearest proof point: an identical, timestamped credential match between the attacker's tool output and the honeypot's own log removes any doubt that the "attack" and the "log" are the same event.
- **The Cowrie timing pattern (6.1)** shows the pipeline captures behavioral signal (session duration, connection cadence) that's useful for distinguishing automated activity from a human operator, even without inspecting session content in depth.
- **The Nmap/Suricata mismatch (6.3)** is a genuinely useful negative-ish finding: signature names don't always describe the literal technique that triggered them, and alert volume doesn't necessarily scale with scan duration. Both are worth knowing before trusting a signature name at face value in a real SOC context.
- **The SMB evidence (6.4)** does double duty: it proves Dionaea's SMB emulation is protocol-realistic rather than superficial, and it turned the Section 1 network-isolation caveat from a stated risk into an observed one, since the same probe surfaced other real devices on the LAN.
- **The CUPS root cause (Section 3)** turned out to be more interesting than "a service was using the port." The socket-activation detail — that the conflict is a boot-time race rather than a persistent one — explains why the fault didn't reproduce on the first attempt to recreate it, and required going back to a reboot to capture properly. That itself is a useful lesson: "is the service running" and "does the service currently hold the port" are not the same question.

---

## 8. Security Considerations

- Bridged network — the T-Pot VM sat on the home LAN's subnet, not an isolated virtual network. See Section 1 for the full note, and Section 6.4 for direct evidence of what that exposes in practice.
- No outbound internet access enabled beyond what T-Pot itself needs for logging.
- Snapshots taken before each intentional break/fix cycle for clean rollback.
- No real credentials, production data, or production systems exposed at any point.

### 8.1 Planned Next Step: Cloud Deployment for Real Attack Data

The current instance runs on a local VM behind a residential connection, which limits data collection to internally simulated traffic. The planned next iteration is to deploy the same T-Pot configuration to a cloud VPS (DigitalOcean or Vultr), which resolves this since a VPS provider's network sits on its own public IP range with no residential-style port restrictions.

This would involve:
- Provisioning a droplet (4 vCPU / 8GB RAM minimum, per T-Pot's documented recommendations, or a lighter Mini install profile on a smaller instance).
- Deploying the same configuration used locally, with firewalls left open on honeypot-facing ports.
- Leaving the instance live for a short capture window to gather genuine unsolicited internet traffic.
- Replacing the internally-simulated evidence in Section 6 with a comparable set generated from real, unsolicited attacker traffic.

This is a deliberate, scoped next step — a short-lived droplet run for a capture window, then torn down — rather than an ongoing cost commitment.

---

## 9. Conclusion

This lab set out to demonstrate the ability to deploy, troubleshoot, and validate a multi-honeypot stack — not to perform detection engineering, which is covered elsewhere in this portfolio. Both goals were met with direct evidence rather than assumption.

The CUPS/port 631 conflict was diagnosed past the surface-level "a service is using the port" explanation, into the actual mechanism: a boot-time socket-activation race between `cupsd` and Docker, which is why the fault didn't reproduce from a simple service restart and required a full reboot to capture properly. The fix (`mask`, not just `stop`/`disable`) was verified by confirming `docker-proxy` reclaimed the port and the full container set returned to a healthy state.

The attack simulation then validated that the pipeline works as designed: Hydra's FTP credential was matched field-for-field against Dionaea/Heralding's own capture of the same event; Cowrie's session timing was consistent with the SSH brute-force that produced it; Suricata correctly alerted on the Nmap scan (with an honest note on where the signature name and alert volume didn't perfectly match expectations); and the SMB probe both proved Dionaea's protocol-level emulation was genuine and provided direct evidence for the bridged-network exposure caveat raised in Section 1.

The next step — a short-lived cloud deployment to capture real, unsolicited internet traffic — is scoped and ready to run, building on a configuration and validation process that's now proven to work.
