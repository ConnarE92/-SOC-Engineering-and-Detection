# Detecting SSH Brute-Force Activity with Wazuh: Home Lab Build + Attack Simulation

## Summary

I built a two-endpoint Wazuh SIEM lab (Windows + Linux agents) and used it to detect a simulated SSH brute-force attack. This report covers the lab architecture, the attack I ran against it, the actual alert Wazuh generated, and my analysis and triage decision as the reviewing analyst.

**TL;DR:** Hydra dictionary attack against SSH → Wazuh correlation rule fired ~2 seconds after the final logged attempt → confirmed true positive (expected test traffic) → identified that root SSH login was still enabled on the target, which is the real finding here.

---

## 1. Lab Architecture

| Component | Role |
|---|---|
| Wazuh Manager (OVA) | SIEM, manager, indexer, dashboard |
| Windows 10 VM | Agent: Sysmon + Event Logs + FIM |
| Ubuntu 26.04 VM | Agent: `auth.log`, `syslog` |
| Kali Linux VM | Attacker box |
| VMware Workstation, Bridged networking | Virtualization , both target and attacker VMs obtained addresses on the home LAN's subnet (`192.168.0.x`) rather than an isolated virtual network |

Both agents registered and reporting active before the test began.

![Wazuh agents dashboard , both agents active](./Image/Wazuh%20Dashboard.png)

> **Note on network isolation:** this lab used Bridged networking rather than Host-only, meaning the Kali attacker VM and Ubuntu target VM were both reachable on the actual home network during testing, not confined to a private virtual segment. For an internal authentication test between two of my own VMs this is a low-risk setup, but it's a different isolation posture than I used for the malware analysis lab elsewhere in this portfolio, where Host-only was required.

Sysmon was configured on the Windows host (Event IDs 1, 3, 11, 13 enabled) and the event channel added to `ossec.conf` so Wazuh ingests it , this was necessary because Wazuh doesn't pull Sysmon by default:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

*(This section covers the full build , full Windows/Linux install steps are intentionally left out of this report since they're standard vendor documentation, not the finding. If you want to see the raw build steps, they're in [docs/Lab-build-notes.md](../Wazuh-SOC-Build/docs/Lab-build-notes.md))*

---

## 2. Attack Simulation

**Tool:** Hydra
**Target:** Ubuntu Linux agent, SSH (port 22)
**Command:**

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.0.89
```

This runs a dictionary attack against the `root` account specifically , a realistic choice, since `root` is one of the most commonly targeted usernames in real-world SSH brute-force campaigns (it doesn't require guessing a valid username first). Modern Ubuntu ships with `PermitRootLogin prohibit-password` by default, which blocks root from ever successfully authenticating via password , but critically, it does **not** reject the connection before authentication is attempted, so each password guess still generates a genuine `Failed password for root` log entry. This means the attack still produces a realistic brute-force signature even though it can never succeed.

**MITRE ATT&CK mapping:** [T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/)

![Hydra running against target](./Image/Kali%20Linux%20Hydra.png)

---

## 3. Evidence , What Actually Fired

```json
{
  "rule": {
    "id": "5758",
    "level": 8,
    "description": "Maximum authentication attempts exceeded.",
    "groups": ["syslog", "sshd", "authentication_failed"],
    "firedtimes": 106,
    "mitre": {
      "id": ["T1110"],
      "tactic": "Credential Access",
      "technique": "Brute Force"
    }
  },
  "agent": {
    "id": "006",
    "name": "ConnarUbuntu2",
    "ip": "192.168.0.89"
  },
  "data": {
    "dstuser": "root",
    "srcip": "192.168.0.94",
    "srcport": "43364"
  },
  "decoder": {
    "name": "sshd"
  },
  "location": "journald",
  "full_log": "Jul 08 17:35:51 connar-VMware-Virtual-Platform sshd-session[12974]: error: maximum authentication attempts exceeded for root from 192.168.0.94 port 43364 ssh2 [preauth]",
  "timestamp": "Jul 8, 2026 @ 18:35:52.039"
}
```

![Wazuh alert detail , rule 5758 triggered](./Image/Wazuh%20Brute-force%20alert.png)

Raw `auth.log` entries backing this up:

```
2026-07-08T18:35:19.290074+01:00 connar-VMware-Virtual-Platform sshd-session[12844]: Failed password for root from 192.168.0.94 port 52186 ssh2
2026-07-08T18:35:47.444791+01:00 connar-VMware-Virtual-Platform sshd-session[12967]: Failed password for root from 192.168.0.94 port 43356 ssh2
2026-07-08T18:35:50.845735+01:00 connar-VMware-Virtual-Platform sshd-session[12974]: Failed password for root from 192.168.0.94 port 43364 ssh2
```

> Note: `full_log` above shows a timestamp of 17:35:51 while the dashboard's `timestamp` field shows 18:35:52.039 , this isn't an inconsistency, it's a timezone difference. The underlying `journald` source logs in UTC, while the Wazuh dashboard displays local time (UTC+1 / BST). Same event, one hour's display offset.

---

## 4. Timeline

| Time (real, from `auth.log` and Kali terminal) | Event |
|---|---|
| 18:35:06 | Hydra started against `root` @ 192.168.0.89 (confirmed via Kali terminal output) |
| 18:35:19.290 | First failed root login logged in `auth.log` |
| 18:35:19 – 18:35:50 | Sustained rapid-fire failed attempts (~31 seconds) |
| 18:35:50.845 | Final failed attempt logged (port 43364) |
| 18:35:52.039 | Rule 5758 fires , Maximum authentication attempts exceeded (level 8) |

**Detection summary:** ~13 seconds from attack launch to the first logged failure, then a ~31-second sustained burst before the correlation rule's threshold was crossed and it escalated to a level-8 alert , roughly 2 seconds after the final attempt in that burst. That lag reflects genuine correlation-rule behavior (a minimum number of failures within a window must accumulate before escalation), not a slow detection pipeline.

---

## 5. Analysis & Triage

**Verdict: True positive , confirmed test traffic, no remediation needed for this instance.**

Reasoning:
- Source IP (`192.168.0.94`) is my own Kali VM, on the internal lab network , expected.
- Attack pattern (rapid sequential failures, single account, single source, 106 cumulative firings of this rule on the agent) matches classic brute-force behavior, not a false-positive trigger like a misconfigured script or expired credential retry loop.
- No successful authentication occurred in the log , the attack did not succeed, which I confirmed by checking for a `session opened` entry and finding none.

**The actual finding worth acting on:** root login over SSH is enabled on this host (`PermitRootLogin` is not set to `no` in `sshd_config`) , that's what allowed this attack surface to exist at all. In a real environment, that's the item I'd flag for remediation, not the alert itself.

If this had been a real incident rather than a test, next steps would be:
1. Block source IP at the firewall.
2. Check for any successful auth from the same source in a wider time window.
3. Rotate credentials for the targeted account regardless of success/failure.
4. Verify `PermitRootLogin no` and enforce key-based auth.

---

## 6. Recommendations (specific to this finding)

1. **Disable root SSH login** (`PermitRootLogin no`) , this is the actual gap this test exposed.
2. **Move to key-based auth** for this host; disable password auth entirely.
3. **Add `fail2ban`** or Wazuh's active response module to auto-block after N failures instead of relying on manual review.

---

## 7. What I'd do next

- Re-run the same test with `PermitRootLogin no` enforced and confirm the attack surface is meaningfully reduced (attempts still logged, but the specific root-targeted vector is closed).
- Extend detection to a non-root account brute-force to confirm the rule generalizes.
- Move on to Sysmon-based detection of a different technique (e.g., a T1059 PowerShell execution chain) to round out coverage beyond authentication events.
