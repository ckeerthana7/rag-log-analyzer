# Security knowledge base
# Each entry starts with "## " and has ATT&CK, Indicators, Meaning and Response lines.
# Edit or add entries; the analyzer reloads this file on every run.

## SSH brute-force password guessing
ATT&CK: T1110.001 Brute Force: Password Guessing
Indicators: Many failed password login attempts from the same source IP address in a short time. The same few accounts are tried repeatedly, often root, admin or ubuntu. Attempts arrive at a steady automated rate of several per minute.
Meaning: An automated tool is guessing passwords for accounts on the SSH service. Internet-facing servers are scanned constantly, so this is common, but it becomes dangerous if any guess succeeds.
Response: Block the source IP with a firewall or fail2ban. Disable password login and require SSH keys. Enforce long unique passwords and multi-factor authentication. Check whether the same IP later logged in successfully.

## Password spraying
ATT&CK: T1110.003 Brute Force: Password Spraying
Indicators: One source IP address tries many different usernames with only one or two password attempts each. The low number of attempts per account avoids lockout thresholds. Usernames come from common lists such as john, test, backup and guest.
Meaning: The attacker is trying a few very common passwords across many accounts, hoping that at least one account uses a weak password.
Response: Alert on many distinct usernames from one source, not only on repeated failures per account. Block common passwords, require multi-factor authentication, and review accounts that logged in successfully around the same time.

## Username enumeration and invalid user probing
ATT&CK: T1110 Brute Force (reconnaissance step)
Indicators: Log lines saying Invalid user followed by a failed password for invalid user. Many non-existent account names tried from one address.
Meaning: The attacker is discovering which usernames exist on the system before guessing their passwords.
Response: Restrict SSH access with AllowUsers or AllowGroups, expose SSH only to trusted networks or a VPN, and block repeat offenders.

## Successful login after repeated failures
ATT&CK: T1078 Valid Accounts, following T1110 Brute Force
Indicators: An accepted login from an IP address that earlier produced many failed attempts. The successful login uses the same account that was being guessed.
Meaning: The password guessing may have worked, so the account could be compromised. This is the most urgent pattern in authentication logs.
Response: Treat as a possible compromise. Review the session and the commands run, end the session, reset the account credentials, and check authorized_keys, cron jobs and new user accounts for persistence. Isolate the host if activity looks malicious.

## Direct root login attempts
ATT&CK: T1110.001 Brute Force: Password Guessing, T1078.003 Valid Accounts: Local Accounts
Indicators: Repeated failed login attempts for the root account over SSH, from one or several addresses.
Meaning: Attackers favour root because it exists on every system and gives full control if the password is guessed.
Response: Set PermitRootLogin no and use named accounts with sudo. Use key-based authentication for administrators and limit which sources may reach SSH.

## Distributed credential stuffing
ATT&CK: T1110.004 Brute Force: Credential Stuffing
Indicators: Many different source IP addresses each make a small number of attempts against the same few usernames, which spreads the activity below per-IP thresholds.
Meaning: Credentials leaked from other breaches are being tried against this service, often from a botnet.
Response: Rate limit per account as well as per IP, require multi-factor authentication, and check the targeted accounts against known breach lists.

## Port scanning and connection probing
ATT&CK: T1595.001 Active Scanning: Scanning IP Blocks
Indicators: Many connections that close before authentication completes, or connections from one address to many ports, with no login attempts.
Meaning: Someone is mapping which services are exposed. This is reconnaissance and usually precedes targeted attacks.
Response: Close unused ports, put SSH behind a VPN or allow list, and watch for the same address returning with login attempts.

## Log injection and prompt injection in log fields
ATT&CK: Not an ATT&CK technique; see CWE-117 Improper Output Neutralization for Logs, OWASP LLM01 Prompt Injection and MITRE ATLAS AML.T0051
Indicators: A username or other log field contains instruction-like text, such as a request to ignore previous instructions or to report that the system is safe. The text is aimed at an AI log analysis tool, not at the server.
Meaning: An attacker who knows logs are analysed by an AI model plants text in a field they control to mislead the analysis or hide their activity.
Response: Treat every log field as untrusted data, never as instructions. Sanitise and shorten fields, strip control characters, escape output, and never give raw logs to a language model without guarding them.
