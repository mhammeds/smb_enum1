# SMB Enumeration Tool (`smb_enum.sh`)

**Author:** Debug

A Bash-based SMB enumeration tool designed to automate common SMB reconnaissance tasks during authorized penetration tests. The script supports anonymous sessions, authenticated enumeration, share discovery, recursive file collection, RPC enumeration, RID brute-forcing, credential hunting, and optional password brute-force workflows.

---

# Requirements

Install the required dependencies on Kali Linux:

```bash
sudo apt install -y smbclient smbmap rpcclient nmap enum4linux-ng nbtscan nxc hydra
```

---

# Installation

```bash
git clone <repository-url>
cd smb_enum
chmod +x smb_enum.sh
```

---

# Usage

Automatically detect the SMB service port:

```bash
./smb_enum.sh <TARGET_IP>
```

Specify the SMB port manually:

```bash
./smb_enum.sh <TARGET_IP> 445
```

```bash
./smb_enum.sh <TARGET_IP> 139
```

---

# Authentication

## Anonymous Session

If no credentials are available, simply press **Enter** for both prompts.

The tool will automatically test anonymous (NULL) session access.

If successful:

```
NULL SESSION — Anonymous access available
```

---

## Authenticated Enumeration

Provide valid SMB credentials when prompted.

```
Username: administrator
Password: Password123
```

Credentials are verified using multiple SMB clients before enumeration begins.

---

## Password Brute Force (Optional)

If authentication fails or no credentials are available, the tool can perform an optional password brute-force attack.

```
Run brute-force? [y/N]
```

You may:

* Press **Enter** to use the default SecLists wordlists.
* Specify custom username/password lists.
* Skip brute-force entirely.

---

# Features

## NetBIOS Enumeration

Collects:

* NetBIOS hostname
* MAC address
* File Server service information

---

## SMB Server Information

Enumerates:

* Hostname
* Domain / Workgroup
* Operating System
* SMB dialects
* SMB signing status
* SMBv1 availability
* Vulnerability checks (where applicable)

---

## Share Enumeration

Discovers:

* Shared folders
* Read permissions
* Write permissions
* Share descriptions

Writable shares are highlighted automatically.

---

## Share Name Discovery

If no shares are visible, the tool can attempt to discover hidden shares using a wordlist.

---

## Recursive File Collection

Downloads accessible files from discovered shares.

The tool automatically searches downloaded files for:

* Plaintext credentials
* NTLM hashes
* Unix password hashes
* SSH private keys
* Group Policy Preferences (GPP) passwords
* Environment files
* Backup files
* Other potentially sensitive information

---

## SYSVOL & Group Policy Preferences

When SYSVOL is accessible, the tool automatically searches for:

* Groups.xml
* Services.xml
* ScheduledTasks.xml
* Other Group Policy Preference files

Encrypted `cpassword` values are automatically decrypted when possible.

---

## User Enumeration

Collects user information using multiple enumeration techniques.

Information may include:

* Username
* RID
* Password policy flags
* Logon scripts

---

## RPC Enumeration

Enumerates:

* Domain SID
* Password policy
* Named pipes
* SID-to-name mappings

---

## Recursive SMB Mapping

Maps every accessible directory and file within discovered shares.

---

## RID Brute Force

Optionally enumerate users by brute-forcing Relative Identifiers (RIDs).

Useful when standard enumeration is restricted.

---

## Credential Brute Force

The tool can optionally perform password brute-force using collected usernames and supplied wordlists.

---

## Automatic Re-Enumeration

If new credentials are discovered during execution, the tool can automatically repeat SMB enumeration using those credentials.

---

# Output

Results are stored automatically.

```
smb_results/
├── smb_<ip>_<timestamp>.txt
└── files_<ip>_<timestamp>/
```

The report contains:

* Enumeration results
* Share information
* User information
* Downloaded file findings
* Credential discoveries
* SMB configuration

Downloaded files are stored separately for manual review.

---

# Typical Workflow

1. Test anonymous access.
2. Enumerate available shares.
3. Download accessible files.
4. Review downloaded content for credentials or keys.
5. Re-run enumeration using newly discovered credentials.
6. Enumerate users and password policies.
7. Inspect SYSVOL (if available).
8. Review SMB security configuration.
9. Save the generated report for documentation.

---

# Useful Commands

Decrypt a Group Policy Preferences password:

```bash
gpp-decrypt '<cpassword>'
```

Crack an NTLM hash:

```bash
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt
```

Crack a SHA-512 Unix password hash:

```bash
hashcat -m 1800 hash.txt /usr/share/wordlists/rockyou.txt
```

Use a discovered SSH private key:

```bash
chmod 600 id_rsa
ssh -i id_rsa user@<TARGET_IP>
```

---

# Common Issues

| Problem                  | Solution                                                  |
| ------------------------ | --------------------------------------------------------- |
| `nxc: command not found` | Install NetExec (`nxc`) or use a compatible alternative.  |
| SecLists missing         | `sudo apt install seclists`                               |
| No shares discovered     | Verify the correct SMB port (139 or 445) and credentials. |
| Brute-force is slow      | Use a smaller wordlist.                                   |
| Anonymous session denied | Retry with valid credentials if available.                |

---

# Disclaimer

This tool is intended **only** for authorized security assessments, penetration testing engagements, and educational environments.

Do **not** use this tool against systems or networks without explicit permission from the owner.
