#!/usr/bin/env python3
"""
enrich_effects.py — Replace generic `action_completed` with meaningful effect predicates.

Most batch-generated actions declare only `expected_effects: [action_completed]`,
which breaks the attack chain planner. This script infers meaningful effects from
action name, category, and command_template.

Usage:
    python3 enrich_effects.py --dry-run    # Show changes
    python3 enrich_effects.py --apply      # Apply changes
"""

import argparse
import sys
from pathlib import Path

import yaml

ACTIONS_DIR = Path("/home/kali/knowledge/actions")


# ── Effect inference rules ──
# Maps action name pattern → list of effects to declare
EFFECT_RULES = {
    # Recon/enumeration
    "nmap_": ["services_enumerated", "ports_discovered"],
    "port_scan": ["ports_discovered"],
    "service_scan": ["services_enumerated"],
    "subdomain_enum": ["subdomains_found", "has_subdomains"],
    "dns_": ["dns_records_found"],
    "vhost_enum": ["vhosts_discovered"],
    # Web enumeration
    "gobuster": ["web_directories_discovered", "has_web_paths"],
    "feroxbuster": ["web_directories_discovered", "has_web_paths"],
    "ffuf": ["web_directories_discovered", "has_web_paths"],
    "dirsearch": ["web_directories_discovered", "has_web_paths"],
    "wfuzz": ["web_directories_discovered", "has_web_paths"],
    "api_enum": ["api_endpoints_found"],
    "nikto": ["web_vulns_found", "tech_fingerprinted"],
    "whatweb": ["tech_fingerprinted"],
    "wpscan": ["cms_enumerated", "wordpress_vulns_found"],
    "droopescan": ["cms_enumerated", "drupal_vulns_found"],
    "joomscan": ["cms_enumerated", "joomla_vulns_found"],
    # SMB
    "smb_": ["smb_info_gathered", "has_shares"],
    "smbclient": ["shares_enumerated", "has_shares"],
    "smb_enum_shares": ["has_shares"],
    "smb_enum_users": ["has_users"],
    "enum4linux": ["has_users", "has_shares", "smb_info_gathered"],
    "crackmapexec": ["smb_access_tested", "credentials_validated"],
    "nxc_smb": ["smb_access_tested"],
    "nxc_winrm": ["winrm_access_tested"],
    "nxc_ldap": ["ldap_access_tested"],
    "nxc_mssql": ["mssql_access_tested"],
    # AD — credential acquisition
    "kerberoast": ["tgs_hashes_obtained", "has_hash"],
    "asreproast": ["asrep_hashes_obtained", "has_hash"],
    "secretsdump": ["hashes_dumped", "ntlm_hashes_obtained", "has_hash"],
    "dcsync": ["krbtgt_hash", "domain_admin", "has_hash"],
    "dpapi": ["dpapi_secrets_dumped", "has_cred"],
    "gmsa": ["gmsa_password_read", "has_cred"],
    "laps": ["laps_password_read", "has_cred"],
    "gpp_password": ["gpp_password_found", "has_cred"],
    "msol_": ["azure_cred_found", "has_cred"],
    "stored_credentials": ["stored_creds_extracted", "has_cred"],
    "ntds_": ["ntds_dumped", "has_hash", "domain_admin"],
    # AD — kerberos
    "gettgt": ["tgt_obtained", "has_ticket"],
    "getst": ["tgs_obtained", "has_ticket"],
    "golden_ticket": ["golden_ticket_forged", "domain_admin"],
    "silver_ticket": ["silver_ticket_forged"],
    "diamond_ticket": ["diamond_ticket_forged", "domain_admin"],
    "passtheticket": ["ticket_injected", "shell_obtained"],
    "passthehash": ["pth_success", "shell_obtained"],
    "overpass_the_hash": ["opth_success", "has_ticket"],
    "kerberos_delegation": ["delegation_abused", "shell_obtained"],
    "constrained_delegation": ["delegation_abused", "shell_obtained"],
    "unconstrained_delegation": ["delegation_abused", "has_ticket"],
    "rbcd": ["rbcd_configured", "shell_obtained"],
    # AD — escalation
    "adcs_esc1": ["certificate_obtained", "domain_admin"],
    "adcs_esc4": ["template_modified", "certificate_obtained"],
    "adcs_esc8": ["relay_to_adcs_success", "certificate_obtained"],
    "certipy": ["adcs_findings", "certificate_obtained"],
    "acl_abuse": ["acl_abused", "privilege_escalated"],
    "dacledit": ["dacl_modified"],
    "gpo_abuse": ["gpo_modified", "domain_admin"],
    "shadow_credentials": ["shadow_creds_added", "has_ticket"],
    "sid_history": ["sid_history_added", "domain_admin"],
    "skeleton_key": ["skeleton_key_installed", "domain_admin"],
    "krbtgt": ["krbtgt_accessed", "domain_admin"],
    "zerologon": ["zerologon_exploited", "domain_admin"],
    "samaccountname_spoof": ["nopac_exploited", "domain_admin"],
    "machine_account": ["machine_account_added"],
    "maq_": ["machine_account_added"],
    "addcomputer": ["machine_account_added"],
    # AD — coercion/relay
    "coerce": ["coerced_auth", "ntlm_captured"],
    "petitpotam": ["coerced_auth", "ntlm_captured"],
    "spoolsample": ["coerced_auth", "ntlm_captured"],
    "responder": ["ntlm_captured", "has_hash"],
    "ntlmrelayx": ["ntlm_relayed", "shell_obtained"],
    "ntlm_theft": ["ntlm_captured"],
    # AD — shell/execution
    "psexec": ["shell_obtained", "admin_shell"],
    "wmiexec": ["shell_obtained", "admin_shell"],
    "smbexec": ["shell_obtained", "admin_shell"],
    "dcomexec": ["shell_obtained"],
    "atexec": ["command_executed"],
    "evil_winrm": ["shell_obtained"],
    "winrm": ["shell_obtained"],
    # Bloodhound
    "bloodhound": ["graph_collected", "attack_paths_found"],
    # Enum — AD
    "ldap_anon": ["ldap_info_gathered", "has_users"],
    "ldap_passback": ["ldap_creds_captured", "has_cred"],
    "ldapdomaindump": ["domain_info_dumped", "has_users"],
    "ldapsearch": ["ldap_info_gathered"],
    "rpcclient": ["rpc_info_gathered", "has_users"],
    "trusts_enum": ["trusts_enumerated"],
    "wmi_enum": ["wmi_info_gathered"],
    "kerberos_enum": ["spn_users_found", "has_users"],
    "kerberos_bruteforce": ["valid_users_found", "has_users"],
    "kerbrute": ["valid_users_found", "has_users"],
    "rid_brute": ["has_users"],
    # Spraying / brute-force
    "spray": ["credentials_validated", "has_cred"],
    "hydra": ["credentials_brute_forced", "has_cred"],
    # Hash cracking
    "hashcat": ["password_cracked", "has_cred"],
    "john": ["password_cracked", "has_cred"],
    # Web exploitation → shell or info
    "sqli": ["sqli_confirmed", "database_access"],
    "sqli_union": ["data_dumped", "has_cred"],
    "sqli_blind": ["data_extracted"],
    "sqli_stacked": ["rce_achieved", "shell_obtained"],
    "sqlmap": ["sqli_confirmed", "data_dumped", "has_cred"],
    "nosqli": ["nosqli_confirmed", "auth_bypassed"],
    "ssti": ["ssti_confirmed", "rce_achieved", "shell_obtained"],
    "xss": ["xss_confirmed"],
    "lfi": ["file_read", "config_leaked"],
    "path_traversal": ["file_read", "config_leaked"],
    "rfi": ["rce_achieved", "shell_obtained"],
    "ssrf": ["ssrf_confirmed", "internal_service_accessed"],
    "xxe": ["file_read", "xxe_confirmed"],
    "command_injection": ["rce_achieved", "shell_obtained"],
    "rce_": ["rce_achieved", "shell_obtained"],
    "deserialization": ["rce_achieved", "shell_obtained"],
    "insecure_deserialization": ["rce_achieved", "shell_obtained"],
    "file_upload": ["webshell_uploaded", "rce_achieved"],
    "insecure_upload": ["webshell_uploaded", "rce_achieved"],
    "log_poisoning": ["rce_achieved", "shell_obtained"],
    "php_filter": ["file_read", "config_leaked"],
    "php_object": ["rce_achieved", "shell_obtained"],
    "jwt": ["auth_bypassed", "privilege_escalated"],
    "idor": ["idor_confirmed", "data_accessed"],
    "cors": ["cors_misconfigured"],
    "csrf": ["csrf_confirmed"],
    "open_redirect": ["redirect_abused"],
    "graphql": ["graphql_enumerated"],
    "race_condition": ["race_exploited"],
    "oauth": ["oauth_flawed", "auth_bypassed"],
    "saml": ["saml_flawed", "auth_bypassed"],
    "mass_assignment": ["mass_assignment_confirmed", "privilege_escalated"],
    "prototype_pollution": ["pp_confirmed", "rce_achieved"],
    "request_smuggling": ["request_smuggled"],
    "waf_bypass": ["waf_bypassed"],
    "subdomain_takeover": ["subdomain_hijacked"],
    "log4shell": ["rce_achieved", "shell_obtained"],
    "struts_rce": ["rce_achieved", "shell_obtained"],
    "spring_boot": ["config_leaked", "rce_achieved"],
    "laravel_debug": ["rce_achieved", "config_leaked"],
    "django_debug": ["config_leaked"],
    "confluence": ["rce_achieved", "shell_obtained"],
    "phpmyadmin": ["rce_achieved", "shell_obtained"],
    "weblogic": ["rce_achieved", "shell_obtained"],
    "activemq": ["rce_achieved", "shell_obtained"],
    "solr": ["rce_achieved", "shell_obtained"],
    "grafana": ["file_read", "config_leaked"],
    "gitea": ["rce_achieved"],
    "magento": ["rce_achieved"],
    "splunk": ["rce_achieved"],
    "apache_rce": ["rce_achieved", "shell_obtained"],
    "ajp_ghostcat": ["file_read", "config_leaked"],
    "iis_shortname": ["files_enumerated"],
    "shellshock": ["rce_achieved", "shell_obtained"],
    "cgi_shellshock": ["rce_achieved", "shell_obtained"],
    "git_dump": ["source_code_leaked", "has_cred"],
    "api_key": ["api_keys_leaked", "has_cred"],
    "header_injection": ["header_injection_confirmed"],
    "type_juggling": ["auth_bypassed"],
    "auth_bypass": ["auth_bypassed", "session_obtained"],
    "webdav": ["file_uploaded"],
    "http_smuggling": ["request_smuggled"],
    "cache_poisoning": ["cache_poisoned"],
    "host_header": ["host_header_abused"],
    "crlf": ["crlf_confirmed"],
    # Privesc — Linux
    "suid": ["suid_exploited", "root_shell"],
    "capabilities": ["capability_exploited", "root_shell"],
    "cron_": ["cron_exploited", "root_shell"],
    "sudo_": ["sudo_exploited", "root_shell"],
    "sudoers": ["sudo_exploited", "root_shell"],
    "kernel_": ["kernel_exploit_used", "root_shell"],
    "docker_privesc": ["docker_escape", "root_shell"],
    "lxd_privesc": ["lxd_escape", "root_shell"],
    "writable_": ["writable_exploited", "root_shell"],
    "pkexec": ["pkexec_exploited", "root_shell"],
    "polkit": ["polkit_exploited", "root_shell"],
    "dbus_exploit": ["dbus_exploited", "root_shell"],
    "logrotate": ["logrotate_exploited", "root_shell"],
    "sambacry": ["sambacry_exploited", "root_shell"],
    "passwd_write": ["passwd_modified", "root_shell"],
    "pspy": ["processes_monitored", "cron_found"],
    "gtfobins": ["gtfobin_used", "root_shell"],
    "path_hijack": ["path_hijacked", "root_shell"],
    "env_variable": ["env_abused", "root_shell"],
    "apt_get": ["apt_abused", "root_shell"],
    "npm_privesc": ["npm_abused", "root_shell"],
    "pip_install": ["pip_abused", "root_shell"],
    "python_library": ["python_lib_hijacked", "root_shell"],
    "shared_library": ["library_hijacked", "root_shell"],
    "snap_exploit": ["snap_exploited", "root_shell"],
    "systemd_timer": ["timer_abused", "root_shell"],
    "wildcard_injection": ["wildcard_exploited", "root_shell"],
    "rbash_escape": ["shell_escaped"],
    "linpeas": ["privesc_vectors_enumerated"],
    # Privesc — Windows
    "potato": ["potato_exploited", "system_shell"],
    "printspoofer": ["printspoofer_used", "system_shell"],
    "efspotato": ["potato_exploited", "system_shell"],
    "godpotato": ["potato_exploited", "system_shell"],
    "juicypotato": ["potato_exploited", "system_shell"],
    "dll_hijack": ["dll_hijacked", "system_shell"],
    "always_install": ["msi_abused", "system_shell"],
    "backup_operators": ["backup_abused", "system_shell"],
    "unquoted_service": ["unquoted_exploited", "system_shell"],
    "seimpersonate": ["impersonate_used", "system_shell"],
    "sebackup": ["backup_priv_used", "file_read"],
    "serestore": ["restore_priv_used"],
    "setakeownership": ["ownership_taken"],
    "service_exploit": ["service_exploited", "system_shell"],
    "service_file_overwrite": ["service_hijacked", "system_shell"],
    "scheduled_task": ["task_abused", "system_shell"],
    "registry_autorun": ["autorun_abused", "system_shell"],
    "runas_savecred": ["savecred_abused"],
    "token_manipulation": ["token_stolen", "system_shell"],
    "printnightmare": ["printnightmare_exploited", "system_shell"],
    "winpeas": ["privesc_vectors_enumerated"],
    # Pivoting
    "chisel": ["pivot_established"],
    "ligolo": ["pivot_established"],
    "proxychains": ["pivot_established"],
    "ssh_tunnel": ["pivot_established"],
    "port_forward": ["pivot_established"],
    "double_pivot": ["pivot_established"],
    "tunnel": ["pivot_established"],
    "proxy_check": ["proxy_validated"],
    # Services — enumeration/exploitation
    "ssh_": ["ssh_tested"],
    "ftp_": ["ftp_tested"],
    "ftp_anon": ["ftp_anonymous_access", "has_files"],
    "mysql": ["mysql_access", "has_cred"],
    "mssql": ["mssql_access", "has_cred"],
    "postgres": ["postgres_access", "has_cred"],
    "redis": ["redis_access", "rce_achieved"],
    "mongodb": ["mongodb_access"],
    "cassandra": ["cassandra_access"],
    "elasticsearch": ["elastic_access", "data_access"],
    "memcached": ["memcached_access"],
    "snmp": ["snmp_info_gathered"],
    "smtp": ["smtp_tested", "has_users"],
    "pop3": ["pop3_tested"],
    "imap": ["imap_tested"],
    "ipmi": ["ipmi_tested", "has_hash"],
    "nfs_": ["nfs_shares_found"],
    "rpc_": ["rpc_info_gathered"],
    "rdp": ["rdp_tested"],
    "vnc": ["vnc_tested"],
    "tomcat": ["tomcat_access", "rce_achieved"],
    "jenkins": ["jenkins_access", "rce_achieved"],
    "java_rmi": ["rmi_exploited", "rce_achieved"],
    "proftpd": ["proftpd_exploited"],
    "rsync": ["rsync_tested"],
    "docker_": ["docker_tested"],
    "kubernetes": ["k8s_tested"],
    "netcat": ["connection_made"],
    "curl_request": ["http_response_captured"],
    # Shell operations
    "file_download": ["file_downloaded"],
    "http_server": ["http_server_started"],
    "metasploit": ["exploit_attempted"],
    # CMS/web additions
    "file_read_exploitation": ["file_read", "config_leaked"],
    "template_engine_detect": ["template_engine_fingerprinted"],
    # OCD mindmap additions (v2.1)
    "sccm_find": ["sccm_infrastructure_mapped", "sccm_site_code_found", "sccm_mp_identified", "sccm_dp_identified"],
    "sccm_pxe_hashcap": ["pxe_hash_captured", "sccm_naa_ciphertext_obtained", "has_hash"],
    "sccm_naa_extract": ["sccm_naa_obtained", "naa_extracted", "has_cred"],
    "sccm_admin_enum": ["sccm_admins_enumerated", "sccm_full_admin_list"],
    "sccm_client_push": ["netntlmv2_hash_captured", "sccm_client_push_coerced", "has_hash"],
    "sccm_http_looter": ["sccm_scripts_exfiltrated", "sccm_collection_vars_obtained", "has_cred"],
    "sccm_mssql_relay": ["sccm_site_db_sysadmin", "sccm_takeover_complete", "sccm_admin"],
    "sccm_device_enum": ["sccm_devices_enumerated", "sccm_collection_map_obtained"],
    "certifried": ["computer_cert_obtained", "dc_certificate_obtained", "domain_admin"],
    "skeleton_key": ["skeleton_key_installed", "universal_backdoor", "domain_persistence"],
    "custom_ssp": ["custom_ssp_installed", "credential_logging_active", "domain_persistence"],
    "dc_shadow": ["replication_writeable", "domain_admin", "domain_persistence"],
    "dsrm_password": ["dsrm_password_set", "local_admin_on_dc", "domain_persistence"],
    "saphire_ticket": ["saphire_ticket_forged", "sid_injected", "domain_admin"],
    "blind_kerberoast": ["spn_tgs_blind_obtained", "has_hash"],
    "nopac": ["domain_admin_session", "nopac_exploited", "has_cred"],
    "privexchange": ["exchange_machine_coerced", "ldap_relay_success", "dcsync_right_granted", "has_cred"],
    "dnsadmins": ["dns_server_rce", "system_shell", "domain_admin"],
    "adcs_esc9": ["certificate_obtained", "upn_reverted", "domain_admin_session", "has_cred"],
    "adcs_esc10": ["certificate_obtained", "domain_admin_session", "has_cred"],
    "adcs_esc13": ["certificate_obtained", "privileged_group_membership", "has_cred"],
    "adcs_esc14": ["cert_alt_identity_set", "victim_auth_as_attacker_cert"],
    "adcs_esc15": ["certificate_obtained", "domain_admin_session", "has_cred"],
    "passthecert": ["cert_auth_success", "ldap_schannel_session", "has_cred"],
    "krbrelayup": ["rbcd_written_via_relay", "local_system_domain_joined", "system_shell"],
    "trust_key_extract": ["trust_key_extracted", "trust_key_used", "inter_forest_pivot_ready"],
    "trust_ticket_forge": ["inter_realm_tgt_forged", "cross_forest_access", "forest_admin"],
    "msol_password": ["msol_account_obtained", "msol_obtained", "dcsync_right_granted", "has_cred"],
    "keepass_dump": ["keepass_master_password_leaked", "has_cred"],
    "targetedkerberoast": ["spn_written", "tgs_hashes_obtained", "has_hash"],
    "timeroast": ["machine_account_hash_captured", "has_hash"],
    "goldenpac_ms14068": ["domain_admin_session", "pac_forged", "has_cred"],
    "gpp_password": ["gpp_cpassword_decrypted", "has_cred"],
    # Privesc additions
    "remotepotato0": ["cross_session_token_obtained", "netntlmv2_hash_captured", "has_hash"],
    "roguepotato": ["system_shell", "root_access"],
    "uac_bypass": ["uac_bypassed", "high_integrity_shell", "admin_context"],
    "applocker_bypass": ["applocker_bypassed", "arbitrary_code_execution"],
    "serioussam": ["sam_hashes_obtained", "local_admin_hash", "has_hash"],
    "smbghost": ["system_shell", "rce_achieved"],
    # Services / quick wins
    "eternalblue": ["system_shell", "rce_achieved", "shell_obtained"],
    "veeam_cve2024_40711": ["veeam_rce", "system_shell", "has_cred"],
    "veeam_cve2023_27532": ["veeam_credentials_dumped", "service_account_password", "has_cred"],
    "mitm6": ["ipv6_dns_takeover_active", "netntlmv2_hash_captured", "has_hash"],
    "ntlm_theft_file_drop": ["ntlm_bait_planted", "netntlmv2_hash_captured"],
    # Creds additions
    "lsass_procdump": ["lsass_dump_obtained", "ntlm_hashes_obtained", "tgt_material_obtained", "has_hash"],
    "lsass_comsvcs": ["lsass_dump_obtained", "ntlm_hashes_obtained", "has_hash"],
    "mscache2_dump": ["mscache2_hashes_obtained", "offline_crack_seed", "has_hash"],
    "dpapi_masterkey": ["dpapi_masterkey_decrypted", "browser_creds_decryptable", "cert_private_keys_decryptable", "has_cred"],
    "sam_offline_dump": ["local_admin_nthash", "has_hash"],
    # Perception gap fixes (v2.2)
    "playwright_screenshot": ["web_visual_captured", "web_recon_done"],
    "playwright_crawl": ["web_visual_captured", "dom_xss_sink_present", "login_form_found", "spa_routes_discovered", "auth_endpoint_known", "honeypot_detected", "js_secret_exposed"],
    "timing_probe": ["timebased_injection_confirmed", "timing_differential_marginal", "timing_anomaly_detected"],
    "js_secrets_scan": ["js_secret_exposed", "web_recon_done"],
    "honeypot_detect": ["honeypot_detected", "target_fingerprinted"],
    # Cloud — AWS (v2.3)
    "aws_iam_enum": ["aws_iam_enumerated", "cloud_identity_known", "aws_roles_discovered"],
    "aws_s3_enum": ["s3_buckets_discovered", "cloud_data_exposed"],
    "aws_ec2_metadata": ["aws_instance_role_creds_obtained", "cloud.aws_creds_available", "aws_access_key_found"],
    "aws_sts_assume": ["aws_role_assumed", "cloud_privilege_escalated", "aws_creds_upgraded"],
    "aws_lambda_enum": ["lambda_functions_discovered", "cloud_secrets_exposed"],
    # Cloud — Azure (v2.3)
    "azure_aad_enum": ["azure_ad_enumerated", "azure_users_discovered", "azure_roles_known"],
    "azure_managed_identity": ["azure_managed_identity_token_obtained", "cloud.azure_token_available", "cloud_privilege_escalated"],
    "azure_storage_enum": ["azure_storage_enumerated", "cloud_data_exposed"],
    # Cloud — GCP (v2.3)
    "gcp_metadata": ["gcp_metadata_obtained", "gcp_service_account_token", "cloud.gcp_token_available"],
    "gcp_sa_impersonate": ["gcp_service_accounts_enumerated", "cloud_privilege_escalated"],
    # JWT deep library (v2.3)
    "jwt_alg_confusion": ["jwt_forged", "auth_bypass_achieved", "privilege_escalated"],
    "jwt_jwk_injection": ["jwt_forged", "auth_bypass_achieved"],
    "jwt_jku_abuse": ["jwt_forged", "auth_bypass_achieved"],
    "jwt_kid_sqli": ["jwt_forged", "auth_bypass_achieved"],
    "jwt_sig_strip": ["jwt_forged", "auth_bypass_achieved"],
}


def infer_effects(action: dict) -> list:
    """Infer effects for an action based on name and category."""
    name = action.get("name", "")
    for pattern, effects in EFFECT_RULES.items():
        if pattern in name:
            return effects
    return None


def enrich_file(yml_path: Path, dry_run: bool = True) -> dict:
    """Enrich one YAML's expected_effects if currently generic."""
    try:
        content = yml_path.read_text()
        data = yaml.safe_load(content)
        if not data or "name" not in data:
            return {}
    except Exception:
        return {}

    current = data.get("expected_effects", []) or []

    # Only replace if current is generic or empty
    if current and current != ["action_completed"] and "action_completed" not in current:
        # Already has meaningful effects
        return {}

    new_effects = infer_effects(data)
    if not new_effects:
        return {}

    if not dry_run:
        data["expected_effects"] = new_effects
        with open(yml_path, "w") as f:
            yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)

    return {
        "file": str(yml_path),
        "name": data["name"],
        "before": current,
        "after": new_effects,
    }


def main():
    parser = argparse.ArgumentParser(description="Enrich action YAML effects")
    parser.add_argument("--dry-run", action="store_true", default=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--category")
    args = parser.parse_args()

    dry_run = not args.apply

    changes = []
    for p in sorted(ACTIONS_DIR.rglob("*.yml")):
        if args.category and args.category not in str(p):
            continue
        change = enrich_file(p, dry_run=dry_run)
        if change:
            changes.append(change)

    print(f"{'[DRY-RUN]' if dry_run else '[APPLIED]'} {len(changes)} actions enriched with effects")
    if dry_run and changes:
        print("\nSample (first 5):")
        for c in changes[:5]:
            print(f"  {c['name']}: {c['before']} → {c['after']}")


if __name__ == "__main__":
    main()
