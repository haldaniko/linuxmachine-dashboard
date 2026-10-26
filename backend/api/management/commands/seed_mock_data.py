import os
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from api.models import (
    AccessControlRule,
    AccessPolicy,
    Alert,
    CorrelationRule,
    EDREndpoint,
    EDREvent,
    EDRPolicy,
    EDRThreat,
    EDRVulnerability,
    EndpointAsset,
    FirewallRule,
    IPSAlert,
    IPSCustomRule,
    IPSRule,
    IPSRuleCategory,
    LogEntry,
    LogSource,
    ModuleSetting,
    SecurityComponent,
    SecurityEvent,
    WebFilterRule,
)


DATA_TAG = "ledgerlab-accounting-v1"
LEGACY_TAG = "bg-office-soc"

COMPONENTS = {
    "firewall": ("Firewall", "firewall"),
    "ips": ("IPS", "ips"),
    "edr": ("EDR", "edr"),
    "web-filter": ("Web Filter", "web_filter"),
    "access": ("IAM / MFA", "access"),
    "siem": ("SIEM", "siem"),
}

LEGACY_NAMES = {
    "office-egress",
    "dns-allow",
    "admin-vpn",
    "customer-portal",
    "mail-relay",
    "temporary-rdp-block",
    "Allow Microsoft 365",
    "Block new domains",
    "Review file sharing",
    "Block anonymizers",
    "Admins MFA",
    "Employees VPN",
    "Contractors restricted",
    "Guest deny",
    "Allow HTTPS към клиентски портал Plameli",
    "Block SSH към вътрешната мрежа от интернет",
    "Allow VPN администратори към сървърния VLAN",
    "Block директен SMTP от работни станции",
    "Reject RDP от складовия Wi-Fi",
    "Block фалшив вход към ePay",
    "Block домейни за фалшиви фактури",
    "Review анонимизиращи proxy услуги",
    "Allow GitLab за разработчици",
    "Администратори само с MFA",
    "VPN служители с потвърден MFA",
    "Блокирай гост достъп до ERP",
    "SQL injection към клиентски портал",
    "Encoded PowerShell при счетоводство",
    "Nmap сканиране към DMZ",
    "Подозрителен SMB lateral movement",
}


class Command(BaseCommand):
    help = "Seed a realistic, non-adversarial LedgerLab accounting-office dataset."

    @transaction.atomic
    def handle(self, *args, **options):
        self.now = timezone.now()
        self.components = self._ensure_components()
        self._cleanup_previous_seed()
        self._seed_users()
        self._seed_module_settings()
        self._seed_firewall_rules()
        self._seed_ips()
        endpoints = self._seed_edr()
        self._seed_web_and_access_rules()
        security_events = self._seed_security_events()
        self._seed_siem(security_events)
        self._seed_assets_and_policies(endpoints)
        self._update_components()

        self.stdout.write(
            self.style.SUCCESS(
                "LedgerLab dataset ready: 12 endpoints, 9 network rules, "
                "8 operational events, 6 log sources."
            )
        )

    def _ensure_components(self):
        components = {}
        for key, (name, category) in COMPONENTS.items():
            component, _ = SecurityComponent.objects.get_or_create(
                key=key,
                defaults={"name": name, "category": category, "description": "LedgerLab security control"},
            )
            components[key] = component
        return components

    def _cleanup_previous_seed(self):
        for tag in (DATA_TAG, LEGACY_TAG):
            Alert.objects.filter(event__extra_data__seed=tag).delete()
            LogEntry.objects.filter(parsed__seed=tag).delete()
            IPSAlert.objects.filter(raw_event__seed=tag).delete()
            EDREvent.objects.filter(raw_event__seed=tag).delete()
            SecurityEvent.objects.filter(extra_data__seed=tag).delete()

        FirewallRule.objects.filter(name__in=LEGACY_NAMES).delete()
        IPSRule.objects.filter(name__in=LEGACY_NAMES).delete()
        WebFilterRule.objects.filter(name__in=LEGACY_NAMES).delete()
        AccessControlRule.objects.filter(name__in=LEGACY_NAMES).delete()
        IPSCustomRule.objects.filter(sid__in=[1002401, 1004201, 1004202]).delete()
        EDREndpoint.objects.filter(external_id__startswith="ledgerlab-").delete()
        EDREndpoint.objects.filter(external_id__startswith="plameli-").delete()

        new_names = self._all_seed_names()
        FirewallRule.objects.filter(name__in=new_names).delete()
        IPSRule.objects.filter(name__in=new_names).delete()
        WebFilterRule.objects.filter(name__in=new_names).delete()
        AccessControlRule.objects.filter(name__in=new_names).delete()
        EDRPolicy.objects.filter(name__in=["LedgerLab standard endpoint policy", "Bulgarian office baseline"]).delete()
        EndpointAsset.objects.filter(name__startswith="LL-").delete()
        AccessPolicy.objects.filter(name__in=new_names).delete()
        CorrelationRule.objects.filter(name__in=new_names).delete()

        for old_source in ["Edge firewall", "Windows servers", "VPN gateway", "EDR agent"]:
            LogSource.objects.filter(name=old_source).delete()

        get_user_model().objects.filter(
            username__in=[
                "operator",
                "analyst",
                "stoian.ivanov",
                "maria.georgieva",
                "petar.dimitrov",
                "elena.koleva",
                "security.admin",
                "it.operations",
                "compliance.viewer",
                "accounting.lead",
                "payroll.lead",
            ]
        ).delete()

    @staticmethod
    def _all_seed_names():
        return {
            "Guest network isolation",
            "Public client portal HTTPS",
            "Corporate DNS to resolver",
            "Workstations to SMTP relay",
            "Accounting workstations to file services",
            "VPN staff to document portal",
            "IT administrators to management SSH",
            "IT administrators to Windows management",
            "Block direct SMTP from user networks",
            "Cleartext access to client portal",
            "External DNS resolver use",
            "LedgerLab corporate services",
            "Microsoft 365 business services",
            "Bulgarian public administration",
            "Accounting software updates",
            "Review personal cloud storage",
            "Restrict public paste services",
            "IT administrators via VPN",
            "Accounting staff via VPN",
            "Payroll staff via VPN",
            "Office staff on managed network",
            "Compliance read-only access",
            "Contractor privileged access",
            "Guest network application access",
            "MFA prompt fatigue indicator",
            "Backup completion control",
            "Large document export",
            "Privileged group membership change",
            "Corporate SaaS allow-list",
            "Personal storage review",
            "Public paste services restriction",
        }

    def _seed_users(self):
        User = get_user_model()
        admin = User.objects.filter(username="admin").first()
        if admin:
            admin.email = "admin@ledgerlab.tech"
            admin.first_name = "System"
            admin.last_name = "Administrator"
            admin.save(update_fields=["email", "first_name", "last_name"])

        password = os.environ.get("SEED_USER_PASSWORD")
        users = [
            ("security.admin", "security.admin@ledgerlab.tech", "Security", "Administrator", True),
            ("it.operations", "it.operations@ledgerlab.tech", "IT", "Operations", True),
            ("compliance.viewer", "compliance@ledgerlab.tech", "Compliance", "Viewer", False),
            ("accounting.lead", "accounting@ledgerlab.tech", "Accounting", "Lead", False),
            ("payroll.lead", "payroll@ledgerlab.tech", "Payroll", "Lead", False),
        ]
        for username, email, first_name, last_name, is_staff in users:
            user = User.objects.create_user(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name,
                is_staff=is_staff,
                is_active=True,
            )
            if password:
                user.set_password(password)
            else:
                user.set_unusable_password()
            user.save(update_fields=["password"])

    def _seed_module_settings(self):
        records = {
            "firewall": {
                "display_name": "LedgerLab edge and segment firewall",
                "mode": "enforce",
                "settings": {
                    "default_action": "block",
                    "logging": True,
                    "rate_limit": 2500,
                    "deployment": "Sofia office edge",
                    "last_applied_at": None,
                    "applied_rule_ids": [],
                },
                "notes": "Segmentation for servers, office users, guest Wi-Fi, management and remote access.",
            },
            "ips": {
                "display_name": "Network detection and protocol monitoring",
                "mode": "monitor",
                "settings": {"engine": "Suricata", "profile": "balanced", "interface": "eth0", "ruleset": "ET Open"},
                "notes": "Operational protocol and policy detections; blocking requires review.",
            },
            "edr": {
                "display_name": "Endpoint security and compliance",
                "mode": "enforce",
                "settings": {
                    "provider": "Wazuh",
                    "manager_url": "https://wazuh.ledgerlab.tech:55000",
                    "inventory_interval_minutes": 30,
                    "retention_days": 180,
                },
                "notes": "Windows workstations and Linux servers used for accounting, payroll and document exchange.",
            },
            "web_filter": {
                "display_name": "Business web access policy",
                "mode": "enforce",
                "settings": {"default_action": "allow", "safe_search": True, "log_allowed": False, "retention_days": 90},
                "notes": "Business services remain available; external file sharing is routed for review.",
            },
            "access": {
                "display_name": "Identity, remote access and MFA",
                "mode": "enforce",
                "settings": {"default_action": "deny", "mfa_provider": "Microsoft Entra ID", "session_minutes": 480},
                "notes": "Role-based access for accounting, payroll, compliance and IT administration.",
            },
            "siem": {
                "display_name": "Central audit and operational monitoring",
                "mode": "monitor",
                "settings": {"retention_days": 365, "timezone": "Europe/Sofia", "daily_review": "09:00"},
                "notes": "Audit trail for identity, file access, business systems, backups and network policy.",
            },
        }
        for key, values in records.items():
            ModuleSetting.objects.update_or_create(key=key, defaults={"enabled": True, **values})

    def _seed_firewall_rules(self):
        rows = [
            (10, "Guest network isolation", "block", "any", "any", "10.42.50.0/24", "any", "10.42.0.0/16", "any", 184, "Guest Wi-Fi cannot reach corporate address space."),
            (20, "Public client portal HTTPS", "allow", "inbound", "tcp", "any", "any", "10.42.20.20/32", "443", 28431, "TLS access to the customer document portal."),
            (30, "Corporate DNS to resolver", "allow", "outbound", "udp", "10.42.0.0/16", "any", "10.42.20.10/32", "53", 42890, "Corporate segments use the managed DNS resolver."),
            (40, "Workstations to SMTP relay", "allow", "outbound", "tcp", "10.42.30.0/24", "any", "10.42.20.25/32", "587", 6821, "Authenticated scanner and application mail relay."),
            (50, "Accounting workstations to file services", "allow", "any", "tcp", "10.42.30.0/24", "any", "10.42.20.12/32", "445", 18922, "Managed accounting workstations access the document share."),
            (60, "VPN staff to document portal", "allow", "inbound", "tcp", "10.42.80.0/24", "any", "10.42.20.20/32", "443", 3074, "Remote staff access the internal portal after MFA."),
            (70, "IT administrators to management SSH", "allow", "inbound", "tcp", "10.42.80.0/24", "any", "10.42.70.0/24", "22", 438, "Administrative SSH from the managed VPN segment."),
            (80, "IT administrators to Windows management", "allow", "inbound", "tcp", "10.42.80.0/24", "any", "10.42.70.0/24", "3389", 216, "Windows administration from the managed VPN segment."),
            (90, "Block direct SMTP from user networks", "block", "outbound", "tcp", "10.42.30.0/24", "any", "any", "25", 7, "Mail must pass through smtp-relay.ledgerlab.tech."),
        ]
        for priority, name, action, direction, protocol, src, sport, dst, dport, hits, description in rows:
            FirewallRule.objects.create(
                priority=priority, name=name, enabled=True, action=action, direction=direction, protocol=protocol,
                source_cidr=src, source_port=sport, destination_cidr=dst, destination_port=dport,
                hit_count=hits, last_matched=self.now - timedelta(minutes=max(2, priority)), description=description,
            )

    def _seed_ips(self):
        categories = [
            ("Protocol anomalies", 684, "Malformed or inconsistent network protocol behavior."),
            ("TLS policy", 312, "Certificate, cipher and TLS version policy checks."),
            ("DNS policy", 221, "Resolver usage and DNS protocol policy."),
            ("HTTP policy", 476, "Cleartext HTTP and application protocol policy."),
            ("Informational", 938, "Context-rich observations that do not indicate compromise."),
        ]
        for name, count, description in categories:
            IPSRuleCategory.objects.update_or_create(name=name, defaults={"enabled": True, "rule_count": count, "description": description})

        rules = [
            (20, "Cleartext access to client portal", "url", "portal.ledgerlab.tech", "alert", "medium", 3, "Detect requests that should be redirected to HTTPS."),
            (30, "External DNS resolver use", "message", "external dns", "alert", "low", 6, "Review devices bypassing the managed resolver."),
        ]
        for priority, name, field, pattern, action, severity, hits, description in rules:
            IPSRule.objects.create(priority=priority, name=name, match_field=field, pattern=pattern, action=action, severity=severity, hit_count=hits, last_matched=self.now - timedelta(days=1), description=description)

        IPSCustomRule.objects.create(
            name="LedgerLab cleartext portal request",
            sid=1004201,
            raw_rule='alert http $HOME_NET any -> 10.42.20.20 any (msg:"LEDGERLAB HTTP request to client portal"; flow:to_server,established; http.host; content:"portal.ledgerlab.tech"; nocase; sid:1004201; rev:1;)',
            enabled=True,
        )

        alerts = [
            ("informational", "Microsoft Teams STUN session observed", 2016149, "Business application traffic", "10.42.30.41", 53318, "52.112.64.18", 3478, "udp", "allowed", 3),
            ("low", "Managed endpoint queried an external DNS resolver", 1004202, "DNS policy", "10.42.30.46", 53804, "1.1.1.1", 53, "udp", "alert", 21),
            ("medium", "HTTP request redirected to the TLS client portal", 1004201, "HTTP policy", "10.42.40.22", 51226, "10.42.20.20", 80, "tcp", "alert", 46),
            ("low", "TCP stream timestamp outside expected window", 2210054, "Protocol anomalies", "10.42.20.14", 443, "10.42.20.12", 49512, "tcp", "alert", 125),
        ]
        for idx, row in enumerate(alerts):
            severity, signature, sid, category, src, sport, dst, dport, protocol, action, minutes = row
            IPSAlert.objects.create(
                timestamp=self.now - timedelta(minutes=minutes), severity=severity, signature=signature,
                signature_id=sid, category=category, source_ip=src, source_port=sport,
                destination_ip=dst, destination_port=dport, protocol=protocol, action=action,
                interface="eth0", direction="to_server", event_hash=f"ledgerlab-ips-{idx}",
                raw_event={"seed": DATA_TAG, "environment": "production", "site": "sofia"},
            )

    def _seed_edr(self):
        EDRPolicy.objects.create(
            name="LedgerLab standard endpoint policy", enabled=True, telemetry_level="standard",
            block_usb=True, block_script_interpreters=False, quarantine_on_malware=True,
            protected_paths="C:\\Windows\\System32\nC:\\ProgramData\\LedgerLab\n/srv/accounting\n/srv/client-documents",
        )
        rows = [
            ("dc-sf-01", "10.42.20.10", "Windows Server", "2022", "SYSTEM", "protected", 2),
            ("files-sf-01", "10.42.20.12", "Ubuntu Server", "22.04 LTS", "svc-files", "attention", 4),
            ("acct-db-01", "10.42.20.13", "Ubuntu Server", "24.04 LTS", "postgres", "protected", 3),
            ("backup-sf-01", "10.42.20.14", "Ubuntu Server", "22.04 LTS", "svc-backup", "protected", 6),
            ("wazuh-sf-01", "10.42.20.15", "Ubuntu Server", "24.04 LTS", "wazuh", "protected", 1),
            ("portal-web-01", "10.42.20.20", "Ubuntu Server", "24.04 LTS", "www-data", "protected", 1),
            ("acc-ws-01", "10.42.30.41", "Windows 11 Pro", "24H2", "accounting.lead", "protected", 8),
            ("acc-ws-02", "10.42.30.42", "Windows 11 Pro", "24H2", "accounting.user", "protected", 11),
            ("pay-ws-01", "10.42.30.43", "Windows 11 Pro", "24H2", "payroll.lead", "attention", 18),
            ("tax-lt-01", "10.42.30.44", "Windows 11 Pro", "24H2", "tax.consultant", "protected", 9),
            ("mgr-lt-01", "10.42.30.45", "Windows 11 Pro", "24H2", "management", "protected", 7),
            ("reception-ws-01", "10.42.30.46", "Windows 11 Pro", "23H2", "client.services", "attention", 22),
        ]
        endpoints = {}
        for idx, (hostname, ip, os_name, version, username, security_status, minutes) in enumerate(rows, start=1):
            endpoint = EDREndpoint.objects.create(
                external_id=f"ledgerlab-{idx:03d}", hostname=hostname, ip=ip, os=os_name, os_version=version,
                architecture="x86_64", agent_version="4.9.2", agent_id=f"ll-{idx:03d}", status="online",
                security_status=security_status, provider="wazuh", logged_in_user=username,
                last_seen=self.now - timedelta(minutes=minutes), first_seen=self.now - timedelta(days=410 - idx),
            )
            endpoints[hostname] = endpoint

        event_rows = [
            ("dc-sf-01", "configuration", "identity", "informational", "Directory policy synchronized", "The scheduled identity and MFA policy synchronization completed.", "svchost.exe", "completed", 8),
            ("files-sf-01", "package_inventory", "vulnerability", "medium", "OpenSSH maintenance update scheduled", "The approved OpenSSH update is queued for the Sunday maintenance window.", "apt.systemd.daily", "review", 34),
            ("acct-db-01", "service_health", "database", "informational", "Nightly database maintenance completed", "Statistics refresh and integrity checks completed without errors.", "postgres", "completed", 66),
            ("backup-sf-01", "backup", "availability", "informational", "Encrypted backup verified", "The nightly backup and sample restore verification completed successfully.", "restic", "completed", 91),
            ("pay-ws-01", "patching", "compliance", "medium", "Restart pending after security updates", "A restart is required outside the payroll processing window.", "TiWorker.exe", "review", 143),
            ("tax-lt-01", "software_install", "change", "low", "Approved tax client update installed", "The signed vendor package was installed from the managed software repository.", "msiexec.exe", "completed", 211),
            ("reception-ws-01", "network_policy", "compliance", "low", "External DNS setting corrected", "The endpoint returned to the managed DNS resolver after a network profile refresh.", "svchost.exe", "remediated", 248),
            ("mgr-lt-01", "device_control", "policy", "medium", "Removable storage blocked by policy", "A USB storage device was denied; no files were transferred.", "System", "blocked", 390),
        ]
        created_events = []
        for idx, row in enumerate(event_rows):
            hostname, event_type, category, severity, title, description, process, action, minutes = row
            created_events.append(
                EDREvent.objects.create(
                    timestamp=self.now - timedelta(minutes=minutes), endpoint=endpoints[hostname], event_type=event_type,
                    category=category, severity=severity, title=title, description=description,
                    process_name=process, username=endpoints[hostname].logged_in_user, action=action,
                    source="wazuh", raw_event={"seed": DATA_TAG, "control": category, "site": "sofia"},
                )
            )

        EDRThreat.objects.create(
            event=created_events[4], endpoint=endpoints["pay-ws-01"], title="Pending restart beyond maintenance target",
            category="patch_compliance", severity="medium", status="investigating",
        )
        EDRThreat.objects.create(
            event=created_events[7], endpoint=endpoints["mgr-lt-01"], title="USB policy enforcement review",
            category="device_control", severity="medium", status="resolved",
        )

        vulnerabilities = [
            ("files-sf-01", "CVE-2024-6387", "openssh-server", "1:8.9p1-3ubuntu0.7", "1:8.9p1-3ubuntu0.10", "medium", "open"),
            ("pay-ws-01", "CVE-2025-21298", "Microsoft Windows", "Windows 11 24H2", "KB5050009", "high", "resolved"),
            ("mgr-lt-01", "CVE-2023-4863", "Google Chrome", "116.0.5845.179", "116.0.5845.187", "high", "resolved"),
        ]
        for hostname, cve, package, installed, fixed, severity, status in vulnerabilities:
            EDRVulnerability.objects.create(
                endpoint=endpoints[hostname], cve=cve, package=package, installed_version=installed,
                fixed_version=fixed, severity=severity, status=status,
            )
        return endpoints

    def _seed_web_and_access_rules(self):
        web_rules = [
            (10, "LedgerLab corporate services", "domain", "ledgerlab.tech", "Corporate", "allow", 21840),
            (20, "Microsoft 365 business services", "domain", "office.com", "Productivity", "allow", 17638),
            (30, "Bulgarian public administration", "regex", r"(^|\\.)(nra|nssi|registryagency)\\.bg$", "Public administration", "allow", 6942),
            (40, "Accounting software updates", "domain", "microinvest.net", "Business software", "allow", 1142),
            (80, "Review personal cloud storage", "regex", r"(^|\\.)(dropbox|wetransfer)\\.com$", "External file sharing", "review", 37),
            (90, "Restrict public paste services", "domain", "pastebin.com", "Public content sharing", "block", 4),
        ]
        for priority, name, match_type, pattern, category, action, hits in web_rules:
            WebFilterRule.objects.create(
                priority=priority, name=name, match_type=match_type, pattern=pattern, category=category,
                action=action, hit_count=hits, last_matched=self.now - timedelta(minutes=priority + 3),
            )

        access_rules = [
            (10, "IT administrators via VPN", "vpn", "it-admins", True, "allow", 284),
            (20, "Accounting staff via VPN", "vpn", "accounting", True, "allow", 1261),
            (30, "Payroll staff via VPN", "vpn", "payroll", True, "allow", 346),
            (40, "Office staff on managed network", "wired", "employees", False, "allow", 6822),
            (50, "Compliance read-only access", "any", "compliance-viewers", True, "allow", 193),
            (80, "Contractor privileged access", "admin", "contractors", True, "review", 9),
            (90, "Guest network application access", "wireless", "guests", False, "deny", 48),
        ]
        for priority, name, network, group, mfa, effect, hits in access_rules:
            AccessControlRule.objects.create(
                priority=priority, name=name, network_type=network, group=group, mfa_required=mfa,
                effect=effect, hit_count=hits, last_matched=self.now - timedelta(minutes=priority + 6),
            )

    def _seed_security_events(self):
        rows = [
            ("access", "10.42.80.24", "id.ledgerlab.tech", "MFA authentication", "low", "Remote accounting session approved with MFA.", "resolved", 12, {"user": "accounting.lead", "result": "success"}),
            ("firewall", "10.42.50.18", "10.42.20.12:445", "Guest network isolation", "low", "Guest Wi-Fi traffic to the document share was denied by policy.", "resolved", 27, {"rule": "Guest network isolation", "result": "blocked"}),
            ("web-filter", "10.42.30.44", "nra.bg", "Business web access", "low", "Access to the National Revenue Agency portal was allowed.", "resolved", 41, {"category": "Public administration", "result": "allowed"}),
            ("edr", "10.42.30.43", "pay-ws-01", "Patch compliance", "medium", "Payroll workstation requires a restart after security updates.", "investigating", 143, {"owner": "IT Operations", "due": "next maintenance window"}),
            ("ips", "10.42.40.22", "portal.ledgerlab.tech:80", "Cleartext HTTP policy", "medium", "A cleartext request was redirected to the TLS portal.", "resolved", 46, {"signature_id": 1004201, "result": "redirected"}),
            ("access", "10.42.80.31", "id.ledgerlab.tech", "MFA timeout", "medium", "A remote session expired before the MFA prompt was completed.", "resolved", 188, {"user": "payroll.lead", "result": "timeout"}),
            ("firewall", "10.42.30.46", "1.1.1.1:53", "DNS policy deviation", "low", "The endpoint attempted to use an external resolver and was returned to corporate DNS.", "resolved", 248, {"rule": "Corporate DNS to resolver", "result": "remediated"}),
            ("edr", "10.42.20.14", "backup-sf-01", "Backup verification", "low", "Encrypted backup and sample restore verification completed.", "resolved", 91, {"repository": "offsite-encrypted", "result": "verified"}),
        ]
        events = []
        for component_key, source_ip, destination, event_type, severity, message, status, minutes, extra in rows:
            event = SecurityEvent.objects.create(
                component=self.components[component_key], source_ip=source_ip, destination=destination,
                event_type=event_type, severity=severity, message=message,
                extra_data={"seed": DATA_TAG, "organization": "LedgerLab", **extra},
                status=status, occurred_at=self.now - timedelta(minutes=minutes),
            )
            events.append(event)
        Alert.objects.create(
            event=events[3], title="Payroll workstation restart pending", severity="medium",
            status="investigating", assigned_to="IT Operations",
        )
        return events

    def _seed_siem(self, events):
        sources = [
            ("LedgerLab edge firewall", "firewall", "syslog"),
            ("Microsoft Entra ID", "access", "json"),
            ("Accounting database audit", "siem", "json"),
            ("Document file server audit", "siem", "json"),
            ("Encrypted backup service", "siem", "plain"),
            ("Wazuh endpoint manager", "edr", "json"),
        ]
        source_objects = {}
        for name, component, parser in sources:
            source, _ = LogSource.objects.update_or_create(
                name=name, defaults={"component": component, "parser": parser, "enabled": True, "last_seen": self.now - timedelta(minutes=2)},
            )
            source_objects[name] = source

        correlations = [
            ("MFA prompt fatigue indicator", "access", "mfa_timeout", 3, 15, "medium", 1),
            ("Backup completion control", "siem", "backup_missing", 1, 1440, "high", 0),
            ("Large document export", "siem", "document_export", 500, 30, "high", 0),
            ("Privileged group membership change", "access", "privileged_group_change", 1, 10, "high", 0),
        ]
        for name, component, pattern, threshold, window, severity, hits in correlations:
            CorrelationRule.objects.create(
                name=name, component=component, pattern=pattern, threshold=threshold,
                window_minutes=window, severity=severity, hit_count=hits,
            )

        logs = [
            ("Microsoft Entra ID", "access", "Interactive sign-in", "low", "10.42.80.24", "id.ledgerlab.tech", "MFA satisfied for accounting.lead", 12, events[0]),
            ("LedgerLab edge firewall", "firewall", "Policy deny", "low", "10.42.50.18", "10.42.20.12:445", "Guest segment denied to internal file services", 27, events[1]),
            ("Accounting database audit", "siem", "Scheduled maintenance", "low", "10.42.20.13", "acct-db-01", "Database statistics and integrity checks completed", 66, None),
            ("Encrypted backup service", "siem", "Backup verified", "low", "10.42.20.14", "offsite-encrypted", "Nightly backup completed; sample restore verified", 91, events[7]),
            ("Document file server audit", "siem", "Document archive", "low", "10.42.30.41", "files.ledgerlab.tech", "Authorized month-end archive written by accounting.lead", 114, None),
            ("Wazuh endpoint manager", "edr", "Patch status", "medium", "10.42.30.43", "pay-ws-01", "Restart pending after approved security updates", 143, events[3]),
            ("Microsoft Entra ID", "access", "MFA timeout", "medium", "10.42.80.31", "id.ledgerlab.tech", "Remote sign-in expired before MFA completion", 188, events[5]),
            ("Accounting database audit", "siem", "Payroll export", "low", "10.42.30.43", "acct-db-01", "Authorized monthly payroll export completed", 302, None),
        ]
        for source_name, component, event_type, severity, source_ip, destination, message, minutes, event in logs:
            LogEntry.objects.create(
                source=source_objects[source_name], component=component, raw_message=message,
                parsed={"seed": DATA_TAG, "organization": "LedgerLab", "site": "sofia"},
                source_ip=source_ip, destination=destination, event_type=event_type,
                severity=severity, event=event, created_at=self.now - timedelta(minutes=minutes),
            )

    def _seed_assets_and_policies(self, endpoints):
        risk_by_status = {"protected": "low", "attention": "medium", "at_risk": "high", "critical": "critical"}
        for hostname, endpoint in endpoints.items():
            EndpointAsset.objects.create(
                name=f"LL-{hostname.upper()}", owner=endpoint.logged_in_user or "IT Operations",
                ip_address=endpoint.ip, operating_system=f"{endpoint.os} {endpoint.os_version}",
                risk_level=risk_by_status[endpoint.security_status],
                edr_status=endpoint.get_security_status_display(), last_seen=endpoint.last_seen,
            )

        policies = [
            ("Corporate SaaS allow-list", "All managed endpoints", "Business applications", "allow", 39214),
            ("Personal storage review", "Finance and payroll", "External file sharing", "review", 37),
            ("Public paste services restriction", "All managed endpoints", "Data handling", "block", 4),
        ]
        for name, scope, category, effect, hits in policies:
            AccessPolicy.objects.create(name=name, scope=scope, category=category, effect=effect, enabled=True, hit_count=hits)

    def _update_components(self):
        values = {
            "firewall": ("healthy", 182340, 912, "Network segmentation and policy enforcement are operating normally."),
            "ips": ("healthy", 48620, 4, "Protocol monitoring is active; no confirmed intrusion events are present."),
            "edr": ("warning", 12, 3, "Three endpoints have routine maintenance or policy follow-up items."),
            "web-filter": ("healthy", 76240, 41, "Business access is available; restricted services are handled by policy."),
            "access": ("healthy", 2981, 46, "MFA and role-based access are active for remote and privileged sessions."),
            "siem": ("healthy", 1284600, 1, "Audit sources are reporting and one maintenance item remains assigned."),
        }
        for key, (status, requests, blocked, description) in values.items():
            component = self.components[key]
            component.status = status
            component.request_count = requests
            component.blocked_count = blocked
            component.description = description
            component.last_checked = self.now
            component.save(update_fields=["status", "request_count", "blocked_count", "description", "last_checked"])
