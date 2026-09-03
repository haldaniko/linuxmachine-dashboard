from datetime import timedelta

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from django.utils import timezone

from api.models import (
    AccessControlRule,
    AccessPolicy,
    Alert,
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
    SecurityComponent,
    SecurityEvent,
    WebFilterRule,
)


class Command(BaseCommand):
    help = "Fill the local SQLite database with safe mock SOC data for UI testing."

    firewall_rule_names = [
        "Allow HTTPS to public web",
        "Block inbound SSH from Internet",
        "Allow VPN management network",
        "Block outbound SMTP except relay",
    ]
    ips_rule_names = [
        "SQL injection pattern",
        "Suspicious PowerShell payload",
        "Port scan burst",
    ]
    web_rule_names = [
        "Block phishing domains",
        "Review anonymizers",
        "Allow developer repositories",
    ]
    access_rule_names = [
        "Admins require MFA",
        "VPN employees with MFA",
        "Block guest admin access",
    ]
    edr_policy_names = [
        "Workstations standard protection",
        "Servers strict monitoring",
    ]
    endpoint_names = ["srv-payments-01", "ws-finance-033", "srv-dc-02", "laptop-sales-018"]
    user_names = ["operator", "analyst"]

    def handle(self, *args, **options):
        now = timezone.now()
        self._seed_users()
        self._seed_rules(now)
        endpoints = self._seed_edr(now)
        self._seed_security_events(now)
        self._seed_ips_alerts(now)
        self._seed_legacy_assets(now)
        self._update_components(now, endpoints)
        self.stdout.write(self.style.SUCCESS("Mock data seeded."))

    def _seed_users(self):
        users = [
            ("operator", "operator@example.local", "Оператор", "SOC", False),
            ("analyst", "analyst@example.local", "Анализатор", "SOC", True),
        ]
        for username, email, first_name, last_name, is_staff in users:
            user, created = User.objects.get_or_create(
                username=username,
                defaults={
                    "email": email,
                    "first_name": first_name,
                    "last_name": last_name,
                    "is_staff": is_staff,
                    "is_active": True,
                },
            )
            user.email = email
            user.first_name = first_name
            user.last_name = last_name
            user.is_staff = is_staff
            user.is_active = True
            if created or not user.has_usable_password():
                user.set_password("demo12345")
            user.save()

    def _seed_rules(self, now):
        firewall_rules = [
            {
                "name": "Allow HTTPS to public web",
                "priority": 10,
                "action": "allow",
                "direction": "inbound",
                "protocol": "tcp",
                "source_cidr": "any",
                "source_port": "any",
                "destination_cidr": "10.10.20.15/32",
                "destination_port": "443",
                "description": "Публичен HTTPS достъп до корпоративния портал",
                "hit_count": 348,
            },
            {
                "name": "Block inbound SSH from Internet",
                "priority": 20,
                "action": "block",
                "direction": "inbound",
                "protocol": "tcp",
                "source_cidr": "any",
                "source_port": "any",
                "destination_cidr": "10.10.0.0/16",
                "destination_port": "22",
                "description": "SSH е разрешен само през VPN",
                "hit_count": 41,
            },
            {
                "name": "Allow VPN management network",
                "priority": 30,
                "action": "allow",
                "direction": "inbound",
                "protocol": "tcp",
                "source_cidr": "10.99.0.0/24",
                "source_port": "any",
                "destination_cidr": "10.10.0.0/16",
                "destination_port": "22,3389,8443",
                "description": "Административен достъп през защитен VPN сегмент",
                "hit_count": 87,
            },
            {
                "name": "Block outbound SMTP except relay",
                "priority": 40,
                "action": "block",
                "direction": "outbound",
                "protocol": "tcp",
                "source_cidr": "10.10.0.0/16",
                "source_port": "any",
                "destination_cidr": "any",
                "destination_port": "25",
                "description": "Ограничаване на директен SMTP трафик",
                "hit_count": 13,
            },
        ]
        for item in firewall_rules:
            rule, _ = FirewallRule.objects.update_or_create(name=item["name"], defaults={**item, "enabled": True, "last_matched": now - timedelta(minutes=item["priority"])})
            FirewallRule.objects.filter(id=rule.id).update(applied_at=now - timedelta(minutes=5))

        ips_rules = [
            ("SQL injection pattern", 100, "payload", "union select", "block", "critical", 12),
            ("Suspicious PowerShell payload", 110, "payload", "encodedcommand", "alert", "high", 7),
            ("Port scan burst", 120, "message", "ET SCAN", "alert", "medium", 19),
        ]
        for name, priority, match_field, pattern, action, severity, hits in ips_rules:
            IPSRule.objects.update_or_create(
                name=name,
                defaults={"enabled": True, "priority": priority, "match_field": match_field, "pattern": pattern, "action": action, "severity": severity, "description": "Демо сигнатура за тестване", "hit_count": hits, "last_matched": now - timedelta(hours=hits)},
            )

        web_rules = [
            ("Block phishing domains", 10, "domain", "login-secure-example.com", "Phishing", "block", 28),
            ("Review anonymizers", 20, "contains", "proxy", "Anonymizer", "review", 11),
            ("Allow developer repositories", 30, "domain", "github.com", "Development", "allow", 164),
        ]
        for name, priority, match_type, pattern, category, action, hits in web_rules:
            WebFilterRule.objects.update_or_create(
                name=name,
                defaults={"enabled": True, "priority": priority, "match_type": match_type, "pattern": pattern, "category": category, "action": action, "hit_count": hits, "last_matched": now - timedelta(minutes=hits)},
            )

        access_rules = [
            ("Admins require MFA", 10, "admin", "admins", True, "allow", 56),
            ("VPN employees with MFA", 20, "vpn", "employees", True, "allow", 203),
            ("Block guest admin access", 30, "admin", "guests", True, "deny", 9),
        ]
        for name, priority, network_type, group, mfa_required, effect, hits in access_rules:
            AccessControlRule.objects.update_or_create(
                name=name,
                defaults={"enabled": True, "priority": priority, "network_type": network_type, "group": group, "mfa_required": mfa_required, "effect": effect, "hit_count": hits, "last_matched": now - timedelta(minutes=hits)},
            )

        categories = [("Malware", 1412), ("Web attacks", 823), ("Scanning", 390), ("Exploits", 517), ("DNS", 204), ("Policy", 96)]
        for name, count in categories:
            IPSRuleCategory.objects.update_or_create(name=name, defaults={"enabled": True, "rule_count": count})

        IPSCustomRule.objects.update_or_create(
            sid=1000001,
            defaults={
                "name": "Demo SSH probe",
                "raw_rule": 'alert tcp any any -> $HOME_NET 22 (msg:"Demo SSH probe"; sid:1000001; rev:1;)',
                "enabled": True,
                "validation_error": "",
                "applied_at": now - timedelta(minutes=4),
            },
        )

    def _seed_edr(self, now):
        for name, telemetry, block_usb in [
            ("Workstations standard protection", "standard", False),
            ("Servers strict monitoring", "verbose", True),
        ]:
            EDRPolicy.objects.update_or_create(
                name=name,
                defaults={"enabled": True, "telemetry_level": telemetry, "block_usb": block_usb, "block_script_interpreters": True, "quarantine_on_malware": True, "protected_paths": "/etc\n/var/www\nC:\\Windows\\System32"},
            )

        endpoint_data = [
            ("srv-payments-01", "10.10.20.15", "Ubuntu Server", "22.04", "x86_64", "4.7.5", "001", "online", "attention", "svc-payments", 3),
            ("ws-finance-033", "10.10.31.33", "Windows 11 Pro", "23H2", "x64", "4.7.5", "033", "online", "critical", "maria.georgieva", 12),
            ("srv-dc-02", "10.10.1.12", "Windows Server", "2022", "x64", "4.7.4", "012", "offline", "at_risk", "administrator", 46),
            ("laptop-sales-018", "10.10.44.18", "macOS", "14.5", "arm64", "4.7.5", "018", "never_connected", "protected", "sales.user", 240),
        ]
        endpoints = []
        for hostname, ip, os_name, os_version, arch, agent_version, agent_id, status, security_status, username, minutes_ago in endpoint_data:
            endpoint, _ = EDREndpoint.objects.update_or_create(
                hostname=hostname,
                defaults={
                    "external_id": f"demo-{agent_id}",
                    "ip": ip,
                    "os": os_name,
                    "os_version": os_version,
                    "architecture": arch,
                    "agent_version": agent_version,
                    "agent_id": agent_id,
                    "status": status,
                    "security_status": security_status,
                    "provider": "wazuh",
                    "logged_in_user": username,
                    "last_seen": now - timedelta(minutes=minutes_ago),
                },
            )
            endpoints.append(endpoint)

        EDREvent.objects.filter(rule_id__startswith="demo-edr-").delete()
        EDRThreat.objects.filter(title__startswith="Demo ").delete()
        events = [
            (endpoints[1], "malware", "Malware", "critical", "Demo malware blocked on workstation", "powershell.exe", "maria.georgieva", "203.0.113.45", "quarantine", 8),
            (endpoints[2], "lateral_movement", "Credential Access", "high", "Demo suspicious credential access", "lsass.exe", "administrator", "198.51.100.77", "alert", 35),
            (endpoints[0], "policy", "Policy", "medium", "Demo sensitive file access", "python3", "svc-payments", "10.10.20.15", "alert", 72),
        ]
        created_events = []
        for index, (endpoint, event_type, category, severity, title, process, username, source_ip, action, minutes_ago) in enumerate(events, start=1):
            event = EDREvent.objects.create(
                endpoint=endpoint,
                event_type=event_type,
                category=category,
                severity=severity,
                title=title,
                description="Демо EDR събитие за визуална проверка на панела.",
                process_name=process,
                process_path=f"C:\\Demo\\{process}",
                process_id=str(4000 + index),
                parent_process="explorer.exe",
                username=username,
                source_ip=source_ip,
                destination_ip=endpoint.ip,
                destination_port=443,
                protocol="tcp",
                file_path=f"C:\\Temp\\demo-{index}.bin",
                file_hash=f"demo-hash-{index}",
                action=action,
                rule_id=f"demo-edr-{index}",
                raw_event={"demo": True, "rule": f"demo-edr-{index}"},
                timestamp=now - timedelta(minutes=minutes_ago),
            )
            created_events.append(event)
            if severity in {"high", "critical"}:
                EDRThreat.objects.create(event=event, endpoint=endpoint, title=f"Demo {title}", category=category, severity=severity, status="new" if severity == "critical" else "investigating")

        vulns = [
            (endpoints[0], "CVE-2024-3094", "xz-utils", "5.6.0", "5.6.1", "critical"),
            (endpoints[1], "CVE-2025-21298", "Windows OLE", "10.0.22631", "KB5050009", "high"),
            (endpoints[2], "CVE-2024-6387", "openssh-server", "8.9p1", "9.8p1", "high"),
        ]
        for endpoint, cve, package, installed, fixed, severity in vulns:
            EDRVulnerability.objects.update_or_create(
                endpoint=endpoint,
                cve=cve,
                package=package,
                defaults={"installed_version": installed, "fixed_version": fixed, "severity": severity, "status": "open"},
            )
        return endpoints

    def _seed_security_events(self, now):
        SecurityEvent.objects.filter(extra_data__demo=True).delete()
        Alert.objects.filter(title__startswith="Demo ").delete()
        component_by_key = {item.category: item for item in SecurityComponent.objects.all()}
        event_rows = [
            ("firewall", "203.0.113.44", "10.10.20.15:22", "Denied inbound SSH", "high", "Входящ SSH трафик е блокиран от защитната стена", "block", 18),
            ("firewall", "198.51.100.23", "10.10.20.15:443", "Allowed HTTPS", "low", "HTTPS заявка е разрешена", "allow", 75),
            ("web_filter", "10.10.31.33", "login-secure-example.com", "URL category block", "high", "Блокиран е домейн с фишинг категория", "block", 24),
            ("access", "10.10.44.18", "VPN", "MFA required", "medium", "VPN вход изисква MFA потвърждение", "review", 40),
            ("access", "10.10.50.8", "Admin portal", "Denied admin access", "high", "Гост потребител е спрян при административен достъп", "deny", 9),
            ("edr", "203.0.113.45", "ws-finance-033", "Endpoint malware", "critical", "EDR маркира процес за карантина", "quarantine", 8),
        ]
        for component_key, source_ip, destination, event_type, severity, message, action, minutes_ago in event_rows:
            event = SecurityEvent.objects.create(
                component=component_by_key.get(component_key),
                source_ip=source_ip,
                destination=destination,
                event_type=event_type,
                severity=severity,
                message=message,
                extra_data={"demo": True, "action": action},
                occurred_at=now - timedelta(minutes=minutes_ago),
            )
            if severity in {"high", "critical"}:
                Alert.objects.create(event=event, title=f"Demo {event_type}", severity=severity, status="new", assigned_to="SOC")

    def _seed_ips_alerts(self, now):
        IPSAlert.objects.filter(event_hash__startswith="demo-ips-").delete()
        rows = [
            ("critical", "ET WEB_SERVER SQL Injection Attempt", 2010935, "Web attacks", "203.0.113.90", 51544, "10.10.20.15", 443, "tcp", "blocked", "eth0", 6),
            ("high", "ET SCAN Nmap Scripting Engine User-Agent", 2009358, "Scanning", "198.51.100.17", 41412, "10.10.20.15", 80, "tcp", "alert", "eth0", 28),
            ("medium", "ET POLICY Suspicious TLS SNI", 2024218, "Policy", "10.10.31.33", 55210, "104.18.12.34", 443, "tcp", "alert", "eth1", 64),
        ]
        for index, (severity, signature, signature_id, category, source_ip, source_port, destination_ip, destination_port, protocol, action, interface, minutes_ago) in enumerate(rows, start=1):
            IPSAlert.objects.create(
                timestamp=now - timedelta(minutes=minutes_ago),
                severity=severity,
                signature=signature,
                signature_id=signature_id,
                category=category,
                source_ip=source_ip,
                source_port=source_port,
                destination_ip=destination_ip,
                destination_port=destination_port,
                protocol=protocol,
                action=action,
                interface=interface,
                flow_id=f"demo-flow-{index}",
                direction="to_server",
                event_hash=f"demo-ips-{index}",
                raw_event={"demo": True, "signature_id": signature_id},
            )

    def _seed_legacy_assets(self, now):
        assets = [
            ("srv-payments-01", "Payments", "10.10.20.15", "Ubuntu Server 22.04", "high", "Attention"),
            ("ws-finance-033", "Finance", "10.10.31.33", "Windows 11 Pro", "critical", "Quarantine recommended"),
            ("srv-dc-02", "Infrastructure", "10.10.1.12", "Windows Server 2022", "high", "At risk"),
        ]
        for name, owner, ip, os_name, risk, status in assets:
            EndpointAsset.objects.update_or_create(
                name=name,
                defaults={"owner": owner, "ip_address": ip, "operating_system": os_name, "risk_level": risk, "edr_status": status, "last_seen": now - timedelta(minutes=15)},
            )
        AccessPolicy.objects.update_or_create(name="Demo SaaS review", defaults={"scope": "employees", "category": "SaaS", "effect": "review", "enabled": True, "hit_count": 14})

    def _update_components(self, now, endpoints):
        stats = {
            "firewall": (489, 54, "warning"),
            "ips": (322, 3, "critical"),
            "edr": (len(endpoints), 2, "critical"),
            "web_filter": (203, 28, "warning"),
            "access": (268, 9, "warning"),
            "siem": (0, 0, "healthy"),
        }
        for category, (requests, blocked, status) in stats.items():
            SecurityComponent.objects.filter(category=category).update(request_count=requests, blocked_count=blocked, status=status, last_checked=now)
