from datetime import timedelta

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
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
    SecurityComponent,
    SecurityEvent,
    WebFilterRule,
)


DATA_TAG = "bg-office-soc"


class Command(BaseCommand):
    help = "Fill the local SQLite database with realistic Bulgarian SOC data."

    def handle(self, *args, **options):
        now = timezone.now()
        self._cleanup_previous_seed()
        self._seed_users()
        self._seed_rules(now)
        endpoints = self._seed_edr(now)
        self._seed_security_events(now)
        self._seed_ips_alerts(now)
        self._seed_siem(now)
        self._seed_assets_and_policies(now)
        self._update_components(now, endpoints)
        self.stdout.write(self.style.SUCCESS("Bulgarian SOC data seeded."))

    def _cleanup_previous_seed(self):
        Alert.objects.filter(event__extra_data__seed=DATA_TAG).delete()
        SecurityEvent.objects.filter(extra_data__seed=DATA_TAG).delete()
        LogEntry.objects.filter(parsed__seed=DATA_TAG).delete()
        IPSAlert.objects.filter(raw_event__seed=DATA_TAG).delete()
        EDREvent.objects.filter(raw_event__seed=DATA_TAG).delete()
        EDRThreat.objects.filter(
            title__in=[
                "Карантиниран троянец при счетоводен отдел",
                "Подозрителен достъп до LSASS на домейн контролер",
            ]
        ).delete()

        Alert.objects.filter(title__startswith="Demo ").delete()
        SecurityEvent.objects.filter(extra_data__demo=True).delete()
        EDREvent.objects.filter(rule_id__startswith="demo-edr-").delete()
        EDRThreat.objects.filter(title__startswith="Demo ").delete()
        IPSAlert.objects.filter(event_hash__startswith="demo-ips-").delete()
        IPSCustomRule.objects.filter(name__icontains="Demo").delete()

        FirewallRule.objects.filter(
            name__in=[
                "Allow HTTPS to public web",
                "Block inbound SSH from Internet",
                "Allow VPN management network",
                "Block outbound SMTP except relay",
            ]
        ).delete()
        IPSRule.objects.filter(
            name__in=[
                "SQL injection pattern",
                "Suspicious PowerShell payload",
                "Port scan burst",
            ]
        ).delete()
        WebFilterRule.objects.filter(
            name__in=[
                "Block phishing domains",
                "Review anonymizers",
                "Allow developer repositories",
            ]
        ).delete()
        AccessControlRule.objects.filter(
            name__in=[
                "Admins require MFA",
                "VPN employees with MFA",
                "Block guest admin access",
            ]
        ).delete()
        EDRPolicy.objects.filter(
            name__in=[
                "Workstations standard protection",
                "Servers strict monitoring",
            ]
        ).delete()
        AccessPolicy.objects.filter(name__in=["Demo SaaS review", "Преглед на нови SaaS услуги за търговския отдел"]).delete()
        EndpointAsset.objects.filter(name__in=["srv-payments-01", "ws-finance-033", "srv-dc-02", "laptop-sales-018"]).delete()

    def _seed_users(self):
        User.objects.filter(username="admin").update(email="admin@plameli.bg", first_name="Системен", last_name="Администратор")
        users = [
            ("stoian.ivanov", "stoian.ivanov@plameli.bg", "Стоян", "Иванов", True),
            ("maria.georgieva", "maria.georgieva@plameli.bg", "Мария", "Георгиева", True),
            ("petar.dimitrov", "petar.dimitrov@plameli.bg", "Петър", "Димитров", False),
            ("elena.koleva", "elena.koleva@plameli.bg", "Елена", "Колева", False),
        ]
        for username, email, first_name, last_name, is_staff in users:
            user, created = User.objects.get_or_create(
                username=username,
                defaults={"email": email, "first_name": first_name, "last_name": last_name, "is_staff": is_staff, "is_active": True},
            )
            user.email = email
            user.first_name = first_name
            user.last_name = last_name
            user.is_staff = is_staff
            user.is_active = True
            if created or not user.has_usable_password():
                user.set_password("Sofia!2026")
            user.save()
        User.objects.filter(username__in=["operator", "analyst"]).update(is_active=False)

    def _seed_rules(self, now):
        firewall_rules = [
            ("Allow HTTPS към клиентски портал Plameli", 10, "allow", "inbound", "tcp", "any", "any", "10.24.20.15/32", "443", "Публичен достъп до customer.plameli.bg през балансировчика в DMZ.", 1847),
            ("Block SSH към вътрешната мрежа от интернет", 20, "block", "inbound", "tcp", "any", "any", "10.24.0.0/16", "22", "Административен SSH е позволен само през VPN сегмента на ИТ отдела.", 93),
            ("Allow VPN администратори към сървърния VLAN", 30, "allow", "inbound", "tcp", "10.88.12.0/24", "any", "10.24.10.0/24", "22,3389,8443", "Достъп за администратори от корпоративния VPN с MFA.", 214),
            ("Block директен SMTP от работни станции", 40, "block", "outbound", "tcp", "10.24.30.0/23", "any", "any", "25", "Изходящата поща трябва да минава само през mail-relay.plameli.bg.", 31),
            ("Reject RDP от складовия Wi-Fi", 50, "reject", "inbound", "tcp", "10.24.60.0/24", "any", "10.24.10.0/24", "3389", "Складовите терминали нямат право на RDP към сървъри.", 18),
        ]
        for name, priority, action, direction, protocol, source_cidr, source_port, destination_cidr, destination_port, description, hits in firewall_rules:
            rule, _ = FirewallRule.objects.update_or_create(
                name=name,
                defaults={
                    "enabled": True,
                    "priority": priority,
                    "action": action,
                    "direction": direction,
                    "protocol": protocol,
                    "source_cidr": source_cidr,
                    "source_port": source_port,
                    "destination_cidr": destination_cidr,
                    "destination_port": destination_port,
                    "description": description,
                    "hit_count": hits,
                    "last_matched": now - timedelta(minutes=priority),
                },
            )
            FirewallRule.objects.filter(id=rule.id).update(applied_at=now - timedelta(minutes=6))

        ips_rules = [
            ("SQL injection към клиентски портал", 100, "payload", "union select", "block", "critical", 17),
            ("Encoded PowerShell при счетоводство", 110, "payload", "encodedcommand", "alert", "high", 11),
            ("Nmap сканиране към DMZ", 120, "message", "ET SCAN", "alert", "medium", 36),
            ("Подозрителен SMB lateral movement", 130, "payload", "psexec", "block", "high", 5),
        ]
        for name, priority, match_field, pattern, action, severity, hits in ips_rules:
            IPSRule.objects.update_or_create(
                name=name,
                defaults={
                    "enabled": True,
                    "priority": priority,
                    "match_field": match_field,
                    "pattern": pattern,
                    "action": action,
                    "severity": severity,
                    "description": "Сигнатура, поддържана от SOC екипа за производствената мрежа.",
                    "hit_count": hits,
                    "last_matched": now - timedelta(hours=hits),
                },
            )

        web_rules = [
            ("Block фалшив вход към ePay", 10, "domain", "epay-secure-bg.com", "Phishing", "block", 44),
            ("Block домейни за фалшиви фактури", 20, "contains", "invoice-download", "Fraud", "block", 19),
            ("Review анонимизиращи proxy услуги", 30, "contains", "hide-my-ip", "Anonymizer", "review", 8),
            ("Allow GitLab за разработчици", 40, "domain", "gitlab.com", "Development", "allow", 312),
        ]
        for name, priority, match_type, pattern, category, action, hits in web_rules:
            WebFilterRule.objects.update_or_create(
                name=name,
                defaults={"enabled": True, "priority": priority, "match_type": match_type, "pattern": pattern, "category": category, "action": action, "hit_count": hits, "last_matched": now - timedelta(minutes=hits)},
            )

        access_rules = [
            ("Администратори само с MFA", 10, "admin", "it-admins", True, "allow", 88),
            ("VPN служители с потвърден MFA", 20, "vpn", "employees", True, "allow", 441),
            ("Блокирай гост достъп до ERP", 30, "admin", "contractors", True, "deny", 14),
            ("Преглед за нови устройства в склад", 40, "wireless", "warehouse", False, "review", 27),
        ]
        for name, priority, network_type, group, mfa_required, effect, hits in access_rules:
            AccessControlRule.objects.update_or_create(
                name=name,
                defaults={"enabled": True, "priority": priority, "network_type": network_type, "group": group, "mfa_required": mfa_required, "effect": effect, "hit_count": hits, "last_matched": now - timedelta(minutes=hits)},
            )

        for name, count in [("Malware", 1478), ("Web attacks", 846), ("Scanning", 421), ("Exploits", 539), ("DNS", 231), ("Policy", 122)]:
            IPSRuleCategory.objects.update_or_create(name=name, defaults={"enabled": True, "rule_count": count})

        IPSCustomRule.objects.update_or_create(
            sid=1002401,
            defaults={
                "name": "SSH brute force към plameli edge",
                "raw_rule": 'alert tcp any any -> $HOME_NET 22 (msg:"PLAMELI SSH brute force edge"; flow:to_server; threshold:type both, track by_src, count 6, seconds 60; sid:1002401; rev:3;)',
                "enabled": True,
                "validation_error": "",
                "applied_at": now - timedelta(minutes=9),
            },
        )

    def _seed_edr(self, now):
        for name, telemetry, block_usb in [
            ("Работни станции - стандартна защита", "standard", False),
            ("Сървъри - засилен мониторинг", "verbose", True),
            ("Финансов отдел - блокиране на скриптове", "verbose", True),
        ]:
            EDRPolicy.objects.update_or_create(
                name=name,
                defaults={"enabled": True, "telemetry_level": telemetry, "block_usb": block_usb, "block_script_interpreters": True, "quarantine_on_malware": True, "protected_paths": "/etc\n/opt/plameli\nC:\\Windows\\System32\nD:\\ERP"},
            )

        endpoint_data = [
            ("prd-erp-db-01", "10.24.10.21", "Ubuntu Server", "22.04", "x86_64", "4.7.5", "BG-021", "online", "attention", "svc.erp", 4),
            ("fin-ws-034", "10.24.31.34", "Windows 11 Pro", "23H2", "x64", "4.7.5", "BG-034", "online", "critical", "maria.georgieva", 12),
            ("dc-sofia-02", "10.24.1.12", "Windows Server", "2022", "x64", "4.7.4", "BG-012", "offline", "at_risk", "administrator", 51),
            ("sales-lt-018", "10.24.44.18", "macOS", "14.5", "arm64", "4.7.5", "BG-118", "online", "protected", "elena.koleva", 7),
            ("wh-term-072", "10.24.60.72", "Windows 10 IoT", "22H2", "x64", "4.7.3", "BG-272", "online", "attention", "warehouse.shift", 18),
        ]
        endpoints = []
        for hostname, ip, os_name, os_version, arch, agent_version, agent_id, status, security_status, username, minutes_ago in endpoint_data:
            endpoint, _ = EDREndpoint.objects.update_or_create(
                hostname=hostname,
                defaults={"external_id": f"plameli-{agent_id}", "ip": ip, "os": os_name, "os_version": os_version, "architecture": arch, "agent_version": agent_version, "agent_id": agent_id, "status": status, "security_status": security_status, "provider": "wazuh", "logged_in_user": username, "last_seen": now - timedelta(minutes=minutes_ago)},
            )
            endpoints.append(endpoint)

        events = [
            (endpoints[1], "malware", "Malware", "critical", "Карантиниран троянец при счетоводен отдел", "powershell.exe", "maria.georgieva", "185.82.216.44", "quarantine", 8),
            (endpoints[2], "credential_access", "Credential Access", "high", "Подозрителен достъп до LSASS на домейн контролер", "rundll32.exe", "administrator", "91.196.124.88", "alert", 35),
            (endpoints[0], "policy", "Policy", "medium", "Необичаен достъп до ERP архив", "python3", "svc.erp", "10.24.10.21", "alert", 72),
            (endpoints[4], "device_control", "Device Control", "medium", "USB носител е блокиран на складов терминал", "DeviceInstall.exe", "warehouse.shift", "10.24.60.72", "block", 54),
        ]
        for index, (endpoint, event_type, category, severity, title, process, username, source_ip, action, minutes_ago) in enumerate(events, start=1):
            event = EDREvent.objects.create(
                endpoint=endpoint,
                event_type=event_type,
                category=category,
                severity=severity,
                title=title,
                description="Събитие от Wazuh агент, обогатено с контекст от Plameli SOC.",
                process_name=process,
                process_path=f"C:\\ProgramData\\Plameli\\{process}" if endpoint.os.startswith("Windows") else f"/opt/plameli/{process}",
                process_id=str(5200 + index),
                parent_process="explorer.exe" if endpoint.os.startswith("Windows") else "systemd",
                username=username,
                source_ip=source_ip,
                destination_ip=endpoint.ip,
                destination_port=443,
                protocol="tcp",
                file_path=f"C:\\Users\\{username}\\AppData\\Local\\Temp\\invoice_{index}.dat" if endpoint.os.startswith("Windows") else f"/var/tmp/archive_{index}.bin",
                file_hash=f"sha256:{'a' * (60 - len(str(index)))}{index}",
                action=action,
                rule_id=f"plameli-edr-{index:03d}",
                raw_event={"seed": DATA_TAG, "rule": f"plameli-edr-{index:03d}"},
                timestamp=now - timedelta(minutes=minutes_ago),
            )
            if severity in {"high", "critical"}:
                EDRThreat.objects.create(event=event, endpoint=endpoint, title=title, category=category, severity=severity, status="new" if severity == "critical" else "investigating")

        for endpoint, cve, package, installed, fixed, severity in [
            (endpoints[0], "CVE-2024-3094", "xz-utils", "5.6.0", "5.6.1", "critical"),
            (endpoints[1], "CVE-2025-21298", "Windows OLE", "10.0.22631", "KB5050009", "high"),
            (endpoints[2], "CVE-2024-6387", "openssh-server", "8.9p1", "9.8p1", "high"),
            (endpoints[4], "CVE-2023-36884", "Office runtime", "16.0.16327", "16.0.16731", "medium"),
        ]:
            EDRVulnerability.objects.update_or_create(endpoint=endpoint, cve=cve, package=package, defaults={"installed_version": installed, "fixed_version": fixed, "severity": severity, "status": "open"})
        return endpoints

    def _seed_security_events(self, now):
        component_by_key = {item.category: item for item in SecurityComponent.objects.all()}
        rows = [
            ("firewall", "45.144.212.19", "10.24.20.15:22", "Denied inbound SSH", "high", "Входящ SSH опит към DMZ е блокиран от edge firewall.", "block", 18),
            ("firewall", "212.5.158.77", "10.24.20.15:443", "Allowed HTTPS", "low", "Клиентска HTTPS заявка към портала е разрешена.", "allow", 75),
            ("web_filter", "10.24.31.34", "epay-secure-bg.com", "URL category block", "high", "Блокиран е домейн, имитиращ ePay вход за плащане.", "block", 24),
            ("access", "10.24.44.18", "VPN Sofia", "MFA required", "medium", "VPN вход от търговски лаптоп изисква MFA потвърждение.", "review", 40),
            ("access", "10.24.60.72", "ERP Admin", "Denied admin access", "high", "Складов терминал е спрян при опит за административен достъп до ERP.", "deny", 9),
            ("edr", "185.82.216.44", "fin-ws-034", "Endpoint malware", "critical", "EDR постави процес в карантина на работна станция във финансов отдел.", "quarantine", 8),
        ]
        for component_key, source_ip, destination, event_type, severity, message, action, minutes_ago in rows:
            event = SecurityEvent.objects.create(component=component_by_key.get(component_key), source_ip=source_ip, destination=destination, event_type=event_type, severity=severity, message=message, extra_data={"seed": DATA_TAG, "action": action}, occurred_at=now - timedelta(minutes=minutes_ago))
            if severity in {"high", "critical"}:
                Alert.objects.create(event=event, title=f"{event_type}: {destination}", severity=severity, status="new", assigned_to="Plameli SOC")

    def _seed_ips_alerts(self, now):
        rows = [
            ("critical", "ET WEB_SERVER SQL Injection Attempt", 2010935, "Web attacks", "45.144.212.91", 51544, "10.24.20.15", 443, "tcp", "blocked", "dmz0", 6),
            ("high", "ET SCAN Nmap Scripting Engine User-Agent", 2009358, "Scanning", "91.196.124.88", 41412, "10.24.20.15", 80, "tcp", "alert", "dmz0", 28),
            ("medium", "ET POLICY Suspicious TLS SNI", 2024218, "Policy", "10.24.31.34", 55210, "104.18.12.34", 443, "tcp", "alert", "lan0", 64),
            ("high", "ET MALWARE Possible AsyncRAT Checkin", 2037481, "Malware", "10.24.31.34", 49712, "185.82.216.44", 443, "tcp", "blocked", "lan0", 11),
        ]
        for index, (severity, signature, signature_id, category, source_ip, source_port, destination_ip, destination_port, protocol, action, interface, minutes_ago) in enumerate(rows, start=1):
            IPSAlert.objects.create(timestamp=now - timedelta(minutes=minutes_ago), severity=severity, signature=signature, signature_id=signature_id, category=category, source_ip=source_ip, source_port=source_port, destination_ip=destination_ip, destination_port=destination_port, protocol=protocol, action=action, interface=interface, flow_id=f"plameli-flow-{index:04d}", direction="to_server" if destination_ip.startswith("10.24.") else "to_client", event_hash=f"plameli-ips-{index:04d}-{int(now.timestamp())}", raw_event={"seed": DATA_TAG, "signature_id": signature_id, "site": "Sofia office"})

    def _seed_siem(self, now):
        source_map = {}
        for name, component, parser, minutes_ago in [
            ("edge-fw-sofia", "firewall", "syslog", 3),
            ("wazuh-manager-sofia", "edr", "json", 1),
            ("erp-audit-prd", "siem", "json", 6),
            ("vpn-gateway-plovdiv", "access", "syslog", 12),
        ]:
            source, _ = LogSource.objects.update_or_create(name=name, defaults={"component": component, "parser": parser, "enabled": True, "last_seen": now - timedelta(minutes=minutes_ago)})
            source_map[name] = source

        CorrelationRule.objects.update_or_create(name="Множество отказани VPN входове за 10 минути", defaults={"enabled": True, "component": "access", "pattern": "vpn_auth_failed", "threshold": 5, "window_minutes": 10, "severity": "high", "hit_count": 7})
        CorrelationRule.objects.update_or_create(name="ERP достъп извън работно време", defaults={"enabled": True, "component": "siem", "pattern": "after_hours_erp_access", "threshold": 2, "window_minutes": 30, "severity": "medium", "hit_count": 3})

        logs = [
            ("edge-fw-sofia", "firewall", "BLOCK tcp 45.144.212.19:51244 -> 10.24.20.15:22 policy=Block SSH", "45.144.212.19", "10.24.20.15:22", "Firewall deny", "high", 18),
            ("wazuh-manager-sofia", "edr", "rule=plameli-edr-001 host=fin-ws-034 action=quarantine user=maria.georgieva", "185.82.216.44", "fin-ws-034", "EDR quarantine", "critical", 8),
            ("erp-audit-prd", "siem", "after_hours_erp_access user=petar.dimitrov module=invoices ip=10.24.44.18", "10.24.44.18", "erp.plameli.bg", "ERP audit", "medium", 37),
            ("vpn-gateway-plovdiv", "access", "vpn_auth_failed user=external.contractor ip=77.85.48.21 reason=mfa_timeout", "77.85.48.21", "vpn-plovdiv", "VPN auth failed", "medium", 5),
        ]
        for source_name, component, raw_message, source_ip, destination, event_type, severity, minutes_ago in logs:
            LogEntry.objects.create(source=source_map[source_name], component=component, raw_message=raw_message, parsed={"seed": DATA_TAG, "source": source_name, "event_type": event_type}, source_ip=source_ip, destination=destination, event_type=event_type, severity=severity, created_at=now - timedelta(minutes=minutes_ago))

    def _seed_assets_and_policies(self, now):
        for name, owner, ip, os_name, risk, status in [
            ("prd-erp-db-01", "ERP Operations", "10.24.10.21", "Ubuntu Server 22.04", "high", "Attention"),
            ("fin-ws-034", "Finance", "10.24.31.34", "Windows 11 Pro", "critical", "Quarantine recommended"),
            ("dc-sofia-02", "Infrastructure", "10.24.1.12", "Windows Server 2022", "high", "At risk"),
            ("sales-lt-018", "Sales", "10.24.44.18", "macOS 14.5", "low", "Protected"),
            ("wh-term-072", "Warehouse", "10.24.60.72", "Windows 10 IoT", "medium", "Attention"),
        ]:
            EndpointAsset.objects.update_or_create(name=name, defaults={"owner": owner, "ip_address": ip, "operating_system": os_name, "risk_level": risk, "edr_status": status, "last_seen": now - timedelta(minutes=15)})

        for name, scope, category, effect, hits in [
            ("Преглед на нови SaaS услуги за търговския отдел", "sales", "SaaS", "review", 14),
            ("Блокиране на лични пощи от финансовия VLAN", "finance", "Email", "block", 22),
            ("Разрешени хранилища за разработка", "engineering", "Development", "allow", 189),
        ]:
            AccessPolicy.objects.update_or_create(name=name, defaults={"scope": scope, "category": category, "effect": effect, "enabled": True, "hit_count": hits})

    def _update_components(self, now, endpoints):
        stats = {
            "firewall": (2264, 142, "warning"),
            "ips": (514, 7, "critical"),
            "edr": (len(endpoints), 2, "critical"),
            "web_filter": (383, 63, "warning"),
            "access": (570, 21, "warning"),
            "siem": (1288, 4, "healthy"),
        }
        for category, (requests, blocked, status) in stats.items():
            SecurityComponent.objects.filter(category=category).update(request_count=requests, blocked_count=blocked, status=status, last_checked=now)
