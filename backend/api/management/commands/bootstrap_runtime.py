from pathlib import Path
import os

from django.conf import settings
from django.contrib.auth.models import User
from django.core.management.base import BaseCommand

from api.models import AccessPolicy, Alert, EndpointAsset, IPSRuleCategory, ModuleSetting, SecurityComponent, SecurityEvent


MODULE_DEFAULTS = {
    SecurityComponent.Category.FIREWALL: {
        "display_name": "Firewall: защитна стена",
        "description": "Политики за филтриране на мрежови връзки по CIDR, посока, протокол и порт.",
        "settings": {"default_action": "allow", "log_allowed": True},
    },
    SecurityComponent.Category.IPS: {
        "display_name": "IPS: откриване на прониквания",
        "description": "Управление на Suricata IDS/IPS, приемане на EVE JSON събития и действия при сработване.",
        "settings": {"mode": "ids", "interface": "", "home_net": "192.168.1.0/24", "auto_update": False, "update_period": "daily", "logging_enabled": True},
    },
    SecurityComponent.Category.EDR: {
        "display_name": "EDR: сървъри и работни станции",
        "description": "Централизирано състояние на Wazuh Agent endpoints, събития за сигурност, заплахи и уязвимости.",
        "settings": {"provider": "wazuh", "manager_url": "http://localhost:55000", "agent_offline_timeout_minutes": 15, "event_retention_days": 90, "automatic_refresh": True},
    },
    SecurityComponent.Category.WEB_FILTER: {
        "display_name": "Web Filter: интернет достъп",
        "description": "Проверка на URL по домейн, текстови съвпадения и regex правила.",
        "settings": {"default_action": "allow", "log_allowed": False},
    },
    SecurityComponent.Category.ACCESS: {
        "display_name": "IAM/MFA: управление на достъпа",
        "description": "Проверка на мрежови връзки, групи и MFA политики.",
        "settings": {"default_effect": "deny", "mfa_grace_minutes": 0},
    },
    SecurityComponent.Category.SIEM: {
        "display_name": "SIEM и мониторинг на логове",
        "description": "Централизирано приемане на логове и корелация на събития за киберсигурност.",
        "settings": {"correlation_enabled": True, "alert_on_high": True},
    },
}

DEMO_POLICY_NAMES = [
    "Блокировка фишинговых доменов",
    "Ограничение анонимайзеров",
    "MFA для административных групп",
    "Проверка новых SaaS-сервисов",
    "Разрешение репозиториев разработки",
]
DEMO_ASSET_NAMES = ["srv-payments-01", "ws-fin-033", "srv-dc-02", "mac-design-012", "vpn-user-204"]
DEMO_COMPONENT_KEYS = ["fw-core", "ips-east", "edr-fleet", "web-policy", "iam-mfa", "siem-core"]
DEMO_EVENT_TYPES = [
    "Port scan",
    "Suspicious process tree",
    "URL category block",
    "MFA fatigue",
    "Exploit attempt",
    "Impossible travel",
    "Denied inbound traffic",
]


class Command(BaseCommand):
    help = "Initialize real runtime configuration without demo events or fake metrics."

    def handle(self, *args, **options):
        SecurityComponent.objects.filter(key__in=DEMO_COMPONENT_KEYS).delete()
        self._purge_old_demo_once()
        for key, defaults in MODULE_DEFAULTS.items():
            component, created = SecurityComponent.objects.get_or_create(
                key=key,
                defaults={
                    "name": defaults["display_name"],
                    "category": key,
                    "description": defaults["description"],
                    "status": SecurityComponent.Status.HEALTHY,
                },
            )
            if not created:
                component.name = defaults["display_name"]
                component.category = key
                component.description = defaults["description"]
                component.save(update_fields=["name", "category", "description"])
            setting, created = ModuleSetting.objects.get_or_create(
                key=key,
                defaults={
                    "display_name": defaults["display_name"],
                    "settings": defaults["settings"],
                },
            )
            if not created and setting.display_name != defaults["display_name"]:
                setting.display_name = defaults["display_name"]
                setting.save(update_fields=["display_name", "updated_at"])
        for name in ["Malware", "Web attacks", "Scanning", "Exploits", "DNS", "Policy"]:
            IPSRuleCategory.objects.get_or_create(name=name, defaults={"enabled": True, "rule_count": 0})
        self._ensure_admin_user()
        self.stdout.write(self.style.SUCCESS("Runtime modules initialized."))

    def _ensure_admin_user(self):
        username = os.getenv("ADMIN_USERNAME", "admin").strip()
        password = os.getenv("ADMIN_PASSWORD", "admin12345")
        email = os.getenv("ADMIN_EMAIL", "admin@example.local")
        if not username:
            return
        user, created = User.objects.get_or_create(
            username=username,
            defaults={"email": email, "is_staff": True, "is_superuser": True},
        )
        changed = False
        if created or not user.has_usable_password():
            user.set_password(password)
            changed = True
        if not user.is_staff or not user.is_superuser:
            user.is_staff = True
            user.is_superuser = True
            changed = True
        if changed:
            user.save()

    def _purge_old_demo_once(self):
        db_path = Path(os.getenv("SQLITE_DB_PATH", settings.BASE_DIR / "data" / "db.sqlite3"))
        marker_path = db_path.parent / ".demo_purged"
        if marker_path.exists():
            return

        Alert.objects.filter(event__event_type__in=DEMO_EVENT_TYPES).delete()
        SecurityEvent.objects.filter(event_type__in=DEMO_EVENT_TYPES).delete()
        AccessPolicy.objects.filter(name__in=DEMO_POLICY_NAMES).delete()
        EndpointAsset.objects.filter(name__in=DEMO_ASSET_NAMES).delete()
        SecurityComponent.objects.filter(key__in=MODULE_DEFAULTS.keys()).update(
            request_count=0,
            blocked_count=0,
            status=SecurityComponent.Status.HEALTHY,
        )
        marker_path.parent.mkdir(parents=True, exist_ok=True)
        marker_path.write_text("ok\n", encoding="utf-8")
