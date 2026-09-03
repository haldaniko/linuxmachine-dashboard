from django.db import models
from django.utils import timezone


class SecurityComponent(models.Model):
    class Category(models.TextChoices):
        FIREWALL = "firewall", "Межсетевой экран"
        IPS = "ips", "Система обнаружения вторжений"
        EDR = "edr", "Защита серверов и рабочих станций"
        WEB_FILTER = "web_filter", "Интернет-доступ и фильтрация"
        ACCESS = "access", "Доступ и MFA"
        SIEM = "siem", "SIEM и мониторинг логов"

    class Status(models.TextChoices):
        HEALTHY = "healthy", "В норме"
        WARNING = "warning", "Требует внимания"
        CRITICAL = "critical", "Критично"
        OFFLINE = "offline", "Недоступен"

    key = models.SlugField(unique=True)
    name = models.CharField(max_length=140)
    category = models.CharField(max_length=32, choices=Category.choices)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.HEALTHY)
    description = models.TextField(blank=True)
    request_count = models.PositiveIntegerField(default=0)
    blocked_count = models.PositiveIntegerField(default=0)
    last_checked = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["id"]

    def __str__(self):
        return self.name


class ModuleSetting(models.Model):
    class Mode(models.TextChoices):
        MONITOR = "monitor", "Мониторинг"
        ENFORCE = "enforce", "Применение"
        DISABLED = "disabled", "Отключено"

    key = models.CharField(max_length=32, choices=SecurityComponent.Category.choices, unique=True)
    display_name = models.CharField(max_length=140)
    enabled = models.BooleanField(default=True)
    mode = models.CharField(max_length=16, choices=Mode.choices, default=Mode.MONITOR)
    settings = models.JSONField(default=dict, blank=True)
    notes = models.TextField(blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["key"]

    def __str__(self):
        return self.display_name


class FirewallRule(models.Model):
    class Action(models.TextChoices):
        ALLOW = "allow", "Разрешить"
        BLOCK = "block", "Блокировать"
        REJECT = "reject", "Отклонить"
        LOG = "log", "Только логировать"

    class Direction(models.TextChoices):
        INBOUND = "inbound", "Входящий"
        OUTBOUND = "outbound", "Исходящий"
        ANY = "any", "Любой"

    class Protocol(models.TextChoices):
        ANY = "any", "Любой"
        TCP = "tcp", "TCP"
        UDP = "udp", "UDP"
        ICMP = "icmp", "ICMP"

    name = models.CharField(max_length=140)
    enabled = models.BooleanField(default=True)
    priority = models.PositiveIntegerField(default=100)
    action = models.CharField(max_length=16, choices=Action.choices, default=Action.BLOCK)
    direction = models.CharField(max_length=16, choices=Direction.choices, default=Direction.ANY)
    protocol = models.CharField(max_length=16, choices=Protocol.choices, default=Protocol.ANY)
    source_cidr = models.CharField(max_length=64, default="any")
    source_port = models.CharField(max_length=80, default="any")
    destination_cidr = models.CharField(max_length=64, default="any")
    destination_port = models.CharField(max_length=80, default="any")
    description = models.TextField(blank=True)
    hit_count = models.PositiveIntegerField(default=0)
    last_matched = models.DateTimeField(null=True, blank=True)
    applied_at = models.DateTimeField(null=True, blank=True)
    apply_error = models.TextField(blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["priority", "id"]

    def __str__(self):
        return self.name


class IPSRule(models.Model):
    class MatchField(models.TextChoices):
        PAYLOAD = "payload", "Payload"
        URL = "url", "URL"
        MESSAGE = "message", "Message"

    class Action(models.TextChoices):
        ALERT = "alert", "Создать алерт"
        BLOCK = "block", "Блокировать"

    name = models.CharField(max_length=140)
    enabled = models.BooleanField(default=True)
    priority = models.PositiveIntegerField(default=100)
    match_field = models.CharField(max_length=16, choices=MatchField.choices, default=MatchField.PAYLOAD)
    pattern = models.CharField(max_length=280)
    action = models.CharField(max_length=16, choices=Action.choices, default=Action.ALERT)
    severity = models.CharField(
        max_length=16,
        choices=[
            ("low", "Низкая"),
            ("medium", "Средняя"),
            ("high", "Высокая"),
            ("critical", "Критичная"),
        ],
        default="high",
    )
    description = models.TextField(blank=True)
    hit_count = models.PositiveIntegerField(default=0)
    last_matched = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["priority", "id"]

    def __str__(self):
        return self.name


class IPSRuleCategory(models.Model):
    name = models.CharField(max_length=120, unique=True)
    description = models.TextField(blank=True)
    enabled = models.BooleanField(default=True)
    rule_count = models.PositiveIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class IPSCustomRule(models.Model):
    name = models.CharField(max_length=160)
    sid = models.PositiveIntegerField(unique=True)
    raw_rule = models.TextField()
    enabled = models.BooleanField(default=True)
    validation_error = models.TextField(blank=True)
    applied_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["sid"]

    def __str__(self):
        return f"{self.sid} {self.name}"


class IPSAlert(models.Model):
    timestamp = models.DateTimeField(default=timezone.now)
    severity = models.CharField(
        max_length=16,
        choices=[
            ("informational", "Informational"),
            ("low", "Low"),
            ("medium", "Medium"),
            ("high", "High"),
            ("critical", "Critical"),
        ],
        default="low",
    )
    signature = models.CharField(max_length=240)
    signature_id = models.PositiveIntegerField(null=True, blank=True)
    category = models.CharField(max_length=140, blank=True)
    source_ip = models.GenericIPAddressField(default="0.0.0.0")
    source_port = models.PositiveIntegerField(null=True, blank=True)
    destination_ip = models.GenericIPAddressField(default="0.0.0.0")
    destination_port = models.PositiveIntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=24, blank=True)
    action = models.CharField(max_length=32, default="alert")
    interface = models.CharField(max_length=64, blank=True)
    flow_id = models.CharField(max_length=80, blank=True)
    direction = models.CharField(max_length=40, blank=True)
    event_hash = models.CharField(max_length=64, unique=True)
    raw_event = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self):
        return self.signature


class IPSUpdateLog(models.Model):
    started_at = models.DateTimeField(default=timezone.now)
    finished_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=24, default="running")
    message = models.TextField(blank=True)
    rules_total = models.PositiveIntegerField(default=0)
    added = models.PositiveIntegerField(default=0)
    updated = models.PositiveIntegerField(default=0)
    removed = models.PositiveIntegerField(default=0)
    disabled = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["-started_at"]


class EDRPolicy(models.Model):
    name = models.CharField(max_length=140)
    enabled = models.BooleanField(default=True)
    telemetry_level = models.CharField(max_length=40, default="standard")
    block_usb = models.BooleanField(default=False)
    block_script_interpreters = models.BooleanField(default=True)
    quarantine_on_malware = models.BooleanField(default=True)
    protected_paths = models.TextField(default="/etc\n/var/www\nC:\\Windows\\System32")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class EDREndpoint(models.Model):
    class AgentStatus(models.TextChoices):
        ONLINE = "online", "Online"
        OFFLINE = "offline", "Offline"
        NEVER_CONNECTED = "never_connected", "Never connected"
        ERROR = "error", "Error"

    class SecurityStatus(models.TextChoices):
        PROTECTED = "protected", "Protected"
        ATTENTION = "attention", "Attention"
        AT_RISK = "at_risk", "At risk"
        CRITICAL = "critical", "Critical"

    external_id = models.CharField(max_length=120, blank=True)
    hostname = models.CharField(max_length=160)
    ip = models.GenericIPAddressField(default="0.0.0.0")
    os = models.CharField(max_length=120, blank=True)
    os_version = models.CharField(max_length=120, blank=True)
    architecture = models.CharField(max_length=40, blank=True)
    agent_version = models.CharField(max_length=80, blank=True)
    agent_id = models.CharField(max_length=120, blank=True)
    status = models.CharField(max_length=24, choices=AgentStatus.choices, default=AgentStatus.NEVER_CONNECTED)
    security_status = models.CharField(max_length=24, choices=SecurityStatus.choices, default=SecurityStatus.PROTECTED)
    provider = models.CharField(max_length=40, default="wazuh")
    logged_in_user = models.CharField(max_length=140, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    first_seen = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["hostname"]

    def __str__(self):
        return self.hostname


class EDREvent(models.Model):
    class Severity(models.TextChoices):
        INFORMATIONAL = "informational", "Informational"
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    timestamp = models.DateTimeField(default=timezone.now)
    endpoint = models.ForeignKey(EDREndpoint, on_delete=models.SET_NULL, null=True, blank=True, related_name="events")
    event_type = models.CharField(max_length=120)
    category = models.CharField(max_length=80)
    severity = models.CharField(max_length=16, choices=Severity.choices, default=Severity.LOW)
    title = models.CharField(max_length=240)
    description = models.TextField(blank=True)
    process_name = models.CharField(max_length=160, blank=True)
    process_path = models.CharField(max_length=500, blank=True)
    process_id = models.CharField(max_length=40, blank=True)
    parent_process = models.CharField(max_length=160, blank=True)
    username = models.CharField(max_length=140, blank=True)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    destination_ip = models.GenericIPAddressField(null=True, blank=True)
    source_port = models.PositiveIntegerField(null=True, blank=True)
    destination_port = models.PositiveIntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=24, blank=True)
    file_path = models.CharField(max_length=500, blank=True)
    file_hash = models.CharField(max_length=160, blank=True)
    action = models.CharField(max_length=80, default="alert")
    rule_id = models.CharField(max_length=120, blank=True)
    source = models.CharField(max_length=40, default="wazuh")
    raw_event = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self):
        return self.title


class EDRThreat(models.Model):
    class Status(models.TextChoices):
        NEW = "new", "New"
        INVESTIGATING = "investigating", "Investigating"
        RESOLVED = "resolved", "Resolved"
        IGNORED = "ignored", "Ignored"
        BLOCKED = "blocked", "Blocked"

    event = models.ForeignKey(EDREvent, on_delete=models.CASCADE, related_name="threats")
    endpoint = models.ForeignKey(EDREndpoint, on_delete=models.SET_NULL, null=True, blank=True, related_name="threats")
    title = models.CharField(max_length=240)
    category = models.CharField(max_length=80)
    severity = models.CharField(max_length=16, choices=EDREvent.Severity.choices, default=EDREvent.Severity.LOW)
    status = models.CharField(max_length=24, choices=Status.choices, default=Status.NEW)
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-created_at"]


class EDRVulnerability(models.Model):
    endpoint = models.ForeignKey(EDREndpoint, on_delete=models.CASCADE, related_name="vulnerabilities")
    cve = models.CharField(max_length=40)
    package = models.CharField(max_length=160, blank=True)
    installed_version = models.CharField(max_length=120, blank=True)
    fixed_version = models.CharField(max_length=120, blank=True)
    severity = models.CharField(max_length=16, choices=EDREvent.Severity.choices, default=EDREvent.Severity.LOW)
    status = models.CharField(max_length=40, default="open")
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("endpoint", "cve", "package")
        ordering = ["-created_at"]


class EDREnrollmentToken(models.Model):
    token = models.CharField(max_length=80, unique=True)
    platform = models.CharField(max_length=24)
    manager_url = models.CharField(max_length=240)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-created_at"]


class WebFilterRule(models.Model):
    class MatchType(models.TextChoices):
        DOMAIN = "domain", "Домен"
        CONTAINS = "contains", "Содержит"
        REGEX = "regex", "Regex"

    class Action(models.TextChoices):
        ALLOW = "allow", "Разрешить"
        BLOCK = "block", "Блокировать"
        REVIEW = "review", "На проверку"

    name = models.CharField(max_length=140)
    enabled = models.BooleanField(default=True)
    priority = models.PositiveIntegerField(default=100)
    match_type = models.CharField(max_length=16, choices=MatchType.choices, default=MatchType.DOMAIN)
    pattern = models.CharField(max_length=260)
    category = models.CharField(max_length=120, blank=True)
    action = models.CharField(max_length=16, choices=Action.choices, default=Action.BLOCK)
    hit_count = models.PositiveIntegerField(default=0)
    last_matched = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["priority", "id"]

    def __str__(self):
        return self.name


class AccessControlRule(models.Model):
    class NetworkType(models.TextChoices):
        ANY = "any", "Любой"
        WIRED = "wired", "Проводной"
        WIRELESS = "wireless", "Беспроводной"
        VPN = "vpn", "VPN"
        ADMIN = "admin", "Административный"

    class Effect(models.TextChoices):
        ALLOW = "allow", "Разрешить"
        DENY = "deny", "Запретить"
        REVIEW = "review", "На проверку"

    name = models.CharField(max_length=140)
    enabled = models.BooleanField(default=True)
    priority = models.PositiveIntegerField(default=100)
    network_type = models.CharField(max_length=16, choices=NetworkType.choices, default=NetworkType.ANY)
    group = models.CharField(max_length=140, default="any")
    mfa_required = models.BooleanField(default=True)
    effect = models.CharField(max_length=16, choices=Effect.choices, default=Effect.ALLOW)
    hit_count = models.PositiveIntegerField(default=0)
    last_matched = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["priority", "id"]

    def __str__(self):
        return self.name


class EndpointAsset(models.Model):
    class RiskLevel(models.TextChoices):
        LOW = "low", "Низкий"
        MEDIUM = "medium", "Средний"
        HIGH = "high", "Высокий"
        CRITICAL = "critical", "Критичный"

    name = models.CharField(max_length=140)
    owner = models.CharField(max_length=140, blank=True)
    ip_address = models.GenericIPAddressField()
    operating_system = models.CharField(max_length=120, blank=True)
    risk_level = models.CharField(max_length=16, choices=RiskLevel.choices, default=RiskLevel.LOW)
    edr_status = models.CharField(max_length=64, default="Protected")
    last_seen = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-last_seen"]

    def __str__(self):
        return self.name


class AccessPolicy(models.Model):
    class Effect(models.TextChoices):
        ALLOW = "allow", "Разрешить"
        BLOCK = "block", "Блокировать"
        REVIEW = "review", "На проверку"

    name = models.CharField(max_length=140)
    scope = models.CharField(max_length=140)
    category = models.CharField(max_length=120)
    effect = models.CharField(max_length=16, choices=Effect.choices, default=Effect.BLOCK)
    enabled = models.BooleanField(default=True)
    hit_count = models.PositiveIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class SecurityEvent(models.Model):
    class Severity(models.TextChoices):
        LOW = "low", "Низкая"
        MEDIUM = "medium", "Средняя"
        HIGH = "high", "Высокая"
        CRITICAL = "critical", "Критичная"

    class Status(models.TextChoices):
        NEW = "new", "Новый"
        INVESTIGATING = "investigating", "Расследуется"
        RESOLVED = "resolved", "Закрыт"

    component = models.ForeignKey(SecurityComponent, on_delete=models.SET_NULL, null=True, blank=True, related_name="events")
    source_ip = models.GenericIPAddressField(default="0.0.0.0")
    destination = models.CharField(max_length=180, blank=True)
    event_type = models.CharField(max_length=120)
    severity = models.CharField(max_length=16, choices=Severity.choices)
    message = models.TextField()
    extra_data = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=24, choices=Status.choices, default=Status.NEW)
    occurred_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-occurred_at"]

    def __str__(self):
        return f"{self.event_type} from {self.source_ip}"


class Alert(models.Model):
    event = models.ForeignKey(SecurityEvent, on_delete=models.CASCADE, null=True, blank=True, related_name="alerts")
    title = models.CharField(max_length=180)
    severity = models.CharField(max_length=16, choices=SecurityEvent.Severity.choices)
    status = models.CharField(max_length=24, choices=SecurityEvent.Status.choices, default=SecurityEvent.Status.NEW)
    assigned_to = models.CharField(max_length=140, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return self.title


class LogSource(models.Model):
    class Parser(models.TextChoices):
        JSON = "json", "JSON"
        SYSLOG = "syslog", "Syslog"
        PLAIN = "plain", "Plain text"

    name = models.CharField(max_length=140, unique=True)
    component = models.CharField(max_length=32, choices=SecurityComponent.Category.choices, default=SecurityComponent.Category.SIEM)
    parser = models.CharField(max_length=16, choices=Parser.choices, default=Parser.JSON)
    enabled = models.BooleanField(default=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class LogEntry(models.Model):
    source = models.ForeignKey(LogSource, on_delete=models.SET_NULL, null=True, blank=True, related_name="logs")
    component = models.CharField(max_length=32, choices=SecurityComponent.Category.choices, default=SecurityComponent.Category.SIEM)
    raw_message = models.TextField()
    parsed = models.JSONField(default=dict, blank=True)
    source_ip = models.GenericIPAddressField(default="0.0.0.0")
    destination = models.CharField(max_length=180, blank=True)
    event_type = models.CharField(max_length=120, default="Log event")
    severity = models.CharField(max_length=16, choices=SecurityEvent.Severity.choices, default=SecurityEvent.Severity.LOW)
    event = models.ForeignKey(SecurityEvent, on_delete=models.SET_NULL, null=True, blank=True, related_name="log_entries")
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.component}: {self.event_type}"


class CorrelationRule(models.Model):
    name = models.CharField(max_length=140)
    enabled = models.BooleanField(default=True)
    component = models.CharField(max_length=32, choices=SecurityComponent.Category.choices, default=SecurityComponent.Category.SIEM)
    pattern = models.CharField(max_length=280)
    threshold = models.PositiveIntegerField(default=3)
    window_minutes = models.PositiveIntegerField(default=10)
    severity = models.CharField(max_length=16, choices=SecurityEvent.Severity.choices, default=SecurityEvent.Severity.HIGH)
    hit_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name
