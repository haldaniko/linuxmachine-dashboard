import ipaddress
import json
import re
from datetime import timedelta
from urllib.parse import urlparse

from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.db.models import Count, Max, Q, Sum
from django.utils import timezone
from rest_framework import filters, status, viewsets
from rest_framework.decorators import action, api_view
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny
from rest_framework.decorators import permission_classes
from rest_framework.response import Response

from .firewall_service import apply_firewall_rules, build_nft_config
from .crowdsec_service import collect_cscli_metrics
from .models import (
    AccessControlRule,
    AccessPolicy,
    Alert,
    CorrelationRule,
    EDRPolicy,
    EDREndpoint,
    EDREvent,
    EDRThreat,
    EDRVulnerability,
    EndpointAsset,
    FirewallRule,
    IPSAlert,
    IPSCustomRule,
    IPSRule,
    IPSRuleCategory,
    IPSUpdateLog,
    LogEntry,
    LogSource,
    ModuleSetting,
    SecurityComponent,
    SecurityEvent,
    WebFilterRule,
)
from .serializers import (
    AccessControlRuleSerializer,
    AccessPolicySerializer,
    AlertSerializer,
    CorrelationRuleSerializer,
    EDRPolicySerializer,
    EDREndpointSerializer,
    EDREventSerializer,
    EDRThreatSerializer,
    EDRVulnerabilitySerializer,
    EndpointAssetSerializer,
    FirewallRuleSerializer,
    IPSAlertSerializer,
    IPSCustomRuleSerializer,
    IPSRuleSerializer,
    IPSRuleCategorySerializer,
    IPSUpdateLogSerializer,
    LogEntrySerializer,
    LogSourceSerializer,
    ModuleSettingSerializer,
    SecurityComponentSerializer,
    SecurityEventSerializer,
    UserCreateSerializer,
    UserSerializer,
    WebFilterRuleSerializer,
)
from .edr_service import block_event_ip, create_event as create_edr_event, generate_enrollment, get_edr_setting, upsert_endpoint, upsert_vulnerability
from .suricata_event_service import import_eve_file
from .suricata_service import (
    apply_settings as apply_ips_settings,
    apply_suricata_config,
    ensure_default_categories,
    get_ips_setting,
    get_service_status,
    list_interfaces,
    start_suricata,
    stop_suricata,
    update_rules as update_suricata_rules,
    validate_custom_rule,
)


MODULE_DEFAULTS = {
    SecurityComponent.Category.FIREWALL: {
        "display_name": "Firewall: защитна стена",
        "description": "Политики за филтриране на мрежови връзки по CIDR, посока, протокол и порт.",
        "settings": {"default_action": "allow", "log_allowed": True},
    },
    SecurityComponent.Category.IPS: {
        "display_name": "IPS: откриване на прониквания",
        "description": "Сигнатурна инспекция на payload, URL и съобщения със създаване на събития и сигнали.",
        "settings": {"block_on_critical": True, "inspect_payloads": True},
    },
    SecurityComponent.Category.EDR: {
        "display_name": "EDR: сървъри и работни станции",
        "description": "Приемане на endpoint телеметрия, инвентар на активи, риск статуси и препоръки за карантина.",
        "settings": {"auto_quarantine": True, "telemetry_retention_days": 30},
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

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
BLOCKING_ACTIONS = {"block", "reject", "deny", "quarantine"}


@api_view(["POST"])
@permission_classes([AllowAny])
def auth_login(request):
    username = (request.data.get("username") or "").strip()
    password = request.data.get("password") or ""
    user = authenticate(request, username=username, password=password)
    if not user or not user.is_active:
        return Response({"error": "Невалидно потребителско име или парола"}, status=status.HTTP_400_BAD_REQUEST)
    token, _ = Token.objects.get_or_create(user=user)
    return Response({"token": token.key, "user": UserSerializer(user).data})


@api_view(["POST"])
def auth_logout(request):
    Token.objects.filter(user=request.user).delete()
    return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(["GET"])
def auth_me(request):
    return Response(UserSerializer(request.user).data)


@api_view(["GET", "POST"])
def users_manage(request):
    if request.method == "GET":
        return Response(UserSerializer(User.objects.order_by("username"), many=True).data)
    if not request.user.is_staff:
        return Response({"error": "Само администратор може да създава потребители"}, status=status.HTTP_403_FORBIDDEN)
    serializer = UserCreateSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()
    return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)


def ensure_component(component_key):
    if component_key not in MODULE_DEFAULTS:
        component_key = SecurityComponent.Category.SIEM
    defaults = MODULE_DEFAULTS[component_key]
    component, _ = SecurityComponent.objects.get_or_create(
        key=component_key,
        defaults={
            "name": defaults["display_name"],
            "category": component_key,
            "description": defaults["description"],
        },
    )
    return component


def normalize_severity(value, default="low"):
    value = (value or default).lower()
    if value not in SEVERITY_RANK:
        return default
    return value


def normalize_component(value, default=SecurityComponent.Category.SIEM):
    return value if value in MODULE_DEFAULTS else default


def bump_rule(rule):
    rule.hit_count += 1
    rule.last_matched = timezone.now()
    rule.save(update_fields=["hit_count", "last_matched"])


def record_event(component_key, source_ip, destination, event_type, severity, message, action=None, parsed=None):
    component_key = normalize_component(component_key)
    component = ensure_component(component_key)
    severity = normalize_severity(severity)
    event = SecurityEvent.objects.create(
        component=component,
        source_ip=source_ip or "0.0.0.0",
        destination=destination or "",
        event_type=event_type,
        severity=severity,
        message=message,
        extra_data={**(parsed or {}), "action": action or (parsed or {}).get("action", "")},
    )

    component.request_count += 1
    if action in BLOCKING_ACTIONS:
        component.blocked_count += 1
    if severity == "critical":
        component.status = SecurityComponent.Status.CRITICAL
    elif severity == "high" and component.status == SecurityComponent.Status.HEALTHY:
        component.status = SecurityComponent.Status.WARNING
    component.last_checked = timezone.now()
    component.save(update_fields=["request_count", "blocked_count", "status", "last_checked"])

    if severity in {"high", "critical"}:
        Alert.objects.create(
            event=event,
            title=f"{event_type}: {destination or source_ip or component.name}",
            severity=severity,
            assigned_to="SOC",
        )

    if parsed is not None:
        LogEntry.objects.create(
            component=component_key,
            raw_message=message,
            parsed=parsed,
            source_ip=source_ip or "0.0.0.0",
            destination=destination or "",
            event_type=event_type,
            severity=severity,
            event=event,
        )
    return event


def cidr_matches(ip_value, cidr):
    if not cidr or cidr.lower() in {"any", "*"}:
        return True
    try:
        return ipaddress.ip_address(ip_value) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return ip_value == cidr


def port_matches(port_value, spec):
    if not spec or spec.lower() in {"any", "*"}:
        return True
    if port_value in (None, ""):
        return False
    try:
        port = int(port_value)
    except (TypeError, ValueError):
        return False

    for token in [part.strip() for part in spec.split(",") if part.strip()]:
        if "-" in token:
            start, end = token.split("-", 1)
            if int(start) <= port <= int(end):
                return True
        elif int(token) == port:
            return True
    return False


def firewall_rule_matches(rule, payload):
    direction = (payload.get("direction") or "any").lower()
    protocol = (payload.get("protocol") or "any").lower()
    return (
        rule.enabled
        and rule.direction in {FirewallRule.Direction.ANY, direction}
        and rule.protocol in {FirewallRule.Protocol.ANY, protocol}
        and cidr_matches(payload.get("source_ip") or "0.0.0.0", rule.source_cidr)
        and cidr_matches(payload.get("destination_ip") or payload.get("destination") or "0.0.0.0", rule.destination_cidr)
        and port_matches(payload.get("source_port"), getattr(rule, "source_port", "any"))
        and port_matches(payload.get("destination_port"), rule.destination_port)
    )


def evaluate_firewall_payload(payload, persist=False):
    matched_rule = None
    action = ModuleSetting.objects.filter(key=SecurityComponent.Category.FIREWALL).first()
    default_action = (action.settings.get("default_action") if action else "allow") or "allow"

    for rule in FirewallRule.objects.filter(enabled=True).order_by("priority", "id"):
        if firewall_rule_matches(rule, payload):
            matched_rule = rule
            bump_rule(rule)
            break

    result_action = matched_rule.action if matched_rule else default_action
    severity = "medium" if result_action in BLOCKING_ACTIONS else "low"
    destination = payload.get("destination") or payload.get("destination_ip") or ""

    if persist:
        record_event(
            SecurityComponent.Category.FIREWALL,
            payload.get("source_ip"),
            destination,
            "Firewall decision",
            severity,
            f"{result_action.upper()} {payload.get('protocol', 'any')} {payload.get('source_ip', '0.0.0.0')} -> {destination}:{payload.get('destination_port', 'any')}",
            result_action,
            {
                **payload,
                "matched_rule_id": matched_rule.id if matched_rule else None,
                "matched_rule_name": matched_rule.name if matched_rule else "",
            },
        )

    return {
        "action": result_action,
        "matched_rule": FirewallRuleSerializer(matched_rule).data if matched_rule else None,
        "default_action": default_action,
    }


def web_rule_matches(rule, url):
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = (parsed.hostname or "").lower()
    normalized_url = url.lower()
    pattern = rule.pattern.lower()
    if rule.match_type == WebFilterRule.MatchType.DOMAIN:
        return host == pattern or host.endswith(f".{pattern}")
    if rule.match_type == WebFilterRule.MatchType.CONTAINS:
        return pattern in normalized_url
    try:
        return re.search(rule.pattern, url, re.IGNORECASE) is not None
    except re.error:
        return False


def evaluate_web_payload(payload, persist=False):
    url = payload.get("url") or ""
    matched_rule = None
    setting = ModuleSetting.objects.filter(key=SecurityComponent.Category.WEB_FILTER).first()
    default_action = (setting.settings.get("default_action") if setting else "allow") or "allow"

    for rule in WebFilterRule.objects.filter(enabled=True).order_by("priority", "id"):
        if web_rule_matches(rule, url):
            matched_rule = rule
            bump_rule(rule)
            break

    result_action = matched_rule.action if matched_rule else default_action
    severity = "medium" if result_action in {"block", "review"} else "low"

    if persist:
        record_event(
            SecurityComponent.Category.WEB_FILTER,
            payload.get("source_ip"),
            url,
            "URL filtering decision",
            severity,
            f"{result_action.upper()} URL {url}",
            result_action,
            payload,
        )

    return {
        "action": result_action,
        "category": matched_rule.category if matched_rule else "",
        "matched_rule": WebFilterRuleSerializer(matched_rule).data if matched_rule else None,
        "default_action": default_action,
    }


def text_matches(pattern, value):
    try:
        return re.search(pattern, value or "", re.IGNORECASE) is not None
    except re.error:
        return pattern.lower() in (value or "").lower()


def inspect_ips_payload(payload, persist=True):
    matches = []
    final_action = "allow"
    highest = "low"

    for rule in IPSRule.objects.filter(enabled=True).order_by("priority", "id"):
        target = payload.get(rule.match_field) or ""
        if text_matches(rule.pattern, target):
            if persist:
                bump_rule(rule)
            matches.append(rule)
            if rule.action == IPSRule.Action.BLOCK:
                final_action = "block"
            if SEVERITY_RANK.get(rule.severity, 1) > SEVERITY_RANK[highest]:
                highest = rule.severity

    if matches and persist:
        event = record_event(
            SecurityComponent.Category.IPS,
            payload.get("source_ip"),
            payload.get("destination"),
            "IPS signature match",
            highest,
            f"Matched IPS rules: {', '.join(rule.name for rule in matches)}",
            final_action,
            payload,
        )
    else:
        ensure_component(SecurityComponent.Category.IPS)
        event = None

    return {
        "action": final_action,
        "severity": highest,
        "matches": IPSRuleSerializer(matches, many=True).data,
        "event_id": event.id if event else None,
    }


def access_rule_matches(rule, payload):
    network_type = (payload.get("network_type") or "any").lower()
    group = (payload.get("group") or "any").lower()
    rule_group = (rule.group or "any").lower()
    return (
        rule.enabled
        and rule.network_type in {AccessControlRule.NetworkType.ANY, network_type}
        and (rule_group in {"any", "*"} or rule_group == group)
    )


def evaluate_access_payload(payload, persist=False):
    matched_rule = None
    setting = ModuleSetting.objects.filter(key=SecurityComponent.Category.ACCESS).first()
    default_effect = (setting.settings.get("default_effect") if setting else "deny") or "deny"

    for rule in AccessControlRule.objects.filter(enabled=True).order_by("priority", "id"):
        if access_rule_matches(rule, payload):
            matched_rule = rule
            bump_rule(rule)
            break

    effect = matched_rule.effect if matched_rule else default_effect
    mfa_required = matched_rule.mfa_required if matched_rule else default_effect != "deny"
    mfa_verified = bool(payload.get("mfa_verified"))
    if mfa_required and not mfa_verified:
        effect = "deny"

    severity = "high" if effect == "deny" else ("medium" if effect == "review" else "low")
    if persist:
        record_event(
            SecurityComponent.Category.ACCESS,
            payload.get("source_ip"),
            payload.get("username") or payload.get("group") or "",
            "Access decision",
            severity,
            f"{effect.upper()} network={payload.get('network_type', 'any')} user={payload.get('username', '')} group={payload.get('group', '')} mfa={mfa_verified}",
            effect,
            payload,
        )

    return {
        "effect": effect,
        "mfa_required": mfa_required,
        "mfa_verified": mfa_verified,
        "matched_rule": AccessControlRuleSerializer(matched_rule).data if matched_rule else None,
        "default_effect": default_effect,
    }


def apply_correlation(log_entry):
    setting = ModuleSetting.objects.filter(key=SecurityComponent.Category.SIEM).first()
    if setting and not setting.settings.get("correlation_enabled", True):
        return []

    alerts = []
    haystack = f"{log_entry.raw_message} {json.dumps(log_entry.parsed, ensure_ascii=False)}"
    for rule in CorrelationRule.objects.filter(enabled=True):
        if rule.component != SecurityComponent.Category.SIEM and rule.component != log_entry.component:
            continue
        if not text_matches(rule.pattern, haystack):
            continue
        window_start = timezone.now() - timedelta(minutes=rule.window_minutes)
        recent_logs = LogEntry.objects.filter(created_at__gte=window_start, component=log_entry.component).order_by("-created_at")[:300]
        count = sum(1 for entry in recent_logs if text_matches(rule.pattern, f"{entry.raw_message} {json.dumps(entry.parsed, ensure_ascii=False)}"))
        rule.hit_count += 1
        rule.save(update_fields=["hit_count"])
        if count >= rule.threshold:
            event = record_event(
                SecurityComponent.Category.SIEM,
                log_entry.source_ip,
                log_entry.destination,
                "SIEM correlation",
                rule.severity,
                f"Correlation rule '{rule.name}' reached threshold {count}/{rule.threshold}",
                "alert",
                {"log_entry_id": log_entry.id, "rule_id": rule.id},
            )
            alert = Alert.objects.filter(event=event).first()
            if alert:
                alerts.append(alert)
    return alerts


class SecurityComponentViewSet(viewsets.ModelViewSet):
    queryset = SecurityComponent.objects.all()
    serializer_class = SecurityComponentSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["name", "description", "category", "status"]
    ordering_fields = ["name", "status", "last_checked", "blocked_count"]


class ModuleSettingViewSet(viewsets.ModelViewSet):
    queryset = ModuleSetting.objects.all()
    serializer_class = ModuleSettingSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["key", "display_name", "mode", "notes"]
    ordering_fields = ["key", "updated_at"]


class FirewallRuleViewSet(viewsets.ModelViewSet):
    queryset = FirewallRule.objects.all()
    serializer_class = FirewallRuleSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["name", "source_cidr", "source_port", "destination_cidr", "destination_port", "description"]
    ordering_fields = ["priority", "hit_count", "updated_at"]

    @action(detail=True, methods=["post"])
    def enable(self, request, pk=None):
        rule = self.get_object()
        rule.enabled = True
        rule.applied_at = None
        rule.apply_error = ""
        rule.save(update_fields=["enabled", "applied_at", "apply_error", "updated_at"])
        return Response(self.get_serializer(rule).data)

    @action(detail=True, methods=["post"])
    def disable(self, request, pk=None):
        rule = self.get_object()
        rule.enabled = False
        rule.applied_at = None
        rule.apply_error = ""
        rule.save(update_fields=["enabled", "applied_at", "apply_error", "updated_at"])
        return Response(self.get_serializer(rule).data)

    @action(detail=True, methods=["post"], url_path="move-up")
    def move_up(self, request, pk=None):
        return self._move_rule(-1)

    @action(detail=True, methods=["post"], url_path="move-down")
    def move_down(self, request, pk=None):
        return self._move_rule(1)

    def _move_rule(self, direction):
        rules = list(FirewallRule.objects.order_by("priority", "id"))
        current = self.get_object()
        current_index = next((index for index, rule in enumerate(rules) if rule.id == current.id), None)
        target_index = current_index + direction if current_index is not None else None
        if target_index is None or target_index < 0 or target_index >= len(rules):
            return Response(self.get_serializer(current).data)
        rules[current_index], rules[target_index] = rules[target_index], rules[current_index]
        for index, rule in enumerate(rules, start=10):
            rule.priority = index * 10
            rule.applied_at = None
            rule.apply_error = ""
            rule.save(update_fields=["priority", "applied_at", "apply_error", "updated_at"])
        return Response(FirewallRuleSerializer(FirewallRule.objects.order_by("priority", "id"), many=True).data)


class IPSRuleViewSet(viewsets.ModelViewSet):
    queryset = IPSRule.objects.all()
    serializer_class = IPSRuleSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["name", "pattern", "description"]
    ordering_fields = ["priority", "hit_count", "updated_at"]


class IPSRuleCategoryViewSet(viewsets.ModelViewSet):
    queryset = IPSRuleCategory.objects.all()
    serializer_class = IPSRuleCategorySerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["name", "description"]
    ordering_fields = ["name", "rule_count", "updated_at"]


class IPSCustomRuleViewSet(viewsets.ModelViewSet):
    queryset = IPSCustomRule.objects.all()
    serializer_class = IPSCustomRuleSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["name", "raw_rule"]
    ordering_fields = ["sid", "updated_at"]

    def perform_create(self, serializer):
        rule = serializer.save()
        try:
            validate_custom_rule(rule.raw_rule, rule.sid)
            rule.validation_error = ""
        except ValueError as exc:
            rule.validation_error = str(exc)
        rule.save(update_fields=["validation_error", "updated_at"])

    def perform_update(self, serializer):
        rule = serializer.save()
        try:
            validate_custom_rule(rule.raw_rule, rule.sid)
            rule.validation_error = ""
        except ValueError as exc:
            rule.validation_error = str(exc)
        rule.save(update_fields=["validation_error", "updated_at"])


class IPSAlertViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = IPSAlert.objects.all()
    serializer_class = IPSAlertSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["signature", "category", "source_ip", "destination_ip", "protocol", "action", "interface"]
    ordering_fields = ["timestamp", "severity", "signature", "category", "action"]


class EDRPolicyViewSet(viewsets.ModelViewSet):
    queryset = EDRPolicy.objects.all()
    serializer_class = EDRPolicySerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["name", "telemetry_level", "protected_paths"]
    ordering_fields = ["name", "updated_at"]


class EDREndpointViewSet(viewsets.ModelViewSet):
    queryset = EDREndpoint.objects.all()
    serializer_class = EDREndpointSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["hostname", "ip", "os", "agent_id", "external_id", "logged_in_user"]
    ordering_fields = ["hostname", "status", "security_status", "last_seen"]

    def get_queryset(self):
        return EDREndpoint.objects.annotate(threats_count=Count("threats"), vulnerabilities_count=Count("vulnerabilities"))


class EDREventViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = EDREvent.objects.select_related("endpoint")
    serializer_class = EDREventSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["title", "description", "category", "severity", "endpoint__hostname", "process_name", "file_path", "source_ip", "destination_ip"]
    ordering_fields = ["timestamp", "severity", "category"]


class EDRThreatViewSet(viewsets.ModelViewSet):
    queryset = EDRThreat.objects.select_related("endpoint", "event")
    serializer_class = EDRThreatSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["title", "category", "severity", "status", "endpoint__hostname"]
    ordering_fields = ["created_at", "severity", "status"]


class EDRVulnerabilityViewSet(viewsets.ModelViewSet):
    queryset = EDRVulnerability.objects.select_related("endpoint")
    serializer_class = EDRVulnerabilitySerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["cve", "package", "severity", "status", "endpoint__hostname"]
    ordering_fields = ["created_at", "severity", "status"]


class WebFilterRuleViewSet(viewsets.ModelViewSet):
    queryset = WebFilterRule.objects.all()
    serializer_class = WebFilterRuleSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["name", "pattern", "category"]
    ordering_fields = ["priority", "hit_count", "updated_at"]


class AccessControlRuleViewSet(viewsets.ModelViewSet):
    queryset = AccessControlRule.objects.all()
    serializer_class = AccessControlRuleSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["name", "network_type", "group"]
    ordering_fields = ["priority", "hit_count", "updated_at"]


class SecurityEventViewSet(viewsets.ModelViewSet):
    queryset = SecurityEvent.objects.select_related("component")
    serializer_class = SecurityEventSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["source_ip", "destination", "event_type", "message", "severity", "status"]
    ordering_fields = ["occurred_at", "severity", "status"]


class AlertViewSet(viewsets.ModelViewSet):
    queryset = Alert.objects.select_related("event")
    serializer_class = AlertSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["title", "severity", "status", "assigned_to"]
    ordering_fields = ["created_at", "severity", "status"]


class AccessPolicyViewSet(viewsets.ModelViewSet):
    queryset = AccessPolicy.objects.all()
    serializer_class = AccessPolicySerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["name", "scope", "category", "effect"]
    ordering_fields = ["name", "hit_count", "updated_at"]


class EndpointAssetViewSet(viewsets.ModelViewSet):
    queryset = EndpointAsset.objects.all()
    serializer_class = EndpointAssetSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["name", "owner", "ip_address", "operating_system", "risk_level", "edr_status"]
    ordering_fields = ["last_seen", "risk_level", "name"]


class LogSourceViewSet(viewsets.ModelViewSet):
    queryset = LogSource.objects.all()
    serializer_class = LogSourceSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["name", "component", "parser"]
    ordering_fields = ["name", "last_seen", "created_at"]


class LogEntryViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = LogEntry.objects.select_related("source", "event")
    serializer_class = LogEntrySerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["raw_message", "source_ip", "destination", "event_type", "severity"]
    ordering_fields = ["created_at", "severity"]


class CorrelationRuleViewSet(viewsets.ModelViewSet):
    queryset = CorrelationRule.objects.all()
    serializer_class = CorrelationRuleSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["name", "component", "pattern", "severity"]
    ordering_fields = ["name", "hit_count", "updated_at"]


@api_view(["GET"])
def dashboard_overview(request):
    now = timezone.now()
    day_ago = now - timedelta(hours=24)
    week_ago = now - timedelta(days=7)

    components = SecurityComponent.objects.all()
    recent_events = SecurityEvent.objects.filter(occurred_at__gte=day_ago)
    open_alerts = Alert.objects.exclude(status=SecurityEvent.Status.RESOLVED)
    traffic_totals = components.aggregate(requests=Sum("request_count"), blocked=Sum("blocked_count"))

    timeline = []
    for day_offset in range(6, -1, -1):
        day = (now - timedelta(days=day_offset)).date()
        day_events = SecurityEvent.objects.filter(occurred_at__date=day)
        timeline.append(
            {
                "date": day.isoformat(),
                "events": day_events.count(),
                "blocked": day_events.filter(severity__in=[SecurityEvent.Severity.HIGH, SecurityEvent.Severity.CRITICAL]).count(),
            }
        )

    return Response(
        {
            "generated_at": now,
            "kpis": {
                "components_total": components.count(),
                "components_attention": components.filter(status__in=[SecurityComponent.Status.WARNING, SecurityComponent.Status.CRITICAL, SecurityComponent.Status.OFFLINE]).count(),
                "requests_24h": traffic_totals["requests"] or 0,
                "blocked_24h": traffic_totals["blocked"] or 0,
                "events_24h": recent_events.count(),
                "open_alerts": open_alerts.count(),
                "critical_assets": EndpointAsset.objects.filter(risk_level__in=[EndpointAsset.RiskLevel.HIGH, EndpointAsset.RiskLevel.CRITICAL]).count(),
                "active_rules": (
                    FirewallRule.objects.filter(enabled=True).count()
                    + IPSRule.objects.filter(enabled=True).count()
                    + WebFilterRule.objects.filter(enabled=True).count()
                    + AccessControlRule.objects.filter(enabled=True).count()
                ),
                "log_entries": LogEntry.objects.filter(created_at__gte=day_ago).count(),
            },
            "severity_breakdown": list(SecurityEvent.objects.values("severity").annotate(count=Count("id")).order_by("severity")),
            "component_breakdown": list(SecurityEvent.objects.values("component__category").annotate(count=Count("id")).order_by("component__category")),
            "timeline": timeline,
            "top_sources": list(
                SecurityEvent.objects.filter(occurred_at__gte=week_ago)
                .values("source_ip")
                .annotate(count=Count("id"), critical=Count("id", filter=Q(severity=SecurityEvent.Severity.CRITICAL)))
                .order_by("-count")[:6]
            ),
        }
    )


@api_view(["POST"])
def firewall_evaluate(request):
    return Response(evaluate_firewall_payload(request.data, persist=False))


@api_view(["POST"])
def firewall_ingest(request):
    return Response(evaluate_firewall_payload(request.data, persist=True), status=status.HTTP_201_CREATED)


def get_firewall_setting():
    defaults = MODULE_DEFAULTS[SecurityComponent.Category.FIREWALL]
    setting, _ = ModuleSetting.objects.get_or_create(
        key=SecurityComponent.Category.FIREWALL,
        defaults={
            "display_name": defaults["display_name"],
            "enabled": True,
            "mode": ModuleSetting.Mode.MONITOR,
            "settings": defaults["settings"],
        },
    )
    return setting


@api_view(["GET"])
def firewall_status(request):
    now = timezone.now()
    day_ago = now - timedelta(hours=24)
    setting = get_firewall_setting()
    rules = FirewallRule.objects.all()
    last_rule_update = rules.aggregate(value=Max("updated_at"))["value"]
    last_apply = rules.exclude(applied_at=None).aggregate(value=Max("applied_at"))["value"]
    has_unapplied = rules.filter(Q(applied_at=None) | Q(updated_at__gt=last_apply)).exists() if last_apply else rules.exists()
    blocked_events = SecurityEvent.objects.filter(
        component__category=SecurityComponent.Category.FIREWALL,
        occurred_at__gte=day_ago,
        extra_data__action__in=["block", "reject"],
    ).count()
    return Response(
        {
            "enabled": setting.enabled,
            "backend": "nftables",
            "active_rules": rules.filter(enabled=True).count(),
            "blocked_24h": blocked_events,
            "last_rule_update": last_rule_update,
            "last_apply": last_apply,
            "has_unapplied_changes": has_unapplied,
            "table": "inet security_platform",
        }
    )


@api_view(["POST"])
def firewall_apply(request):
    setting = get_firewall_setting()
    rules = FirewallRule.objects.filter(enabled=True).order_by("priority", "id")
    result = apply_firewall_rules(request, rules, firewall_enabled=setting.enabled)
    now = timezone.now()
    if result.ok:
        FirewallRule.objects.update(applied_at=now, apply_error="")
        SecurityComponent.objects.filter(category=SecurityComponent.Category.FIREWALL).update(last_checked=now)
    else:
        FirewallRule.objects.update(apply_error=result.error)
    return Response(
        {
            "ok": result.ok,
            "message": result.message,
            "warning": result.warning,
            "error": result.error,
            "config": result.config,
        },
        status=status.HTTP_200_OK if result.ok or result.warning else status.HTTP_400_BAD_REQUEST,
    )


@api_view(["GET"])
def firewall_events(request):
    events = SecurityEvent.objects.select_related("component").filter(component__category=SecurityComponent.Category.FIREWALL)
    ip_filter = request.query_params.get("ip")
    action_filter = request.query_params.get("action")
    protocol_filter = request.query_params.get("protocol")
    if ip_filter:
        events = events.filter(Q(source_ip__icontains=ip_filter) | Q(destination__icontains=ip_filter))
    if action_filter:
        events = events.filter(extra_data__action=action_filter)
    if protocol_filter:
        events = events.filter(extra_data__protocol=protocol_filter)
    return Response(SecurityEventSerializer(events.order_by("-occurred_at")[:100], many=True).data)


@api_view(["POST"])
def firewall_enable(request):
    setting = get_firewall_setting()
    setting.enabled = True
    setting.save(update_fields=["enabled", "updated_at"])
    config = build_nft_config(FirewallRule.objects.filter(enabled=True).order_by("priority", "id"), firewall_enabled=True)
    return Response({"enabled": True, "backend": "nftables", "config": config})


@api_view(["POST"])
def firewall_disable(request):
    setting = get_firewall_setting()
    setting.enabled = False
    setting.save(update_fields=["enabled", "updated_at"])
    config = build_nft_config([], firewall_enabled=False)
    return Response({"enabled": False, "backend": "nftables", "config": config})


@api_view(["POST"])
def web_filter_check(request):
    return Response(evaluate_web_payload(request.data, persist=True), status=status.HTTP_201_CREATED)


@api_view(["POST"])
def web_filter_evaluate(request):
    return Response(evaluate_web_payload(request.data, persist=False))


@api_view(["POST"])
def ips_inspect(request):
    return Response(inspect_ips_payload(request.data), status=status.HTTP_201_CREATED)


@api_view(["POST"])
def ips_evaluate(request):
    return Response(inspect_ips_payload(request.data, persist=False))


@api_view(["GET"])
def ips_status(request):
    ensure_default_categories()
    import_eve_file()
    now = timezone.now()
    day_ago = now - timedelta(hours=24)
    setting = get_ips_setting()
    service = get_service_status()
    alerts = IPSAlert.objects.filter(timestamp__gte=day_ago)
    return Response(
        {
            "enabled": setting.enabled,
            "engine": "suricata",
            "mode": (setting.settings or {}).get("mode", "ids"),
            "service_status": service["status"],
            "service_message": service.get("message", ""),
            "version": service.get("version", ""),
            "rules_enabled": IPSRuleCategory.objects.filter(enabled=True).aggregate(total=Sum("rule_count"))["total"] or IPSCustomRule.objects.filter(enabled=True).count(),
            "alerts_24h": alerts.count(),
            "blocked_24h": alerts.filter(action__in=["drop", "blocked", "block"]).count(),
            "high_severity": alerts.filter(severity__in=["high", "critical"]).count(),
            "last_event": IPSAlert.objects.order_by("-timestamp").values_list("timestamp", flat=True).first(),
            "interfaces": list_interfaces(),
        }
    )


@api_view(["GET"])
def ips_events(request):
    import_eve_file()
    events = IPSAlert.objects.all()
    filters_map = {
        "severity": "severity",
        "source_ip": "source_ip__icontains",
        "destination_ip": "destination_ip__icontains",
        "protocol": "protocol__iexact",
        "category": "category__icontains",
        "action": "action__icontains",
        "search": "signature__icontains",
    }
    for param, lookup in filters_map.items():
        value = request.query_params.get(param)
        if value:
            events = events.filter(**{lookup: value})
    return Response(IPSAlertSerializer(events.order_by("-timestamp")[:1000], many=True).data)


@api_view(["GET"])
def ips_event_detail(request, event_id):
    alert = IPSAlert.objects.get(id=event_id)
    return Response(IPSAlertSerializer(alert).data)


@api_view(["GET"])
def ips_rule_categories(request):
    ensure_default_categories()
    return Response(IPSRuleCategorySerializer(IPSRuleCategory.objects.all(), many=True).data)


@api_view(["GET", "PUT"])
def ips_settings(request):
    setting = get_ips_setting()
    if request.method == "PUT":
        try:
            setting = apply_ips_settings(request.data)
        except ValueError as exc:
            return Response({"error": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
    payload = ModuleSettingSerializer(setting).data
    payload["interfaces"] = list_interfaces()
    return Response(payload)


@api_view(["POST"])
def ips_apply(request):
    try:
        if request.data:
            apply_ips_settings(request.data)
        result = apply_suricata_config()
    except ValueError as exc:
        return Response({"ok": False, "error": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
    return Response(result, status=status.HTTP_200_OK if result.get("ok") else status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
def ips_start(request):
    setting = get_ips_setting()
    setting.enabled = True
    setting.save(update_fields=["enabled", "updated_at"])
    result = start_suricata()
    result["enabled"] = True
    return Response(result, status=status.HTTP_200_OK if result.get("ok") else status.HTTP_200_OK)


@api_view(["POST"])
def ips_stop(request):
    setting = get_ips_setting()
    setting.enabled = False
    setting.save(update_fields=["enabled", "updated_at"])
    result = stop_suricata()
    result["enabled"] = False
    return Response(result, status=status.HTTP_200_OK)


@api_view(["POST"])
def ips_update_rules(request):
    log = update_suricata_rules()
    return Response(IPSUpdateLogSerializer(log).data, status=status.HTTP_200_OK if log.status == "success" else status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
def ips_block_source(request, event_id):
    alert = IPSAlert.objects.get(id=event_id)
    ip = ipaddress.ip_address(alert.source_ip)
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return Response({"error": "Этот адрес нельзя автоматически заблокировать из IPS-события"}, status=status.HTTP_400_BAD_REQUEST)
    rule = FirewallRule.objects.create(
        name=f"Block IPS source {alert.source_ip}",
        enabled=True,
        priority=50,
        action=FirewallRule.Action.BLOCK,
        direction=FirewallRule.Direction.INBOUND,
        protocol=FirewallRule.Protocol.ANY,
        source_cidr=f"{alert.source_ip}/32" if ip.version == 4 else f"{alert.source_ip}/128",
        source_port="any",
        destination_cidr="any",
        destination_port="any",
        description=f"Created from IPS event SID {alert.signature_id or '-'}",
    )
    return Response(FirewallRuleSerializer(rule).data, status=status.HTTP_201_CREATED)


@api_view(["POST"])
def edr_telemetry(request):
    payload = request.data
    hostname = payload.get("hostname") or payload.get("name")
    if not hostname:
        return Response({"detail": "hostname is required"}, status=status.HTTP_400_BAD_REQUEST)

    severity = normalize_severity(payload.get("severity"), "low")
    command_line = payload.get("command_line") or ""
    process_name = payload.get("process_name") or ""
    threat_name = payload.get("threat_name") or ""
    suspicious_markers = [" -enc", "mimikatz", "credential dump", "rundll32", "encodedcommand"]
    suspicious = bool(threat_name) or any(marker in command_line.lower() for marker in suspicious_markers)
    if suspicious and severity == "low":
        severity = "high"

    risk_level = severity if severity in {"medium", "high", "critical"} else "low"
    status_text = "Quarantine recommended" if risk_level in {"high", "critical"} else "Protected"

    asset, _ = EndpointAsset.objects.get_or_create(
        name=hostname,
        defaults={
            "owner": payload.get("owner") or "",
            "ip_address": payload.get("ip_address") or payload.get("source_ip") or "0.0.0.0",
            "operating_system": payload.get("operating_system") or "",
            "risk_level": risk_level,
            "edr_status": status_text,
        },
    )
    asset.owner = payload.get("owner") or asset.owner
    asset.ip_address = payload.get("ip_address") or payload.get("source_ip") or asset.ip_address
    asset.operating_system = payload.get("operating_system") or asset.operating_system
    asset.risk_level = risk_level
    asset.edr_status = status_text
    asset.last_seen = timezone.now()
    asset.save()

    event = None
    if suspicious or severity in {"medium", "high", "critical"}:
        event = record_event(
            SecurityComponent.Category.EDR,
            asset.ip_address,
            hostname,
            threat_name or "Endpoint telemetry",
            severity,
            f"process={process_name} command={command_line}",
            "quarantine" if risk_level in {"high", "critical"} else "alert",
            payload,
        )

    return Response(
        {
            "asset": EndpointAssetSerializer(asset).data,
            "event_id": event.id if event else None,
            "suspicious": suspicious,
        },
        status=status.HTTP_201_CREATED,
    )


@api_view(["GET"])
def edr_status(request):
    now = timezone.now()
    day_ago = now - timedelta(hours=24)
    setting = get_edr_setting()
    endpoints = EDREndpoint.objects.all()
    events_24h = EDREvent.objects.filter(timestamp__gte=day_ago)
    return Response(
        {
            "enabled": setting.enabled,
            "provider": (setting.settings or {}).get("provider", "wazuh"),
            "endpoints": endpoints.count(),
            "online": endpoints.filter(status=EDREndpoint.AgentStatus.ONLINE).count(),
            "offline": endpoints.filter(status=EDREndpoint.AgentStatus.OFFLINE).count(),
            "never_connected": endpoints.filter(status=EDREndpoint.AgentStatus.NEVER_CONNECTED).count(),
            "threats_24h": EDRThreat.objects.filter(created_at__gte=day_ago).count(),
            "critical_24h": events_24h.filter(severity="critical").count(),
            "high_24h": events_24h.filter(severity="high").count(),
            "vulnerable_endpoints": endpoints.filter(vulnerabilities__status__iexact="open").distinct().count(),
            "last_event": EDREvent.objects.order_by("-timestamp").values_list("timestamp", flat=True).first(),
        }
    )


@api_view(["GET"])
def edr_crowdsec_metrics(request):
    return Response(collect_cscli_metrics())


@api_view(["GET"])
def edr_endpoint_events(request, endpoint_id):
    return Response(EDREventSerializer(EDREvent.objects.filter(endpoint_id=endpoint_id).order_by("-timestamp")[:1000], many=True).data)


@api_view(["GET"])
def edr_endpoint_vulnerabilities(request, endpoint_id):
    return Response(EDRVulnerabilitySerializer(EDRVulnerability.objects.filter(endpoint_id=endpoint_id), many=True).data)


@api_view(["POST"])
def edr_endpoint_register(request):
    try:
        endpoint = upsert_endpoint(request.data)
    except ValueError as exc:
        return Response({"error": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
    return Response(EDREndpointSerializer(endpoint).data, status=status.HTTP_201_CREATED)


@api_view(["POST"])
def edr_event_ingest(request):
    try:
        event = create_edr_event(request.data)
    except (ValueError, EDREndpoint.DoesNotExist) as exc:
        return Response({"error": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
    record_event(
        SecurityComponent.Category.EDR,
        event.source_ip,
        event.destination_ip or "",
        event.event_type,
        event.severity if event.severity != "informational" else "low",
        event.title,
        event.action,
        {"category": event.category, "endpoint_id": event.endpoint_id, "process": event.process_name, "file": event.file_path},
    )
    return Response(EDREventSerializer(event).data, status=status.HTTP_201_CREATED)


@api_view(["POST"])
def edr_vulnerability_ingest(request):
    try:
        vulnerability = upsert_vulnerability(request.data)
    except (KeyError, ValueError, EDREndpoint.DoesNotExist) as exc:
        return Response({"error": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
    return Response(EDRVulnerabilitySerializer(vulnerability).data, status=status.HTTP_201_CREATED)


@api_view(["GET"])
def edr_events(request):
    events = EDREvent.objects.select_related("endpoint")
    for param, lookup in {
        "severity": "severity",
        "category": "category__icontains",
        "endpoint": "endpoint__hostname__icontains",
        "source_ip": "source_ip__icontains",
        "search": "title__icontains",
    }.items():
        value = request.query_params.get(param)
        if value:
            events = events.filter(**{lookup: value})
    return Response(EDREventSerializer(events.order_by("-timestamp")[:1000], many=True).data)


@api_view(["GET"])
def edr_event_detail(request, event_id):
    return Response(EDREventSerializer(EDREvent.objects.get(id=event_id)).data)


@api_view(["GET"])
def edr_threats(request):
    return Response(EDRThreatSerializer(EDRThreat.objects.select_related("endpoint", "event").all()[:1000], many=True).data)


@api_view(["PUT"])
def edr_threat_status(request, threat_id):
    threat = EDRThreat.objects.get(id=threat_id)
    new_status = request.data.get("status")
    if new_status not in dict(EDRThreat.Status.choices):
        return Response({"error": "Некорректный статус угрозы"}, status=status.HTTP_400_BAD_REQUEST)
    threat.status = new_status
    threat.save(update_fields=["status", "updated_at"])
    return Response(EDRThreatSerializer(threat).data)


@api_view(["POST"])
def edr_event_block_ip(request, event_id):
    event = EDREvent.objects.get(id=event_id)
    try:
        rule = block_event_ip(event)
    except ValueError as exc:
        return Response({"error": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
    return Response(FirewallRuleSerializer(rule).data, status=status.HTTP_201_CREATED)


@api_view(["GET"])
def edr_install_linux(request):
    return Response(generate_enrollment("linux"))


@api_view(["GET"])
def edr_install_windows(request):
    return Response(generate_enrollment("windows"))


@api_view(["GET", "PUT"])
def edr_settings(request):
    setting = get_edr_setting()
    if request.method == "PUT":
        payload = request.data
        current = setting.settings or {}
        setting.enabled = bool(payload.get("enabled", setting.enabled))
        setting.settings = {
            **current,
            "provider": "wazuh",
            "manager_url": payload.get("manager_url", current.get("manager_url", "http://localhost:55000")),
            "agent_offline_timeout_minutes": int(payload.get("agent_offline_timeout_minutes", current.get("agent_offline_timeout_minutes", 15))),
            "event_retention_days": int(payload.get("event_retention_days", current.get("event_retention_days", 90))),
            "automatic_refresh": bool(payload.get("automatic_refresh", current.get("automatic_refresh", True))),
        }
        setting.save(update_fields=["enabled", "settings", "updated_at"])
    return Response(ModuleSettingSerializer(setting).data)


@api_view(["POST"])
def access_check(request):
    return Response(evaluate_access_payload(request.data, persist=True), status=status.HTTP_201_CREATED)


@api_view(["POST"])
def access_evaluate(request):
    return Response(evaluate_access_payload(request.data, persist=False))


@api_view(["POST"])
def siem_ingest_log(request):
    payload = request.data
    source_name = payload.get("source") or "api"
    component = normalize_component(payload.get("component"))
    raw_message = payload.get("raw_message") or payload.get("message") or json.dumps(payload, ensure_ascii=False)

    source, _ = LogSource.objects.get_or_create(
        name=source_name,
        defaults={"component": component, "parser": payload.get("parser") or LogSource.Parser.JSON},
    )
    if not source.enabled:
        return Response({"detail": "log source is disabled"}, status=status.HTTP_400_BAD_REQUEST)
    source.last_seen = timezone.now()
    source.component = component
    source.save(update_fields=["last_seen", "component"])

    severity = normalize_severity(payload.get("severity"), "low")
    event = record_event(
        component,
        payload.get("source_ip"),
        payload.get("destination"),
        payload.get("event_type") or "SIEM log",
        severity,
        raw_message,
        "alert" if severity in {"high", "critical"} else "log",
        payload.get("parsed") or payload,
    )
    log_entry = LogEntry.objects.filter(event=event).first()
    if log_entry:
        log_entry.source = source
        log_entry.save(update_fields=["source"])
        correlation_alerts = apply_correlation(log_entry)
    else:
        correlation_alerts = []

    return Response(
        {
            "event": SecurityEventSerializer(event).data,
            "log_entry": LogEntrySerializer(log_entry).data if log_entry else None,
            "correlation_alerts": AlertSerializer(correlation_alerts, many=True).data,
        },
        status=status.HTTP_201_CREATED,
    )
