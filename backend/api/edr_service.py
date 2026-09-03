import ipaddress
import secrets
from datetime import timedelta

from django.utils import timezone

from .models import (
    EDREndpoint,
    EDREnrollmentToken,
    EDREvent,
    EDRThreat,
    EDRVulnerability,
    FirewallRule,
    ModuleSetting,
    SecurityComponent,
)


THREAT_CATEGORIES = {"malware", "suspicious_process", "network_attack", "policy_violation", "rootkit"}


def get_edr_setting():
    defaults = {
        "provider": "wazuh",
        "manager_url": "http://localhost:55000",
        "agent_offline_timeout_minutes": 15,
        "event_retention_days": 90,
        "automatic_refresh": True,
    }
    setting, _ = ModuleSetting.objects.get_or_create(
        key=SecurityComponent.Category.EDR,
        defaults={"display_name": "EDR", "enabled": True, "settings": defaults},
    )
    merged = {**defaults, **(setting.settings or {})}
    if merged != setting.settings:
        setting.settings = merged
        setting.save(update_fields=["settings", "updated_at"])
    return setting


def normalize_severity(value):
    if isinstance(value, int):
        if value >= 13:
            return "critical"
        if value >= 10:
            return "high"
        if value >= 6:
            return "medium"
        if value >= 3:
            return "low"
        return "informational"
    value = str(value or "low").lower()
    aliases = {"info": "informational", "notice": "low", "warn": "medium", "warning": "medium", "error": "high", "fatal": "critical"}
    return aliases.get(value, value if value in {"informational", "low", "medium", "high", "critical"} else "low")


def normalize_category(value):
    value = str(value or "system").lower().replace(" ", "_").replace("-", "_")
    if "malware" in value or "virus" in value:
        return "malware"
    if "process" in value:
        return "suspicious_process"
    if "file" in value or "integrity" in value or "fim" in value:
        return "file_integrity"
    if "network" in value or "ssh" in value or "brute" in value:
        return "network_attack"
    if "vulnerab" in value or "cve" in value:
        return "vulnerability"
    if "policy" in value:
        return "policy_violation"
    return value


def recalculate_endpoint(endpoint):
    high_events = endpoint.events.filter(severity__in=["high", "critical"]).count()
    open_vulns = endpoint.vulnerabilities.exclude(status__iexact="resolved").count()
    critical_vulns = endpoint.vulnerabilities.filter(severity="critical").exclude(status__iexact="resolved").count()
    if high_events or critical_vulns:
        endpoint.security_status = EDREndpoint.SecurityStatus.CRITICAL if endpoint.events.filter(severity="critical").exists() or critical_vulns else EDREndpoint.SecurityStatus.AT_RISK
    elif open_vulns >= 5 or endpoint.events.filter(severity="medium").exists():
        endpoint.security_status = EDREndpoint.SecurityStatus.ATTENTION
    else:
        endpoint.security_status = EDREndpoint.SecurityStatus.PROTECTED
    endpoint.save(update_fields=["security_status", "updated_at"])


def upsert_endpoint(payload):
    hostname = payload.get("hostname") or payload.get("name")
    if not hostname:
        raise ValueError("Укажите hostname endpoint")
    ip_value = payload.get("ip") or payload.get("ip_address") or "0.0.0.0"
    ipaddress.ip_address(ip_value)
    endpoint, _ = EDREndpoint.objects.get_or_create(
        external_id=payload.get("external_id", ""),
        hostname=hostname,
        defaults={"ip": ip_value},
    )
    endpoint.ip = ip_value
    endpoint.os = payload.get("os") or payload.get("operating_system") or endpoint.os
    endpoint.os_version = payload.get("os_version", endpoint.os_version)
    endpoint.architecture = payload.get("architecture", endpoint.architecture)
    endpoint.agent_version = payload.get("agent_version", endpoint.agent_version)
    endpoint.agent_id = payload.get("agent_id", endpoint.agent_id)
    endpoint.provider = payload.get("provider", endpoint.provider or "wazuh")
    endpoint.logged_in_user = payload.get("username") or payload.get("logged_in_user") or endpoint.logged_in_user
    endpoint.status = payload.get("status", EDREndpoint.AgentStatus.ONLINE)
    endpoint.last_seen = timezone.now()
    endpoint.save()
    return endpoint


def create_event(payload):
    endpoint = None
    endpoint_payload = payload.get("endpoint") or {}
    if payload.get("endpoint_id"):
        endpoint = EDREndpoint.objects.filter(id=payload["endpoint_id"]).first()
    if not endpoint and (endpoint_payload or payload.get("hostname")):
        endpoint = upsert_endpoint({**endpoint_payload, **payload})

    event = EDREvent.objects.create(
        endpoint=endpoint,
        event_type=payload.get("event_type", "security_event"),
        category=normalize_category(payload.get("category") or payload.get("event_type")),
        severity=normalize_severity(payload.get("severity")),
        title=payload.get("title") or payload.get("event") or "EDR event",
        description=payload.get("description", ""),
        process_name=payload.get("process_name", ""),
        process_path=payload.get("process_path", ""),
        process_id=str(payload.get("process_id", "")),
        parent_process=payload.get("parent_process", ""),
        username=payload.get("username", ""),
        source_ip=payload.get("source_ip") or None,
        destination_ip=payload.get("destination_ip") or None,
        source_port=payload.get("source_port") or None,
        destination_port=payload.get("destination_port") or None,
        protocol=payload.get("protocol", ""),
        file_path=payload.get("file_path", ""),
        file_hash=payload.get("file_hash", ""),
        action=payload.get("action", "alert"),
        rule_id=payload.get("rule_id", ""),
        source=payload.get("source", "wazuh"),
        raw_event=payload.get("raw_event") or payload,
    )
    if event.category in THREAT_CATEGORIES or event.severity in {"high", "critical"}:
        EDRThreat.objects.create(event=event, endpoint=endpoint, title=event.title, category=event.category, severity=event.severity)
    if endpoint:
        recalculate_endpoint(endpoint)
    return event


def upsert_vulnerability(payload):
    endpoint = EDREndpoint.objects.get(id=payload["endpoint_id"])
    vulnerability, _ = EDRVulnerability.objects.update_or_create(
        endpoint=endpoint,
        cve=payload["cve"],
        package=payload.get("package", ""),
        defaults={
            "installed_version": payload.get("installed_version", ""),
            "fixed_version": payload.get("fixed_version", ""),
            "severity": normalize_severity(payload.get("severity")),
            "status": payload.get("status", "open"),
        },
    )
    recalculate_endpoint(endpoint)
    return vulnerability


def generate_enrollment(platform):
    setting = get_edr_setting()
    token = EDREnrollmentToken.objects.create(
        token=secrets.token_urlsafe(32),
        platform=platform,
        manager_url=(setting.settings or {}).get("manager_url", "http://localhost:55000"),
        expires_at=timezone.now() + timedelta(hours=24),
    )
    if platform == "windows":
        command = f"wazuh-agent.msi /q WAZUH_MANAGER='{token.manager_url}' WAZUH_REGISTRATION_TOKEN='{token.token}'"
    else:
        command = f"sudo WAZUH_MANAGER='{token.manager_url}' WAZUH_REGISTRATION_TOKEN='{token.token}' apt-get install wazuh-agent"
    return {"token": token.token, "expires_at": token.expires_at, "manager_url": token.manager_url, "platform": platform, "command": command}


def block_event_ip(event):
    ip_value = event.source_ip or event.destination_ip
    if not ip_value:
        raise ValueError("В событии нет IP для блокировки")
    ip = ipaddress.ip_address(ip_value)
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        raise ValueError("Этот адрес нельзя автоматически заблокировать из EDR-события")
    return FirewallRule.objects.create(
        name=f"Block EDR source {ip_value}",
        enabled=True,
        priority=50,
        action=FirewallRule.Action.BLOCK,
        direction=FirewallRule.Direction.INBOUND,
        protocol=FirewallRule.Protocol.ANY,
        source_cidr=f"{ip_value}/32" if ip.version == 4 else f"{ip_value}/128",
        source_port="any",
        destination_cidr="any",
        destination_port="any",
        description=f"Created from EDR event {event.id}",
    )
