from django.contrib import admin

from .models import (
    AccessControlRule,
    AccessPolicy,
    Alert,
    CorrelationRule,
    EDRPolicy,
    EDREndpoint,
    EDREnrollmentToken,
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


@admin.register(SecurityComponent)
class SecurityComponentAdmin(admin.ModelAdmin):
    list_display = ("name", "category", "status", "request_count", "blocked_count", "last_checked")
    list_filter = ("category", "status")
    search_fields = ("name", "description")


@admin.register(ModuleSetting)
class ModuleSettingAdmin(admin.ModelAdmin):
    list_display = ("display_name", "key", "enabled", "mode", "updated_at")
    list_filter = ("key", "enabled", "mode")
    search_fields = ("display_name", "notes")


@admin.register(FirewallRule)
class FirewallRuleAdmin(admin.ModelAdmin):
    list_display = ("priority", "name", "enabled", "action", "direction", "protocol", "source_port", "destination_port", "hit_count", "applied_at")
    list_filter = ("enabled", "action", "direction", "protocol")
    search_fields = ("name", "source_cidr", "source_port", "destination_cidr", "destination_port", "description")


@admin.register(IPSRule)
class IPSRuleAdmin(admin.ModelAdmin):
    list_display = ("priority", "name", "enabled", "match_field", "action", "severity", "hit_count")
    list_filter = ("enabled", "match_field", "action", "severity")
    search_fields = ("name", "pattern", "description")


@admin.register(IPSRuleCategory)
class IPSRuleCategoryAdmin(admin.ModelAdmin):
    list_display = ("name", "enabled", "rule_count", "updated_at")
    list_filter = ("enabled",)
    search_fields = ("name", "description")


@admin.register(IPSCustomRule)
class IPSCustomRuleAdmin(admin.ModelAdmin):
    list_display = ("sid", "name", "enabled", "applied_at", "updated_at")
    list_filter = ("enabled",)
    search_fields = ("name", "raw_rule")


@admin.register(IPSAlert)
class IPSAlertAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "severity", "signature", "source_ip", "destination_ip", "protocol", "action")
    list_filter = ("severity", "protocol", "action", "category")
    search_fields = ("signature", "source_ip", "destination_ip", "category")


@admin.register(IPSUpdateLog)
class IPSUpdateLogAdmin(admin.ModelAdmin):
    list_display = ("started_at", "finished_at", "status", "rules_total", "added", "updated", "removed", "disabled")
    list_filter = ("status",)


@admin.register(EDRPolicy)
class EDRPolicyAdmin(admin.ModelAdmin):
    list_display = ("name", "enabled", "telemetry_level", "block_usb", "block_script_interpreters", "quarantine_on_malware")
    list_filter = ("enabled", "telemetry_level", "block_usb")
    search_fields = ("name", "protected_paths")


@admin.register(EDREndpoint)
class EDREndpointAdmin(admin.ModelAdmin):
    list_display = ("hostname", "ip", "os", "status", "security_status", "agent_version", "last_seen")
    list_filter = ("status", "security_status", "provider")
    search_fields = ("hostname", "ip", "agent_id", "external_id", "logged_in_user")


@admin.register(EDREvent)
class EDREventAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "severity", "category", "title", "endpoint", "action")
    list_filter = ("severity", "category", "action", "source")
    search_fields = ("title", "description", "process_name", "file_path", "source_ip", "destination_ip")


@admin.register(EDRThreat)
class EDRThreatAdmin(admin.ModelAdmin):
    list_display = ("created_at", "severity", "category", "title", "endpoint", "status")
    list_filter = ("severity", "category", "status")
    search_fields = ("title", "endpoint__hostname")


@admin.register(EDRVulnerability)
class EDRVulnerabilityAdmin(admin.ModelAdmin):
    list_display = ("cve", "endpoint", "package", "severity", "status", "updated_at")
    list_filter = ("severity", "status")
    search_fields = ("cve", "package", "endpoint__hostname")


@admin.register(EDREnrollmentToken)
class EDREnrollmentTokenAdmin(admin.ModelAdmin):
    list_display = ("platform", "manager_url", "expires_at", "used", "created_at")
    list_filter = ("platform", "used")
    search_fields = ("manager_url",)


@admin.register(WebFilterRule)
class WebFilterRuleAdmin(admin.ModelAdmin):
    list_display = ("priority", "name", "enabled", "match_type", "pattern", "category", "action", "hit_count")
    list_filter = ("enabled", "match_type", "action", "category")
    search_fields = ("name", "pattern", "category")


@admin.register(AccessControlRule)
class AccessControlRuleAdmin(admin.ModelAdmin):
    list_display = ("priority", "name", "enabled", "network_type", "group", "mfa_required", "effect", "hit_count")
    list_filter = ("enabled", "network_type", "mfa_required", "effect")
    search_fields = ("name", "group")


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = ("event_type", "severity", "source_ip", "destination", "status", "occurred_at")
    list_filter = ("severity", "status", "event_type")
    search_fields = ("source_ip", "destination", "message")


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ("title", "severity", "status", "assigned_to", "created_at")
    list_filter = ("severity", "status")
    search_fields = ("title", "assigned_to")


@admin.register(LogSource)
class LogSourceAdmin(admin.ModelAdmin):
    list_display = ("name", "component", "parser", "enabled", "last_seen")
    list_filter = ("component", "parser", "enabled")
    search_fields = ("name",)


@admin.register(LogEntry)
class LogEntryAdmin(admin.ModelAdmin):
    list_display = ("created_at", "component", "source", "event_type", "severity", "source_ip", "destination")
    list_filter = ("component", "severity", "event_type")
    search_fields = ("raw_message", "source_ip", "destination")


@admin.register(CorrelationRule)
class CorrelationRuleAdmin(admin.ModelAdmin):
    list_display = ("name", "enabled", "component", "pattern", "threshold", "window_minutes", "severity", "hit_count")
    list_filter = ("enabled", "component", "severity")
    search_fields = ("name", "pattern")


admin.site.register(EndpointAsset)
admin.site.register(AccessPolicy)
