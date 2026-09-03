from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    AccessControlRuleViewSet,
    AccessPolicyViewSet,
    AlertViewSet,
    CorrelationRuleViewSet,
    EDREndpointViewSet,
    EDREventViewSet,
    EDRPolicyViewSet,
    EDRThreatViewSet,
    EDRVulnerabilityViewSet,
    EndpointAssetViewSet,
    FirewallRuleViewSet,
    IPSAlertViewSet,
    IPSCustomRuleViewSet,
    IPSRuleViewSet,
    IPSRuleCategoryViewSet,
    LogEntryViewSet,
    LogSourceViewSet,
    ModuleSettingViewSet,
    SecurityComponentViewSet,
    SecurityEventViewSet,
    WebFilterRuleViewSet,
    access_check,
    auth_login,
    auth_logout,
    auth_me,
    dashboard_overview,
    firewall_apply,
    firewall_disable,
    firewall_enable,
    edr_telemetry,
    edr_crowdsec_metrics,
    edr_endpoint_events,
    edr_endpoint_register,
    edr_endpoint_vulnerabilities,
    edr_event_block_ip,
    edr_event_detail,
    edr_event_ingest,
    edr_events,
    edr_install_linux,
    edr_install_windows,
    edr_settings,
    edr_status,
    edr_threat_status,
    edr_threats,
    edr_vulnerability_ingest,
    firewall_evaluate,
    firewall_events,
    firewall_ingest,
    firewall_status,
    ips_evaluate,
    ips_apply,
    ips_block_source,
    ips_event_detail,
    ips_events,
    ips_inspect,
    ips_rule_categories,
    ips_settings,
    ips_start,
    ips_status,
    ips_stop,
    ips_update_rules,
    siem_ingest_log,
    access_evaluate,
    users_manage,
    web_filter_evaluate,
    web_filter_check,
)

router = DefaultRouter()
router.register("components", SecurityComponentViewSet)
router.register("module-settings", ModuleSettingViewSet)
router.register("firewall/rules", FirewallRuleViewSet)
router.register("ips/rules", IPSRuleViewSet)
router.register("ips/rule-categories", IPSRuleCategoryViewSet)
router.register("ips/custom-rules", IPSCustomRuleViewSet)
router.register("ips/alerts", IPSAlertViewSet)
router.register("edr/policies", EDRPolicyViewSet)
router.register("edr/endpoints", EDREndpointViewSet)
router.register("edr/event-records", EDREventViewSet)
router.register("edr/threat-records", EDRThreatViewSet)
router.register("edr/vulnerabilities", EDRVulnerabilityViewSet)
router.register("web-filter/rules", WebFilterRuleViewSet)
router.register("access/rules", AccessControlRuleViewSet)
router.register("siem/log-sources", LogSourceViewSet)
router.register("siem/logs", LogEntryViewSet)
router.register("siem/correlation-rules", CorrelationRuleViewSet)
router.register("events", SecurityEventViewSet)
router.register("alerts", AlertViewSet)
router.register("policies", AccessPolicyViewSet)
router.register("assets", EndpointAssetViewSet)

urlpatterns = [
    path("auth/login/", auth_login, name="auth-login"),
    path("auth/logout/", auth_logout, name="auth-logout"),
    path("auth/me/", auth_me, name="auth-me"),
    path("auth/users/", users_manage, name="auth-users"),
    path("dashboard/overview/", dashboard_overview, name="dashboard-overview"),
    path("firewall/status/", firewall_status, name="firewall-status"),
    path("firewall/apply/", firewall_apply, name="firewall-apply"),
    path("firewall/events/", firewall_events, name="firewall-events"),
    path("firewall/enable/", firewall_enable, name="firewall-enable"),
    path("firewall/disable/", firewall_disable, name="firewall-disable"),
    path("firewall/evaluate/", firewall_evaluate, name="firewall-evaluate"),
    path("ingest/firewall/", firewall_ingest, name="firewall-ingest"),
    path("web-filter/check/", web_filter_check, name="web-filter-check"),
    path("web-filter/evaluate/", web_filter_evaluate, name="web-filter-evaluate"),
    path("ips/inspect/", ips_inspect, name="ips-inspect"),
    path("ips/evaluate/", ips_evaluate, name="ips-evaluate"),
    path("ips/status/", ips_status, name="ips-status"),
    path("ips/events/", ips_events, name="ips-events"),
    path("ips/events/<int:event_id>/", ips_event_detail, name="ips-event-detail"),
    path("ips/rules/categories/", ips_rule_categories, name="ips-rule-categories"),
    path("ips/settings/", ips_settings, name="ips-settings"),
    path("ips/apply/", ips_apply, name="ips-apply"),
    path("ips/start/", ips_start, name="ips-start"),
    path("ips/stop/", ips_stop, name="ips-stop"),
    path("ips/update-rules/", ips_update_rules, name="ips-update-rules"),
    path("ips/events/<int:event_id>/block-source/", ips_block_source, name="ips-block-source"),
    path("edr/telemetry/", edr_telemetry, name="edr-telemetry"),
    path("edr/status/", edr_status, name="edr-status"),
    path("edr/crowdsec/metrics/", edr_crowdsec_metrics, name="edr-crowdsec-metrics"),
    path("edr/endpoints/register/", edr_endpoint_register, name="edr-endpoint-register"),
    path("edr/endpoints/<int:endpoint_id>/events/", edr_endpoint_events, name="edr-endpoint-events"),
    path("edr/endpoints/<int:endpoint_id>/vulnerabilities/", edr_endpoint_vulnerabilities, name="edr-endpoint-vulnerabilities"),
    path("edr/events/", edr_events, name="edr-events"),
    path("edr/events/ingest/", edr_event_ingest, name="edr-event-ingest"),
    path("edr/events/<int:event_id>/", edr_event_detail, name="edr-event-detail"),
    path("edr/events/<int:event_id>/block-ip/", edr_event_block_ip, name="edr-event-block-ip"),
    path("edr/vulnerabilities/ingest/", edr_vulnerability_ingest, name="edr-vulnerability-ingest"),
    path("edr/threats/", edr_threats, name="edr-threats"),
    path("edr/threats/<int:threat_id>/status/", edr_threat_status, name="edr-threat-status"),
    path("edr/install/linux/", edr_install_linux, name="edr-install-linux"),
    path("edr/install/windows/", edr_install_windows, name="edr-install-windows"),
    path("edr/settings/", edr_settings, name="edr-settings"),
    path("access/check/", access_check, name="access-check"),
    path("access/evaluate/", access_evaluate, name="access-evaluate"),
    path("ingest/logs/", siem_ingest_log, name="siem-ingest-log"),
    path("", include(router.urls)),
]
