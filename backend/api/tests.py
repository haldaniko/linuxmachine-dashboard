from datetime import timedelta
from io import StringIO
from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from .firewall_service import apply_firewall_rules, build_nft_config, rule_to_nft
from .models import (
    AccessControlRule, EDREndpoint, EDREvent, EDRThreat, EDRVulnerability,
    FirewallRule, IPSAlert, IPSCustomRule, IPSRule, LogEntry, ModuleSetting,
    SecurityComponent, SecurityEvent, WebFilterRule,
)
from .serializers import FirewallRuleSerializer, ModuleSettingSerializer, WebFilterRuleSerializer
from .views import evaluate_access_payload, evaluate_firewall_payload, evaluate_web_payload, inspect_ips_payload


class SecurityConfigurationTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user("administrator", password="Strong!Example374", is_staff=True)
        self.client = APIClient()
        self.client.force_authenticate(self.admin)

    def test_evaluations_do_not_mutate_rules_or_create_events(self):
        firewall = FirewallRule.objects.create(name="Deny network", source_cidr="10.0.0.0/8")
        web = WebFilterRule.objects.create(name="Block example", pattern="example.com")
        access = AccessControlRule.objects.create(name="Require MFA")
        ips = IPSRule.objects.create(name="Signature", pattern="malware")
        self.assertEqual(evaluate_firewall_payload({"source_ip": "10.1.1.1"})["action"], "block")
        self.assertEqual(evaluate_web_payload({"url": "https://sub.example.com"})["action"], "block")
        self.assertEqual(evaluate_access_payload({"mfa_verified": False})["effect"], "deny")
        self.assertEqual(len(inspect_ips_payload({"payload": "malware"}, persist=False)["matches"]), 1)
        for rule in [firewall, web, access, ips]:
            rule.refresh_from_db()
            self.assertEqual(rule.hit_count, 0)
            self.assertIsNone(rule.last_matched)
        self.assertEqual(SecurityEvent.objects.count(), 0)
        self.assertEqual(SecurityComponent.objects.count(), 0)

    def test_monitoring_and_disabled_modules_report_effective_and_policy_results(self):
        web = WebFilterRule.objects.create(name="Block", pattern="example.com")
        setting = ModuleSetting.objects.create(key="web_filter", display_name="Web", mode="monitor", settings={})
        result = evaluate_web_payload({"url": "https://example.com"})
        self.assertEqual((result["action"], result["policy_action"], result["reason"]), ("allow", "block", "monitor_only"))
        setting.enabled = False
        setting.save()
        result = evaluate_web_payload({"url": "https://example.com"}, persist=True)
        self.assertEqual(result["reason"], "module_disabled")
        self.assertEqual(SecurityEvent.objects.count(), 0)
        ModuleSetting.objects.create(key="access", display_name="IAM", mode="monitor", settings={"default_effect": "deny"})
        result = evaluate_access_payload({})
        self.assertEqual((result["effect"], result["policy_effect"]), ("allow", "deny"))
        ModuleSetting.objects.create(key="firewall", display_name="FW", mode="disabled", settings={"default_action": "block"})
        result = evaluate_firewall_payload({})
        self.assertEqual((result["action"], result["policy_action"]), ("allow", "block"))

    def test_web_allowed_logging_is_configurable(self):
        setting = ModuleSetting.objects.create(key="web_filter", display_name="Web", mode="enforce", settings={"log_allowed": False})
        evaluate_web_payload({"url": "https://example.com"}, persist=True)
        self.assertFalse(SecurityEvent.objects.exists())
        setting.settings = {"log_allowed": True}
        setting.save()
        evaluate_web_payload({"url": "https://example.com"}, persist=True)
        self.assertEqual(SecurityEvent.objects.count(), 1)

    def test_invalid_regex_and_domain_are_rejected(self):
        for payload in [
            {"name": "Invalid", "match_type": "regex", "pattern": "["},
            {"name": "Invalid", "match_type": "domain", "pattern": "https://example.com/path"},
        ]:
            serializer = WebFilterRuleSerializer(data=payload)
            self.assertFalse(serializer.is_valid())
            self.assertIn("pattern", serializer.errors)

    def test_domain_normalization_matches_trailing_dot_and_subdomains(self):
        serializer = WebFilterRuleSerializer(data={"name": "Domain", "pattern": "Example.COM."})
        self.assertTrue(serializer.is_valid(), serializer.errors)
        serializer.save()
        self.assertEqual(evaluate_web_payload({"url": "https://sub.example.com./path"})["action"], "block")
        self.assertEqual(evaluate_web_payload({"url": "https://notexample.com"})["action"], "allow")

    def test_firewall_ports_require_transport_protocol(self):
        serializer = FirewallRuleSerializer(data={"name": "Port rule", "destination_port": "443", "protocol": "any"})
        self.assertFalse(serializer.is_valid())
        self.assertIn("protocol", serializer.errors)

    def test_firewall_ip_versions_must_match(self):
        serializer = FirewallRuleSerializer(data={"name": "Mixed", "source_cidr": "10.0.0.1", "destination_cidr": "2001:db8::1"})
        self.assertFalse(serializer.is_valid())
        self.assertIn("destination_cidr", serializer.errors)

    def test_nft_rule_keeps_protocol_without_specific_ports(self):
        rule = FirewallRule(name='TCP "only"', protocol="tcp")
        rendered = rule_to_nft(rule)
        self.assertIn("meta l4proto tcp", rendered)
        self.assertIn(r'comment "TCP \"only\""', rendered)

    def test_nft_monitor_mode_logs_blocked_matches_without_dropping(self):
        rule = FirewallRule(name="Block traffic", protocol="tcp", action="block")
        config = build_nft_config([rule], mode="monitor", default_action="block")
        self.assertIn('log prefix "security_platform monitor " accept', config)
        self.assertNotIn("counter drop", config)

    def test_nft_enforce_mode_applies_default_action_and_allowed_logging(self):
        rule = FirewallRule(name="Allow HTTPS", protocol="tcp", destination_port="443", action="allow")
        config = build_nft_config([rule], mode="enforce", default_action="block", log_allowed=True)
        self.assertIn('log prefix "security_platform allow " accept', config)
        self.assertEqual(config.count("counter drop"), 2)
        reject = build_nft_config([], mode="enforce", default_action="reject")
        self.assertEqual(reject.count("counter reject"), 2)

    def test_nft_disabled_mode_has_no_filtering_rules(self):
        rule = FirewallRule(name="Block traffic", action="block")
        for enabled, mode in [(True, "disabled"), (False, "enforce")]:
            config = build_nft_config([rule], firewall_enabled=enabled, mode=mode, default_action="block")
            self.assertNotIn("counter", config)
            self.assertEqual(config.count("policy accept;"), 2)

    def test_default_log_policy_remains_supported(self):
        config = build_nft_config([], mode="enforce", default_action="log")
        self.assertEqual(config.count('counter log prefix "security_platform " accept'), 2)
        setting = ModuleSetting.objects.create(key="firewall", display_name="FW")
        serializer = ModuleSettingSerializer(setting, data={"settings": {"default_action": "log"}}, partial=True)
        self.assertTrue(serializer.is_valid(), serializer.errors)

    def test_event_list_is_scoped_to_requested_module(self):
        for key in ["web_filter", "access"]:
            component = SecurityComponent.objects.create(key=key, name=key, category=key)
            SecurityEvent.objects.create(component=component, source_ip="10.0.0.1", event_type="Test", severity="low", message=key)
        response = self.client.get("/api/events/?component__category=access")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["results"][0]["component_key"], "access")

    def test_operator_cannot_list_administrative_accounts(self):
        operator = User.objects.create_user("operator", password="Operator!Example374")
        self.client.force_authenticate(operator)
        self.assertEqual(self.client.get("/api/auth/users/").status_code, 403)

    def test_login_records_last_successful_login(self):
        client = APIClient()
        response = client.post("/api/auth/login/", {"username": "administrator", "password": "Strong!Example374"}, format="json")
        self.assertEqual(response.status_code, 200)
        self.admin.refresh_from_db()
        self.assertIsNotNone(self.admin.last_login)

    def test_default_block_requires_explicit_boolean_confirmation(self):
        request = type("Request", (), {"data": {"confirm_admin_lockout": "false"}, "META": {}, "get_host": lambda self: "localhost", "is_secure": lambda self: False})()
        with patch("api.firewall_service.apply_nft_config") as apply:
            result = apply_firewall_rules(request, [], default_action="block")
        self.assertFalse(result.ok)
        self.assertTrue(result.warning)
        apply.assert_not_called()

    def test_editing_firewall_rule_invalidates_applied_state(self):
        rule = FirewallRule.objects.create(name="Original", applied_at=timezone.now())
        response = self.client.patch(f"/api/firewall/rules/{rule.pk}/", {"name": "Changed", "hit_count": 999}, format="json")
        self.assertEqual(response.status_code, 200)
        rule.refresh_from_db()
        self.assertIsNone(rule.applied_at)
        self.assertEqual(rule.hit_count, 0)

    def test_firewall_status_detects_deleted_applied_rules(self):
        applied = timezone.now()
        setting = ModuleSetting.objects.create(key="firewall", display_name="FW", settings={"last_applied_at": applied.isoformat(), "applied_rule_ids": [999]})
        ModuleSetting.objects.filter(pk=setting.pk).update(updated_at=applied)
        with patch("api.views.shutil.which", return_value=None):
            response = self.client.get("/api/firewall/status/")
        self.assertTrue(response.data["has_unapplied_changes"])
        self.assertFalse(response.data["runtime_available"])

    def test_generic_settings_validation_and_partial_merge(self):
        setting = ModuleSetting.objects.create(key="web_filter", display_name="Web", settings={"default_action": "allow", "log_allowed": True})
        invalid = ModuleSettingSerializer(setting, data={"settings": ["wrong"]}, partial=True)
        self.assertFalse(invalid.is_valid())
        valid = ModuleSettingSerializer(setting, data={"settings": {"default_action": "block"}}, partial=True)
        self.assertTrue(valid.is_valid(), valid.errors)
        valid.save()
        self.assertEqual(setting.settings, {"default_action": "block", "log_allowed": True})

    def test_edr_settings_reject_invalid_values_without_saving(self):
        ModuleSetting.objects.create(key="edr", display_name="EDR", settings={"agent_offline_timeout_minutes": 15})
        for payload in [{"agent_offline_timeout_minutes": -1}, {"event_retention_days": "NaN"}, {"manager_url": "javascript:alert(1)"}]:
            response = self.client.put("/api/edr/settings/", payload, format="json")
            self.assertEqual(response.status_code, 400)
        self.assertEqual(ModuleSetting.objects.get(key="edr").settings["agent_offline_timeout_minutes"], 15)

    def test_edr_settings_parse_false_boolean(self):
        response = self.client.put("/api/edr/settings/", {"enabled": "false", "automatic_refresh": "false"}, format="json")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.data["enabled"])
        self.assertFalse(response.data["settings"]["automatic_refresh"])

    def test_endpoint_counts_do_not_multiply_and_timeout_is_used(self):
        ModuleSetting.objects.create(key="edr", display_name="EDR", settings={"agent_offline_timeout_minutes": 5})
        endpoint = EDREndpoint.objects.create(hostname="workstation", status="online", last_seen=timezone.now() - timedelta(minutes=10))
        event = EDREvent.objects.create(endpoint=endpoint, event_type="malware", category="malware", title="Detected")
        for index in range(2):
            EDRThreat.objects.create(endpoint=endpoint, event=event, title=f"Threat {index}", category="malware")
        for index in range(3):
            EDRVulnerability.objects.create(endpoint=endpoint, cve=f"CVE-2026-{index}")
        response = self.client.get("/api/edr/endpoints/")
        item = response.data["results"][0]
        self.assertEqual((item["threats_count"], item["vulnerabilities_count"]), (2, 3))
        self.assertEqual(item["status"], "offline")
        self.assertEqual(self.client.get("/api/edr/status/").data["offline"], 1)

    def test_invalid_suricata_rule_is_not_saved(self):
        response = self.client.post("/api/ips/custom-rules/", {"name": "Wrong SID", "sid": 1000001, "raw_rule": 'alert tcp any any -> any any (msg:"Test"; sid:10000012; rev:1;)'}, format="json")
        self.assertEqual(response.status_code, 400)
        self.assertFalse(IPSCustomRule.objects.exists())

    def test_missing_records_return_404(self):
        for path in ["edr/events/999/", "ips/events/999/", "edr/endpoints/999/events/"]:
            self.assertEqual(self.client.get(f"/api/{path}").status_code, 404)

    def test_mfa_false_string_is_not_treated_as_verified(self):
        AccessControlRule.objects.create(name="MFA", effect="allow", mfa_required=True)
        response = self.client.post("/api/access/evaluate/", {"mfa_verified": "false"}, format="json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["effect"], "deny")
        self.assertFalse(response.data["mfa_verified"])

    def test_invalid_evaluation_returns_field_error(self):
        response = self.client.post("/api/firewall/evaluate/", {"source_ip": "not-an-ip", "destination_ip": "1.1.1.1"}, format="json")
        self.assertEqual(response.status_code, 400)
        self.assertIn("source_ip", response.data)
        self.assertEqual(self.client.post("/api/web-filter/evaluate/", {"url": "http://["}, format="json").status_code, 400)

    def test_admin_can_disable_user_and_revokes_token(self):
        user = User.objects.create_user("analyst", password="Strong!Example374")
        Token.objects.create(user=user)
        response = self.client.patch(f"/api/auth/users/{user.pk}/", {"is_active": False}, format="json")
        self.assertEqual(response.status_code, 200)
        user.refresh_from_db()
        self.assertFalse(user.is_active)
        self.assertFalse(Token.objects.filter(user=user).exists())

    def test_admin_cannot_disable_or_demote_self(self):
        for payload in [{"is_active": False}, {"is_staff": False}]:
            response = self.client.patch(f"/api/auth/users/{self.admin.pk}/", payload, format="json")
            self.assertEqual(response.status_code, 400)

    def test_user_updates_require_admin_and_password_policy(self):
        user = User.objects.create_user("analyst", password="Strong!Example374")
        response = self.client.patch(f"/api/auth/users/{user.pk}/", {"password": "12345678"}, format="json")
        self.assertEqual(response.status_code, 400)
        self.client.force_authenticate(user)
        self.assertEqual(self.client.patch(f"/api/auth/users/{self.admin.pk}/", {"email": "test@example.com"}, format="json").status_code, 403)


class LedgerLabSeedTests(TestCase):
    def test_seed_is_idempotent_and_uses_operational_company_data(self):
        output = StringIO()
        call_command("seed_mock_data", stdout=output)
        call_command("seed_mock_data", stdout=output)

        self.assertEqual(FirewallRule.objects.filter(name="Public client portal HTTPS").count(), 1)
        self.assertEqual(SecurityEvent.objects.filter(extra_data__seed="ledgerlab-accounting-v1").count(), 8)
        self.assertEqual(IPSAlert.objects.filter(raw_event__seed="ledgerlab-accounting-v1").count(), 4)
        self.assertEqual(LogEntry.objects.filter(parsed__seed="ledgerlab-accounting-v1").count(), 8)
        self.assertEqual(EDREndpoint.objects.filter(external_id__startswith="ledgerlab-").count(), 12)

        seeded_users = User.objects.filter(
            username__in=["security.admin", "it.operations", "compliance.viewer", "accounting.lead", "payroll.lead"]
        )
        self.assertEqual(seeded_users.count(), 5)
        self.assertFalse(seeded_users.exclude(email__endswith="@ledgerlab.tech").exists())

        narrative = " ".join(SecurityEvent.objects.values_list("message", flat=True)).lower()
        signatures = " ".join(IPSAlert.objects.values_list("signature", flat=True)).lower()
        for unwanted in ["brute force", "sql injection", "trojan", "ransomware", "nmap"]:
            self.assertNotIn(unwanted, narrative + signatures)
