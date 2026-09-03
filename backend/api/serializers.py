from rest_framework import serializers
from django.contrib.auth.models import User

from .firewall_service import validate_cidr, validate_port
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


class SecurityComponentSerializer(serializers.ModelSerializer):
    category_label = serializers.CharField(source="get_category_display", read_only=True)
    status_label = serializers.CharField(source="get_status_display", read_only=True)
    blocked_ratio = serializers.SerializerMethodField()

    class Meta:
        model = SecurityComponent
        fields = "__all__"

    def get_blocked_ratio(self, obj):
        if obj.request_count == 0:
            return 0
        return round((obj.blocked_count / obj.request_count) * 100, 2)


class ModuleSettingSerializer(serializers.ModelSerializer):
    key_label = serializers.CharField(source="get_key_display", read_only=True)
    mode_label = serializers.CharField(source="get_mode_display", read_only=True)

    class Meta:
        model = ModuleSetting
        fields = "__all__"


class FirewallRuleSerializer(serializers.ModelSerializer):
    action_label = serializers.CharField(source="get_action_display", read_only=True)
    direction_label = serializers.CharField(source="get_direction_display", read_only=True)
    protocol_label = serializers.CharField(source="get_protocol_display", read_only=True)

    class Meta:
        model = FirewallRule
        fields = "__all__"

    def validate(self, attrs):
        source_cidr = attrs.get("source_cidr", getattr(self.instance, "source_cidr", "any"))
        destination_cidr = attrs.get("destination_cidr", getattr(self.instance, "destination_cidr", "any"))
        source_port = attrs.get("source_port", getattr(self.instance, "source_port", "any"))
        destination_port = attrs.get("destination_port", getattr(self.instance, "destination_port", "any"))
        errors = {}
        for field, label, validator, value in [
            ("source_cidr", "IP источника", validate_cidr, source_cidr),
            ("destination_cidr", "IP назначения", validate_cidr, destination_cidr),
            ("source_port", "Порт источника", validate_port, source_port),
            ("destination_port", "Порт назначения", validate_port, destination_port),
        ]:
            try:
                validator(value, label)
            except ValueError as exc:
                errors[field] = str(exc)
        if errors:
            raise serializers.ValidationError(errors)
        return attrs


class IPSRuleSerializer(serializers.ModelSerializer):
    match_field_label = serializers.CharField(source="get_match_field_display", read_only=True)
    action_label = serializers.CharField(source="get_action_display", read_only=True)

    class Meta:
        model = IPSRule
        fields = "__all__"


class IPSRuleCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = IPSRuleCategory
        fields = "__all__"


class IPSCustomRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = IPSCustomRule
        fields = "__all__"


class IPSAlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = IPSAlert
        fields = "__all__"


class IPSUpdateLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = IPSUpdateLog
        fields = "__all__"


class EDRPolicySerializer(serializers.ModelSerializer):
    class Meta:
        model = EDRPolicy
        fields = "__all__"


class EDREndpointSerializer(serializers.ModelSerializer):
    threats_count = serializers.IntegerField(read_only=True)
    vulnerabilities_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = EDREndpoint
        fields = "__all__"


class EDREventSerializer(serializers.ModelSerializer):
    endpoint_hostname = serializers.CharField(source="endpoint.hostname", read_only=True)
    endpoint_ip = serializers.CharField(source="endpoint.ip", read_only=True)
    endpoint_os = serializers.CharField(source="endpoint.os", read_only=True)

    class Meta:
        model = EDREvent
        fields = "__all__"


class EDRThreatSerializer(serializers.ModelSerializer):
    endpoint_hostname = serializers.CharField(source="endpoint.hostname", read_only=True)
    endpoint_ip = serializers.CharField(source="endpoint.ip", read_only=True)
    event_title = serializers.CharField(source="event.title", read_only=True)

    class Meta:
        model = EDRThreat
        fields = "__all__"


class EDRVulnerabilitySerializer(serializers.ModelSerializer):
    endpoint_hostname = serializers.CharField(source="endpoint.hostname", read_only=True)

    class Meta:
        model = EDRVulnerability
        fields = "__all__"


class EDREnrollmentTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = EDREnrollmentToken
        fields = ["platform", "manager_url", "expires_at", "used", "created_at"]


class WebFilterRuleSerializer(serializers.ModelSerializer):
    match_type_label = serializers.CharField(source="get_match_type_display", read_only=True)
    action_label = serializers.CharField(source="get_action_display", read_only=True)

    class Meta:
        model = WebFilterRule
        fields = "__all__"


class AccessControlRuleSerializer(serializers.ModelSerializer):
    network_type_label = serializers.CharField(source="get_network_type_display", read_only=True)
    effect_label = serializers.CharField(source="get_effect_display", read_only=True)

    class Meta:
        model = AccessControlRule
        fields = "__all__"


class UserSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ["id", "username", "email", "first_name", "last_name", "full_name", "is_staff", "is_active", "date_joined", "last_login"]

    def get_full_name(self, obj):
        return obj.get_full_name() or obj.username


class UserCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        fields = ["id", "username", "email", "first_name", "last_name", "password", "is_staff", "is_active"]
        read_only_fields = ["id"]

    def create(self, validated_data):
        password = validated_data.pop("password")
        return User.objects.create_user(password=password, **validated_data)


class EndpointAssetSerializer(serializers.ModelSerializer):
    risk_level_label = serializers.CharField(source="get_risk_level_display", read_only=True)

    class Meta:
        model = EndpointAsset
        fields = "__all__"


class AccessPolicySerializer(serializers.ModelSerializer):
    effect_label = serializers.CharField(source="get_effect_display", read_only=True)

    class Meta:
        model = AccessPolicy
        fields = "__all__"


class SecurityEventSerializer(serializers.ModelSerializer):
    component_name = serializers.CharField(source="component.name", read_only=True)
    component_key = serializers.CharField(source="component.category", read_only=True)
    severity_label = serializers.CharField(source="get_severity_display", read_only=True)
    status_label = serializers.CharField(source="get_status_display", read_only=True)

    class Meta:
        model = SecurityEvent
        fields = "__all__"


class AlertSerializer(serializers.ModelSerializer):
    severity_label = serializers.CharField(source="get_severity_display", read_only=True)
    status_label = serializers.CharField(source="get_status_display", read_only=True)
    source_ip = serializers.CharField(source="event.source_ip", read_only=True)

    class Meta:
        model = Alert
        fields = "__all__"


class LogSourceSerializer(serializers.ModelSerializer):
    component_label = serializers.CharField(source="get_component_display", read_only=True)
    parser_label = serializers.CharField(source="get_parser_display", read_only=True)

    class Meta:
        model = LogSource
        fields = "__all__"


class LogEntrySerializer(serializers.ModelSerializer):
    source_name = serializers.CharField(source="source.name", read_only=True)
    component_label = serializers.CharField(source="get_component_display", read_only=True)
    severity_label = serializers.CharField(source="get_severity_display", read_only=True)

    class Meta:
        model = LogEntry
        fields = "__all__"


class CorrelationRuleSerializer(serializers.ModelSerializer):
    component_label = serializers.CharField(source="get_component_display", read_only=True)
    severity_label = serializers.CharField(source="get_severity_display", read_only=True)

    class Meta:
        model = CorrelationRule
        fields = "__all__"
