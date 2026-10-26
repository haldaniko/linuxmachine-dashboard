import ipaddress
import re

from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError as DjangoValidationError

from .configuration import validate_module_configuration
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

    def validate(self, attrs):
        key = attrs.get("key", getattr(self.instance, "key", None))
        if self.instance and key != self.instance.key:
            raise serializers.ValidationError({"key": "Идентификаторът на модула не може да се променя."})
        if "settings" in attrs:
            try:
                attrs["settings"] = validate_module_configuration(key, attrs["settings"])
            except serializers.ValidationError as exc:
                raise serializers.ValidationError({"settings": exc.detail}) from exc
            current = self.instance.settings if self.instance else {}
            for field in ["last_applied_at", "applied_rule_ids"]:
                attrs["settings"].pop(field, None)
            attrs["settings"] = {**current, **attrs["settings"]}
        return attrs


class FirewallRuleSerializer(serializers.ModelSerializer):
    action_label = serializers.CharField(source="get_action_display", read_only=True)
    direction_label = serializers.CharField(source="get_direction_display", read_only=True)
    protocol_label = serializers.CharField(source="get_protocol_display", read_only=True)

    class Meta:
        model = FirewallRule
        fields = "__all__"
        read_only_fields = ["hit_count", "last_matched", "applied_at", "apply_error", "created_at", "updated_at"]

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
        protocol = attrs.get("protocol", getattr(self.instance, "protocol", "any"))
        if protocol not in {"tcp", "udp"} and any(str(port).lower() not in {"any", "*"} for port in [source_port, destination_port]):
            raise serializers.ValidationError({"protocol": "Изберете TCP или UDP, когато задавате конкретен порт."})
        source = None if source_cidr.lower() in {"any", "*"} else ipaddress.ip_network(source_cidr, strict=False)
        destination = None if destination_cidr.lower() in {"any", "*"} else ipaddress.ip_network(destination_cidr, strict=False)
        if source and destination and source.version != destination.version:
            raise serializers.ValidationError({"destination_cidr": "Източникът и дестинацията трябва да използват еднаква IP версия."})
        return attrs

    def update(self, instance, validated_data):
        validated_data.update(applied_at=None, apply_error="")
        return super().update(instance, validated_data)


class IPSRuleSerializer(serializers.ModelSerializer):
    match_field_label = serializers.CharField(source="get_match_field_display", read_only=True)
    action_label = serializers.CharField(source="get_action_display", read_only=True)

    class Meta:
        model = IPSRule
        fields = "__all__"
        read_only_fields = ["hit_count", "last_matched", "created_at", "updated_at"]

    def validate_pattern(self, value):
        try:
            re.compile(value)
        except re.error as exc:
            raise serializers.ValidationError(f"Невалиден регулярен израз: {exc}") from exc
        return value


class IPSRuleCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = IPSRuleCategory
        fields = "__all__"


class IPSCustomRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = IPSCustomRule
        fields = "__all__"
        read_only_fields = ["validation_error", "applied_at", "created_at", "updated_at"]

    def validate(self, attrs):
        from .suricata_service import validate_custom_rule

        raw_rule = attrs.get("raw_rule", getattr(self.instance, "raw_rule", ""))
        sid = attrs.get("sid", getattr(self.instance, "sid", 0))
        try:
            validate_custom_rule(raw_rule, sid)
        except ValueError as exc:
            raise serializers.ValidationError({"raw_rule": str(exc)}) from exc
        return attrs

    def update(self, instance, validated_data):
        validated_data.update(applied_at=None, validation_error="")
        return super().update(instance, validated_data)


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

    def validate_telemetry_level(self, value):
        if value not in {"minimal", "standard", "extended", "full"}:
            raise serializers.ValidationError("Изберете minimal, standard, extended или full.")
        return value


class EDREndpointSerializer(serializers.ModelSerializer):
    threats_count = serializers.IntegerField(read_only=True)
    vulnerabilities_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = EDREndpoint
        fields = "__all__"

    def to_representation(self, instance):
        payload = super().to_representation(instance)
        payload["status"] = getattr(instance, "effective_status", instance.status)
        return payload


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
        read_only_fields = ["hit_count", "last_matched", "created_at", "updated_at"]

    def validate(self, attrs):
        match_type = attrs.get("match_type", getattr(self.instance, "match_type", "domain"))
        pattern = attrs.get("pattern", getattr(self.instance, "pattern", ""))
        if match_type == "regex":
            try:
                re.compile(pattern)
            except re.error as exc:
                raise serializers.ValidationError({"pattern": f"Невалиден регулярен израз: {exc}"}) from exc
        elif match_type == "domain":
            pattern = pattern.lower().rstrip(".")
            try:
                pattern = pattern.encode("idna").decode("ascii")
            except UnicodeError as exc:
                raise serializers.ValidationError({"pattern": "Въведете валидно име на домейн."}) from exc
            labels = pattern.split(".")
            if len(pattern) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
                raise serializers.ValidationError({"pattern": "Въведете само домейн, например example.com, без протокол, път или *."})
            attrs["pattern"] = pattern
        return attrs


class AccessControlRuleSerializer(serializers.ModelSerializer):
    network_type_label = serializers.CharField(source="get_network_type_display", read_only=True)
    effect_label = serializers.CharField(source="get_effect_display", read_only=True)

    class Meta:
        model = AccessControlRule
        fields = "__all__"
        read_only_fields = ["hit_count", "last_matched", "created_at", "updated_at"]


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

    def validate(self, attrs):
        password = attrs.get("password")
        if password:
            user = User(**{key: attrs.get(key, getattr(self.instance, key, "")) for key in ["username", "email", "first_name", "last_name"]})
            try:
                validate_password(password, user=user)
            except DjangoValidationError as exc:
                raise serializers.ValidationError({"password": exc.messages}) from exc
        return attrs

    def create(self, validated_data):
        password = validated_data.pop("password")
        return User.objects.create_user(password=password, **validated_data)

    def update(self, instance, validated_data):
        password = validated_data.pop("password", None)
        instance = super().update(instance, validated_data)
        if password:
            instance.set_password(password)
            instance.save(update_fields=["password"])
        return instance


class FirewallEvaluationSerializer(serializers.Serializer):
    direction = serializers.ChoiceField(choices=["inbound", "outbound", "any"], default="inbound")
    protocol = serializers.ChoiceField(choices=["tcp", "udp", "icmp", "any"], default="tcp")
    source_ip = serializers.IPAddressField(required=True)
    destination_ip = serializers.IPAddressField(required=True)
    source_port = serializers.IntegerField(min_value=1, max_value=65535, required=False, allow_null=True)
    destination_port = serializers.IntegerField(min_value=1, max_value=65535, required=False, allow_null=True)


class WebEvaluationSerializer(serializers.Serializer):
    url = serializers.CharField(max_length=2048)
    source_ip = serializers.IPAddressField(required=False)

    def validate_url(self, value):
        from urllib.parse import urlsplit

        try:
            parsed = urlsplit(value if "://" in value else f"https://{value}")
            valid = parsed.scheme in {"http", "https"} and parsed.hostname
            parsed.port
        except ValueError:
            valid = False
        if not valid or any(character.isspace() for character in value):
            raise serializers.ValidationError("Въведете валиден HTTP(S) адрес.")
        return value


class AccessEvaluationSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150, required=False, allow_blank=True)
    source_ip = serializers.IPAddressField(required=False)
    network_type = serializers.ChoiceField(choices=AccessControlRule.NetworkType.choices, default="any")
    group = serializers.CharField(max_length=140, default="any")
    mfa_verified = serializers.BooleanField(default=False)


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
