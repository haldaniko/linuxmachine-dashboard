"""Validation shared by module configuration endpoints and generic settings API."""

from urllib.parse import urlsplit

from rest_framework import serializers


class FirewallSettingsSerializer(serializers.Serializer):
    default_action = serializers.ChoiceField(choices=["allow", "block", "reject", "log"], required=False)
    log_allowed = serializers.BooleanField(required=False)


class WebFilterSettingsSerializer(serializers.Serializer):
    default_action = serializers.ChoiceField(choices=["allow", "block", "review"], required=False)
    log_allowed = serializers.BooleanField(required=False)


class AccessSettingsSerializer(serializers.Serializer):
    default_effect = serializers.ChoiceField(choices=["allow", "deny", "review"], required=False)
    mfa_grace_minutes = serializers.IntegerField(min_value=0, max_value=1440, required=False)


class EDRSettingsSerializer(serializers.Serializer):
    enabled = serializers.BooleanField(required=False)
    manager_url = serializers.CharField(max_length=240, required=False)
    agent_offline_timeout_minutes = serializers.IntegerField(min_value=1, max_value=10080, required=False)
    event_retention_days = serializers.IntegerField(min_value=1, max_value=3650, required=False)
    automatic_refresh = serializers.BooleanField(required=False)

    def validate_manager_url(self, value):
        try:
            parsed = urlsplit(value)
            valid = parsed.scheme in {"http", "https"} and parsed.hostname and not parsed.username and not parsed.password
            parsed.port
        except ValueError:
            valid = False
        if not valid or any(character.isspace() or character in "'\"`" for character in value):
            raise serializers.ValidationError("Въведете HTTP(S) адрес на мениджъра без потребителско име и парола.")
        return value.rstrip("/")


class IPSSettingsSerializer(serializers.Serializer):
    enabled = serializers.BooleanField(required=False)
    mode = serializers.ChoiceField(choices=["ids", "ips"], required=False)
    interface = serializers.CharField(max_length=160, allow_blank=True, required=False)
    home_net = serializers.CharField(required=False)
    auto_update = serializers.BooleanField(required=False)
    update_period = serializers.ChoiceField(choices=["daily", "weekly"], required=False)
    logging_enabled = serializers.BooleanField(required=False)


SETTINGS_SERIALIZERS = {
    "firewall": FirewallSettingsSerializer,
    "web_filter": WebFilterSettingsSerializer,
    "access": AccessSettingsSerializer,
    "edr": EDRSettingsSerializer,
    "ips": IPSSettingsSerializer,
}


def validate_module_configuration(key, value):
    if not isinstance(value, dict):
        raise serializers.ValidationError("Настройките трябва да са JSON обект.")
    serializer_class = SETTINGS_SERIALIZERS.get(key)
    if not serializer_class:
        return value
    serializer = serializer_class(data=value)
    serializer.is_valid(raise_exception=True)
    # Retain legacy settings while validating and normalizing supported fields.
    return {**value, **serializer.validated_data}
