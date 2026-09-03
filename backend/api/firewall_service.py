import ipaddress
import shutil
import subprocess
import tempfile
from dataclasses import dataclass


APP_TABLE = "security_platform"
FAMILY = "inet"
BLOCKING_ACTIONS = {"block", "reject"}


@dataclass
class ApplyResult:
    ok: bool
    message: str
    config: str
    warning: str = ""
    error: str = ""


def normalize_any(value):
    value = (value or "any").strip()
    return "" if value.lower() in {"any", "*"} else value


def validate_cidr(value, field_name):
    value = normalize_any(value)
    if not value:
        return
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(f"{field_name}: укажите IP или CIDR, например 192.168.1.10 или 192.168.1.0/24") from exc


def validate_port(value, field_name):
    value = normalize_any(value)
    if not value:
        return
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name}: укажите порт числом от 1 до 65535 или Any") from exc
    if port < 1 or port > 65535:
        raise ValueError(f"{field_name}: порт должен быть от 1 до 65535")


def validate_rule(rule):
    validate_cidr(rule.source_cidr, "IP источника")
    validate_cidr(rule.destination_cidr, "IP назначения")
    validate_port(getattr(rule, "source_port", "any"), "Порт источника")
    validate_port(rule.destination_port, "Порт назначения")
    if rule.action not in {"allow", "block", "reject", "log"}:
        raise ValueError("Действие должно быть Allow или Block")
    if rule.direction not in {"inbound", "outbound", "any"}:
        raise ValueError("Направление должно быть Incoming или Outgoing")
    if rule.protocol not in {"any", "tcp", "udp", "icmp"}:
        raise ValueError("Протокол должен быть Any, TCP, UDP или ICMP")


def nft_action(action):
    if action == "allow":
        return "accept"
    if action == "reject":
        return "reject"
    if action == "log":
        return "log prefix \"security_platform \" accept"
    return "drop"


def cidr_fragment(field, value):
    value = normalize_any(value)
    if not value:
        return ""
    network = ipaddress.ip_network(value, strict=False)
    protocol = "ip6" if network.version == 6 else "ip"
    return f"{protocol} {field} {network.with_prefixlen}"


def port_fragment(field, value, protocol):
    value = normalize_any(value)
    if not value or protocol not in {"tcp", "udp"}:
        return ""
    return f"{protocol} {field} {int(value)}"


def rule_to_nft(rule):
    validate_rule(rule)
    parts = []
    if rule.protocol == "icmp":
        parts.append("ip protocol icmp")
    parts.extend(
        fragment
        for fragment in [
            cidr_fragment("saddr", rule.source_cidr),
            cidr_fragment("daddr", rule.destination_cidr),
            port_fragment("sport", getattr(rule, "source_port", "any"), rule.protocol),
            port_fragment("dport", rule.destination_port, rule.protocol),
        ]
        if fragment
    )
    comment = f'comment "{rule.name[:64].replace(chr(34), "")}"'
    return " ".join([*parts, "counter", nft_action(rule.action), comment]).strip()


def build_nft_config(rules, firewall_enabled=True):
    input_rules = []
    output_rules = []
    if firewall_enabled:
        for rule in rules:
            rendered = rule_to_nft(rule)
            if rule.direction in {"inbound", "any"}:
                input_rules.append(rendered)
            if rule.direction in {"outbound", "any"}:
                output_rules.append(rendered)

    def chain(name, rows):
        body = "\n".join(f"        {row}" for row in rows)
        if body:
            body = "\n" + body + "\n"
        return f"    chain {name} {{\n        type filter hook {name} priority 0; policy accept;{body}    }}"

    return "\n".join(
        [
            f"destroy table {FAMILY} {APP_TABLE}",
            f"table {FAMILY} {APP_TABLE} {{",
            chain("input", input_rules),
            "",
            chain("output", output_rules),
            "}",
            "",
        ]
    )


def admin_session_warning(request, rules):
    admin_ip = request.META.get("HTTP_X_FORWARDED_FOR", "").split(",")[0].strip() or request.META.get("REMOTE_ADDR", "")
    host = request.get_host().split(":")
    web_port = host[1] if len(host) > 1 else ("443" if request.is_secure() else "80")
    payload = {
        "direction": "inbound",
        "protocol": "tcp",
        "source_ip": admin_ip,
        "destination_ip": "127.0.0.1",
        "destination_port": web_port,
    }
    for rule in rules:
        try:
            validate_rule(rule)
        except ValueError:
            continue
        if rule.action in BLOCKING_ACTIONS and rule.direction in {"inbound", "any"}:
            if _rule_could_match_admin(rule, payload):
                return "Это правило может заблокировать ваш доступ к серверу"
    return ""


def _cidr_contains(ip_value, rule_cidr):
    rule_cidr = normalize_any(rule_cidr)
    if not rule_cidr:
        return True
    try:
        return ipaddress.ip_address(ip_value) in ipaddress.ip_network(rule_cidr, strict=False)
    except ValueError:
        return False


def _port_contains(port_value, rule_port):
    rule_port = normalize_any(rule_port)
    if not rule_port:
        return True
    try:
        return int(rule_port) == int(port_value)
    except (TypeError, ValueError):
        return False


def _rule_could_match_admin(rule, payload):
    return (
        rule.enabled
        and rule.protocol in {"any", payload["protocol"]}
        and _cidr_contains(payload["source_ip"], rule.source_cidr)
        and _port_contains(payload["destination_port"], rule.destination_port)
    )


def apply_nft_config(config):
    nft_path = shutil.which("nft")
    if not nft_path:
        return False, "nftables не установлен в окружении backend"

    with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False, encoding="utf-8") as handle:
        handle.write(config)
        config_path = handle.name

    check = subprocess.run([nft_path, "-c", "-f", config_path], capture_output=True, text=True, timeout=15)
    if check.returncode != 0:
        return False, check.stderr.strip() or check.stdout.strip() or "nftables отклонил конфигурацию"

    apply = subprocess.run([nft_path, "-f", config_path], capture_output=True, text=True, timeout=15)
    if apply.returncode != 0:
        return False, apply.stderr.strip() or apply.stdout.strip() or "nftables не смог применить конфигурацию"
    return True, "Правила успешно применены"


def apply_firewall_rules(request, rules, firewall_enabled=True):
    rules = list(rules)
    try:
        config = build_nft_config(rules, firewall_enabled=firewall_enabled)
    except ValueError as exc:
        return ApplyResult(False, str(exc), "", error=str(exc))

    warning = admin_session_warning(request, rules)
    if warning and not request.data.get("confirm_admin_lockout"):
        return ApplyResult(False, warning, config, warning=warning, error=warning)

    ok, message = apply_nft_config(config)
    return ApplyResult(ok, message, config, warning=warning, error="" if ok else message)
