import ipaddress
import os
import shutil
import socket
import subprocess
from pathlib import Path

from django.conf import settings
from django.utils import timezone

from .models import IPSCustomRule, IPSRuleCategory, IPSUpdateLog, ModuleSetting, SecurityComponent


SURICATA_CONFIG_DIR = Path(os.getenv("SURICATA_CONFIG_DIR", settings.BASE_DIR / "data" / "suricata"))
CUSTOM_RULES_PATH = SURICATA_CONFIG_DIR / "custom.rules"


def get_ips_setting():
    defaults = {
        "mode": "ids",
        "interface": "",
        "home_net": "192.168.1.0/24",
        "auto_update": False,
        "update_period": "daily",
        "logging_enabled": True,
    }
    setting, _ = ModuleSetting.objects.get_or_create(
        key=SecurityComponent.Category.IPS,
        defaults={
            "display_name": "Система обнаружения вторжений",
            "enabled": True,
            "mode": ModuleSetting.Mode.MONITOR,
            "settings": defaults,
        },
    )
    merged = {**defaults, **(setting.settings or {})}
    if merged != setting.settings:
        setting.settings = merged
        setting.save(update_fields=["settings", "updated_at"])
    return setting


def list_interfaces():
    names = set()
    sys_net = Path("/sys/class/net")
    if sys_net.exists():
        names.update(path.name for path in sys_net.iterdir() if path.name != "lo")
    try:
        names.update(name for _, name in socket.if_nameindex() if name != "lo")
    except OSError:
        pass
    return sorted(names)


def validate_home_net(value):
    networks = [part.strip() for part in (value or "").replace("\n", ",").split(",") if part.strip()]
    if not networks:
        raise ValueError("HOME_NET: укажите хотя бы одну защищаемую сеть")
    for network in networks:
        try:
            ipaddress.ip_network(network, strict=False)
        except ValueError as exc:
            raise ValueError(f"HOME_NET: некорректная сеть {network}") from exc
    return networks


def validate_interface(name):
    interfaces = list_interfaces()
    if not name:
        return interfaces[0] if interfaces else ""
    if interfaces and name not in interfaces:
        raise ValueError("Выберите сетевой интерфейс из списка ОС")
    return name


def get_service_status():
    suricata = shutil.which("suricata")
    if not suricata:
        return {"installed": False, "status": "not_installed", "version": "", "message": "Suricata не установлена"}
    version = subprocess.run([suricata, "--build-info"], capture_output=True, text=True, timeout=10)
    return {
        "installed": True,
        "status": "available" if version.returncode == 0 else "error",
        "version": (version.stdout.splitlines() or [""])[0],
        "message": version.stderr.strip(),
    }


def write_custom_rules():
    SURICATA_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    rules = IPSCustomRule.objects.filter(enabled=True).order_by("sid")
    CUSTOM_RULES_PATH.write_text("\n".join(rule.raw_rule.strip() for rule in rules) + "\n", encoding="utf-8")
    return CUSTOM_RULES_PATH


def validate_custom_rule(raw_rule, sid):
    if int(sid) < 1000000:
        raise ValueError("Пользовательские SID должны быть 1000000 или выше")
    if f"sid:{sid}" not in raw_rule.replace(" ", ""):
        raise ValueError("Raw rule должен содержать указанный SID")
    if not raw_rule.strip().endswith(")"):
        raise ValueError("Правило Suricata должно завершаться закрывающей скобкой")
    return True


def apply_settings(payload):
    setting = get_ips_setting()
    current = setting.settings or {}
    new_settings = {
        **current,
        "mode": payload.get("mode", current.get("mode", "ids")),
        "interface": validate_interface(payload.get("interface", current.get("interface", ""))),
        "home_net": ",".join(validate_home_net(payload.get("home_net", current.get("home_net", "")))),
        "auto_update": bool(payload.get("auto_update", current.get("auto_update", False))),
        "update_period": payload.get("update_period", current.get("update_period", "daily")),
        "logging_enabled": bool(payload.get("logging_enabled", current.get("logging_enabled", True))),
    }
    if new_settings["mode"] not in {"ids", "ips"}:
        raise ValueError("Режим должен быть IDS или IPS")
    setting.enabled = bool(payload.get("enabled", setting.enabled))
    setting.settings = new_settings
    setting.mode = ModuleSetting.Mode.ENFORCE if new_settings["mode"] == "ips" else ModuleSetting.Mode.MONITOR
    setting.save(update_fields=["enabled", "settings", "mode", "updated_at"])
    return setting


def apply_suricata_config():
    setting = get_ips_setting()
    write_custom_rules()
    status = get_service_status()
    if not status["installed"]:
        return {"ok": False, "message": status["message"], "service_status": status["status"]}

    suricata = shutil.which("suricata")
    command = [suricata, "-T"]
    if CUSTOM_RULES_PATH.exists():
        command.extend(["-S", str(CUSTOM_RULES_PATH)])
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        return {"ok": False, "message": result.stderr.strip() or result.stdout.strip() or "Suricata отклонила конфигурацию"}
    IPSCustomRule.objects.filter(enabled=True).update(applied_at=timezone.now(), validation_error="")
    return {"ok": True, "message": "Настройки Suricata проверены и применены", "settings": setting.settings}


def start_suricata():
    status = get_service_status()
    return {"ok": status["installed"], "message": "Suricata доступна" if status["installed"] else status["message"], **status}


def stop_suricata():
    status = get_service_status()
    return {"ok": status["installed"], "message": "Остановка процесса в Docker MVP выполняется вне приложения" if status["installed"] else status["message"], **status}


def update_rules():
    log = IPSUpdateLog.objects.create(status="running")
    updater = shutil.which("suricata-update")
    if not updater:
        log.status = "error"
        log.message = "suricata-update не установлен"
        log.finished_at = timezone.now()
        log.save(update_fields=["status", "message", "finished_at"])
        return log
    result = subprocess.run([updater], capture_output=True, text=True, timeout=120)
    output = f"{result.stdout}\n{result.stderr}".strip()
    log.status = "success" if result.returncode == 0 else "error"
    log.message = output[-4000:]
    log.finished_at = timezone.now()
    log.save(update_fields=["status", "message", "finished_at"])
    return log


def ensure_default_categories():
    defaults = [
        ("Malware", 0),
        ("Web attacks", 0),
        ("Scanning", 0),
        ("Exploits", 0),
        ("DNS", 0),
        ("Policy", 0),
    ]
    for name, count in defaults:
        IPSRuleCategory.objects.get_or_create(name=name, defaults={"rule_count": count, "enabled": True})
