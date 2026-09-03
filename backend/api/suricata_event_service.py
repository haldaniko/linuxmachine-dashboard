import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

from django.utils import timezone

from .models import IPSAlert, SecurityComponent


EVE_JSON_PATH = Path(os.getenv("SURICATA_EVE_PATH", "/var/log/suricata/eve.json"))


def normalize_severity(priority):
    try:
        value = int(priority)
    except (TypeError, ValueError):
        return "low"
    if value <= 1:
        return "critical"
    if value == 2:
        return "high"
    if value == 3:
        return "medium"
    return "low"


def parse_timestamp(value):
    if not value:
        return timezone.now()
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return timezone.now()


def event_hash(event):
    source = json.dumps(event, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def import_eve_file(path=None, limit=10000):
    eve_path = Path(path or EVE_JSON_PATH)
    if not eve_path.exists():
        return {"imported": 0, "skipped": 0, "message": f"EVE файл не найден: {eve_path}"}

    imported = 0
    skipped = 0
    with eve_path.open("r", encoding="utf-8", errors="ignore") as handle:
        lines = handle.readlines()[-limit:]

    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            continue
        if event.get("event_type") not in {"alert", "drop"}:
            skipped += 1
            continue
        digest = event_hash(event)
        if IPSAlert.objects.filter(event_hash=digest).exists():
            skipped += 1
            continue
        alert = event.get("alert") or {}
        severity = normalize_severity(alert.get("severity") or alert.get("priority"))
        action = (alert.get("action") or event.get("event_type") or "alert").lower()
        IPSAlert.objects.create(
            timestamp=parse_timestamp(event.get("timestamp")),
            severity=severity,
            signature=alert.get("signature") or "Suricata event",
            signature_id=alert.get("signature_id"),
            category=alert.get("category") or alert.get("metadata", {}).get("category", [""])[0],
            source_ip=event.get("src_ip") or "0.0.0.0",
            source_port=event.get("src_port"),
            destination_ip=event.get("dest_ip") or "0.0.0.0",
            destination_port=event.get("dest_port"),
            protocol=(event.get("proto") or "").lower(),
            action=action,
            interface=event.get("in_iface") or event.get("interface") or "",
            flow_id=str(event.get("flow_id") or ""),
            direction=event.get("flow", {}).get("direction") or "",
            event_hash=digest,
            raw_event=event,
        )
        from .views import record_event

        record_event(
            SecurityComponent.Category.IPS,
            event.get("src_ip"),
            event.get("dest_ip"),
            "Suricata alert",
            severity,
            alert.get("signature") or "Suricata event",
            "block" if action in {"drop", "blocked"} else "alert",
            {"signature_id": alert.get("signature_id"), "protocol": event.get("proto"), "action": action},
        )
        imported += 1
    return {"imported": imported, "skipped": skipped, "message": "Импорт EVE завершен"}
