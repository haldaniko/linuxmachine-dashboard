import re
import shutil
import subprocess
import os

from django.utils import timezone


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
INFO_PREFIX_RE = re.compile(r"^INFO\[[^\]]+\]\s*")
SECTION_RE = re.compile(r"^(?P<title>.+(?:Metrics|Decisions|Alerts|Bouncers|Machines|Remediation)):\s*$", re.IGNORECASE)


def _clean_line(line):
    return INFO_PREFIX_RE.sub("", ANSI_RE.sub("", line)).rstrip()


def _is_border(line):
    stripped = line.strip()
    return bool(stripped) and not any(ch.isalnum() for ch in stripped) and any(ch in stripped for ch in "─-+╭╮╰╯┬┴┼├┤|")


def _split_table_row(line):
    stripped = line.strip()
    if "│" in stripped:
        cells = [cell.strip() for cell in stripped.strip("│").split("│")]
    elif "|" in stripped:
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
    else:
        return None
    return cells if any(cells) else None


def parse_cscli_metrics(raw_output):
    sections = []
    current = None

    for original_line in raw_output.splitlines():
        line = _clean_line(original_line)
        if not line.strip():
            continue

        section_match = SECTION_RE.match(line.strip())
        if section_match:
            current = {"title": section_match.group("title"), "columns": [], "rows": []}
            sections.append(current)
            continue

        if _is_border(line):
            continue

        cells = _split_table_row(line)
        if not cells:
            continue

        if len(cells) == 1 and SECTION_RE.match(f"{cells[0]}:"):
            current = {"title": cells[0], "columns": [], "rows": []}
            sections.append(current)
            continue

        if not current:
            continue

        if not current["columns"]:
            current["columns"] = cells
            continue

        row = {}
        for index, column in enumerate(current["columns"]):
            row[column] = cells[index] if index < len(cells) else ""
        current["rows"].append(row)

    return [section for section in sections if section["columns"] or section["rows"]]


def collect_cscli_metrics():
    generated_at = timezone.now()
    command = ["cscli", "metrics", "--color", "no"]
    metrics_url = os.environ.get("CROWDSEC_METRICS_URL", "").strip()
    if metrics_url:
        command.extend(["--url", metrics_url])

    if not shutil.which("cscli"):
        return {
            "ok": False,
            "available": False,
            "generated_at": generated_at,
            "command": " ".join(command),
            "error": "Команда cscli не найдена внутри backend-контейнера.",
            "sections": [],
            "raw": "",
        }

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "available": True,
            "generated_at": generated_at,
            "command": " ".join(command),
            "error": "cscli metrics выполнялась дольше 20 секунд и была остановлена.",
            "sections": [],
            "raw": "",
        }

    raw = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    if result.returncode != 0:
        return {
            "ok": False,
            "available": True,
            "generated_at": generated_at,
            "command": " ".join(command),
            "error": stderr or raw or f"cscli metrics завершилась с кодом {result.returncode}.",
            "sections": [],
            "raw": raw,
        }

    sections = parse_cscli_metrics(raw)
    return {
        "ok": True,
        "available": True,
        "generated_at": generated_at,
        "command": " ".join(command),
        "error": "",
        "sections": sections,
        "raw": raw,
    }
