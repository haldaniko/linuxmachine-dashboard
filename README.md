# Systems Security Web Interface

Веб-интерфейс и API control plane для централизованного мониторинга и управления компонентами защиты:
межсетевой экран, IPS, EDR, веб-фильтрация, управление доступом/MFA и SIEM.

## Запуск для разработки

```bash
docker compose up --build
```

Интерфейс будет доступен на `http://localhost:5173`.

Dev-сборка использует SQLite в Docker volume `sqlite_data`.

## Production-сборка

```bash
docker compose -f docker-compose.prod.yml up --build -d
```

Production-сборка тоже использует SQLite в Docker volume `sqlite_data`, поэтому `DATABASE_URL` в `.env` не нужен.
Наружный порт также `8050`; frontend-контейнер отдаёт собранный React и проксирует `/api` во внутренний backend.
Пример внешнего reverse proxy находится в `.nginx.sample`.

Опционально можно создать `.env` только для секретов и доменов:

```env
DJANGO_SECRET_KEY=change-me-in-production
DJANGO_ALLOWED_HOSTS=example.com,www.example.com
CORS_ALLOWED_ORIGINS=https://example.com
```

## Рабочие возможности

- Управление настройками каждого модуля через `GET/PATCH /api/module-settings/`.
- CRUD правил firewall, IPS, web filtering, access/MFA, EDR-политик и SIEM-корреляций.
- Прием реальных событий через ingestion endpoints.
- Автоматическое создание `SecurityEvent`, `Alert`, `LogEntry` и счетчиков по модулям.
- SQLite хранится в Docker volume `sqlite_data`.

## API

Основные эндпоинты:

- `GET /api/dashboard/overview/`
- `GET/PATCH /api/module-settings/{id}/`
- `GET/POST /api/firewall/rules/`
- `POST /api/ingest/firewall/`
- `GET/POST /api/ips/rules/`
- `POST /api/ips/inspect/`
- `GET/POST /api/edr/policies/`
- `POST /api/edr/telemetry/`
- `GET/POST /api/web-filter/rules/`
- `POST /api/web-filter/check/`
- `GET/POST /api/access/rules/`
- `POST /api/access/check/`
- `GET/POST /api/siem/log-sources/`
- `GET /api/siem/logs/`
- `GET/POST /api/siem/correlation-rules/`
- `POST /api/ingest/logs/`
- `GET /api/events/`
- `GET /api/alerts/`

Примеры отправки реальных данных:

```bash
curl -X POST http://localhost:8050/api/ingest/firewall/ \
  -H "Content-Type: application/json" \
  -d '{"source_ip":"10.1.2.3","destination_ip":"1.1.1.1","destination_port":"443","protocol":"tcp","direction":"outbound"}'
```

```bash
curl -X POST http://localhost:8050/api/edr/telemetry/ \
  -H "Content-Type: application/json" \
  -d '{"hostname":"host-01","ip_address":"10.1.2.6","operating_system":"Windows 11","process_name":"powershell.exe","command_line":"powershell -enc ...","severity":"high"}'
```

```bash
curl -X POST http://localhost:8050/api/ingest/logs/ \
  -H "Content-Type: application/json" \
  -d '{"source":"edge-proxy","component":"siem","source_ip":"10.1.2.8","event_type":"Auth failed","severity":"medium","raw_message":"failed login"}'
```
