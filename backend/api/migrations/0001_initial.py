import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="AccessPolicy",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=140)),
                ("scope", models.CharField(max_length=140)),
                ("category", models.CharField(max_length=120)),
                ("effect", models.CharField(choices=[("allow", "Разрешить"), ("block", "Блокировать"), ("review", "На проверку")], default="block", max_length=16)),
                ("enabled", models.BooleanField(default=True)),
                ("hit_count", models.PositiveIntegerField(default=0)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["name"]},
        ),
        migrations.CreateModel(
            name="EndpointAsset",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=140)),
                ("owner", models.CharField(max_length=140)),
                ("ip_address", models.GenericIPAddressField()),
                ("operating_system", models.CharField(max_length=120)),
                ("risk_level", models.CharField(choices=[("low", "Низкий"), ("medium", "Средний"), ("high", "Высокий"), ("critical", "Критичный")], default="low", max_length=16)),
                ("edr_status", models.CharField(default="Protected", max_length=64)),
                ("last_seen", models.DateTimeField(default=django.utils.timezone.now)),
            ],
            options={"ordering": ["-last_seen"]},
        ),
        migrations.CreateModel(
            name="SecurityComponent",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("key", models.SlugField(unique=True)),
                ("name", models.CharField(max_length=140)),
                ("category", models.CharField(choices=[("firewall", "Межсетевой экран"), ("ips", "IPS"), ("edr", "EDR"), ("web_filter", "Веб-фильтрация"), ("access", "Доступ и MFA"), ("siem", "SIEM")], max_length=32)),
                ("status", models.CharField(choices=[("healthy", "В норме"), ("warning", "Требует внимания"), ("critical", "Критично"), ("offline", "Недоступен")], default="healthy", max_length=16)),
                ("description", models.TextField(blank=True)),
                ("request_count", models.PositiveIntegerField(default=0)),
                ("blocked_count", models.PositiveIntegerField(default=0)),
                ("last_checked", models.DateTimeField(default=django.utils.timezone.now)),
            ],
            options={"ordering": ["id"]},
        ),
        migrations.CreateModel(
            name="SecurityEvent",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("source_ip", models.GenericIPAddressField()),
                ("destination", models.CharField(max_length=180)),
                ("event_type", models.CharField(max_length=120)),
                ("severity", models.CharField(choices=[("low", "Низкая"), ("medium", "Средняя"), ("high", "Высокая"), ("critical", "Критичная")], max_length=16)),
                ("message", models.TextField()),
                ("status", models.CharField(choices=[("new", "Новый"), ("investigating", "Расследуется"), ("resolved", "Закрыт")], default="new", max_length=24)),
                ("occurred_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("component", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="events", to="api.securitycomponent")),
            ],
            options={"ordering": ["-occurred_at"]},
        ),
        migrations.CreateModel(
            name="Alert",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("title", models.CharField(max_length=180)),
                ("severity", models.CharField(choices=[("low", "Низкая"), ("medium", "Средняя"), ("high", "Высокая"), ("critical", "Критичная")], max_length=16)),
                ("status", models.CharField(choices=[("new", "Новый"), ("investigating", "Расследуется"), ("resolved", "Закрыт")], default="new", max_length=24)),
                ("assigned_to", models.CharField(blank=True, max_length=140)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("event", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name="alerts", to="api.securityevent")),
            ],
            options={"ordering": ["-created_at"]},
        ),
    ]

