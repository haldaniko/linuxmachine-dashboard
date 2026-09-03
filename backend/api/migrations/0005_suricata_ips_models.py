import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0004_securityevent_extra_data"),
    ]

    operations = [
        migrations.CreateModel(
            name="IPSAlert",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("timestamp", models.DateTimeField(default=django.utils.timezone.now)),
                ("severity", models.CharField(choices=[("informational", "Informational"), ("low", "Low"), ("medium", "Medium"), ("high", "High"), ("critical", "Critical")], default="low", max_length=16)),
                ("signature", models.CharField(max_length=240)),
                ("signature_id", models.PositiveIntegerField(blank=True, null=True)),
                ("category", models.CharField(blank=True, max_length=140)),
                ("source_ip", models.GenericIPAddressField(default="0.0.0.0")),
                ("source_port", models.PositiveIntegerField(blank=True, null=True)),
                ("destination_ip", models.GenericIPAddressField(default="0.0.0.0")),
                ("destination_port", models.PositiveIntegerField(blank=True, null=True)),
                ("protocol", models.CharField(blank=True, max_length=24)),
                ("action", models.CharField(default="alert", max_length=32)),
                ("interface", models.CharField(blank=True, max_length=64)),
                ("flow_id", models.CharField(blank=True, max_length=80)),
                ("direction", models.CharField(blank=True, max_length=40)),
                ("event_hash", models.CharField(max_length=64, unique=True)),
                ("raw_event", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
            ],
            options={"ordering": ["-timestamp"]},
        ),
        migrations.CreateModel(
            name="IPSCustomRule",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=160)),
                ("sid", models.PositiveIntegerField(unique=True)),
                ("raw_rule", models.TextField()),
                ("enabled", models.BooleanField(default=True)),
                ("validation_error", models.TextField(blank=True)),
                ("applied_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["sid"]},
        ),
        migrations.CreateModel(
            name="IPSRuleCategory",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=120, unique=True)),
                ("description", models.TextField(blank=True)),
                ("enabled", models.BooleanField(default=True)),
                ("rule_count", models.PositiveIntegerField(default=0)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["name"]},
        ),
        migrations.CreateModel(
            name="IPSUpdateLog",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("started_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
                ("status", models.CharField(default="running", max_length=24)),
                ("message", models.TextField(blank=True)),
                ("rules_total", models.PositiveIntegerField(default=0)),
                ("added", models.PositiveIntegerField(default=0)),
                ("updated", models.PositiveIntegerField(default=0)),
                ("removed", models.PositiveIntegerField(default=0)),
                ("disabled", models.PositiveIntegerField(default=0)),
            ],
            options={"ordering": ["-started_at"]},
        ),
    ]
