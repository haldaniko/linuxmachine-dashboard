from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0002_operational_controls"),
    ]

    operations = [
        migrations.AddField(
            model_name="firewallrule",
            name="source_port",
            field=models.CharField(default="any", max_length=80),
        ),
        migrations.AddField(
            model_name="firewallrule",
            name="applied_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="firewallrule",
            name="apply_error",
            field=models.TextField(blank=True),
        ),
    ]
