from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0003_firewall_runtime_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="securityevent",
            name="extra_data",
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
