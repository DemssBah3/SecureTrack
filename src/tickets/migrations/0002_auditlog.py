# Generated migration for AuditLog model

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('tickets', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='AuditLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('action', models.CharField(
                    choices=[
                        ('CREATE_TICKET', 'Create Ticket'),
                        ('UPDATE_TICKET', 'Update Ticket'),
                        ('DELETE_TICKET', 'Delete Ticket'),
                        ('CREATE_PROJECT', 'Create Project'),
                        ('UPDATE_PROJECT', 'Update Project'),
                        ('ADD_MEMBER', 'Add Member'),
                        ('REMOVE_MEMBER', 'Remove Member'),
                        ('CHANGE_ROLE', 'Change Role'),
                    ],
                    max_length=50
                )),
                ('resource_type', models.CharField(max_length=50)),
                ('resource_id', models.IntegerField()),
                ('resource_name', models.CharField(blank=True, max_length=255)),
                ('details', models.JSONField(default=dict)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='audit_logs',
                    to=settings.AUTH_USER_MODEL
                )),
            ],
            options={
                'ordering': ['-timestamp'],
            },
        ),
        migrations.AddIndex(
            model_name='auditlog',
            index=models.Index(fields=['user', '-timestamp'], name='tickets_au_user_id_timestamp_idx'),
        ),
        migrations.AddIndex(
            model_name='auditlog',
            index=models.Index(fields=['action', '-timestamp'], name='tickets_au_action_timestamp_idx'),
        ),
        migrations.AddIndex(
            model_name='auditlog',
            index=models.Index(fields=['resource_type', 'resource_id'], name='tickets_au_resource_idx'),
        ),
    ]
