# Generated by Django 4.1.7 on 2023-02-22 12:45

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('employee', '0037_alter_employee_sex_alter_employee_title'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='relationship',
            name='father',
        ),
        migrations.RemoveField(
            model_name='relationship',
            name='foccupation',
        ),
        migrations.RemoveField(
            model_name='relationship',
            name='moccupation',
        ),
        migrations.RemoveField(
            model_name='relationship',
            name='mother',
        ),
    ]
