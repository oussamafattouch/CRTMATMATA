# Generated by Django 4.1.7 on 2023-02-23 12:00

from django.db import migrations
import phonenumber_field.modelfields


class Migration(migrations.Migration):

    dependencies = [
        ('employee', '0040_remove_employee_user_alter_employee_region_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='employee',
            name='tel',
            field=phonenumber_field.modelfields.PhoneNumberField(default='+21650000000', help_text='Enter number with Country Code Eg. +233240000000', max_length=128, region=None, verbose_name='Phone Number (Example +21650000000)'),
        ),
    ]