# Generated by Django 4.2.6 on 2023-11-09 15:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('store', '0011_remove_orderitem_flash'),
    ]

    operations = [
        migrations.CreateModel(
            name='line_chart',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('label', models.CharField(max_length=50)),
                ('value', models.FloatField()),
            ],
        ),
        migrations.CreateModel(
            name='pie_chart',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('value', models.FloatField()),
                ('brand', models.CharField(max_length=40)),
            ],
        ),
        migrations.CreateModel(
            name='sales_chart',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('value', models.FloatField()),
                ('month', models.CharField(max_length=40)),
            ],
        ),
    ]