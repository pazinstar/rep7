# Generated by Django 4.2.6 on 2023-12-04 10:18

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('store', '0020_remove_product_sellingprice'),
    ]

    operations = [
        migrations.CreateModel(
            name='cartegories',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('cardName', models.CharField(max_length=200)),
            ],
        ),

    ]
