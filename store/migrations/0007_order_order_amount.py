# Generated by Django 4.2.6 on 2023-10-27 14:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('store', '0006_order_orderitem_delete_cart'),
    ]

    operations = [
        migrations.AddField(
            model_name='order',
            name='order_amount',
            field=models.FloatField(null=True),
        ),
    ]