# Generated by Django 4.2.6 on 2023-12-04 10:19

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('store', '0021_cartegories_alter_product_name'),
    ]

    operations = [
        migrations.AddField(
            model_name='product',
            name='Name',
            field=models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='store.cartegories'),
        ),
    ]
