# Generated by Django 4.2.6 on 2023-12-04 11:07

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('store', '0024_alter_product_name_alter_product_value'),
    ]

    operations = [
        migrations.AddField(
            model_name='product',
            name='value2',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='products_by_value', to='store.cartegories', to_field='value'),
        ),
        migrations.AlterField(
            model_name='product',
            name='value',
            field=models.FloatField(),
        ),
    ]
