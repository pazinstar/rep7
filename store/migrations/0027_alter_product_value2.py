# Generated by Django 4.2.6 on 2023-12-04 12:28

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('store', '0026_alter_cartegories_cardname_alter_product_name_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='product',
            name='value2',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='products_by_value', to='store.cartegories', to_field='value'),
        ),
    ]