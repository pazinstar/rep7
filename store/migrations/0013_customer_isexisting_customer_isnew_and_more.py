# Generated by Django 4.2.6 on 2023-12-03 13:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('store', '0012_line_chart_pie_chart_sales_chart'),
    ]

    operations = [
        migrations.AddField(
            model_name='customer',
            name='isExisting',
            field=models.BooleanField(default=False, editable=False),
        ),
        migrations.AddField(
            model_name='customer',
            name='isNew',
            field=models.BooleanField(default=True, editable=False),
        ),
        migrations.AddField(
            model_name='customer',
            name='isVerified',
            field=models.BooleanField(default=False, editable=False),
        ),
        migrations.AlterField(
            model_name='customer',
            name='balance',
            field=models.FloatField(editable=False),
        ),
        migrations.AlterField(
            model_name='customer',
            name='email',
            field=models.CharField(editable=False, max_length=200, null=True),
        ),
        migrations.AlterField(
            model_name='customer',
            name='name',
            field=models.CharField(editable=False, max_length=200, null=True),
        ),
    ]