from django.db import models
from django.contrib.auth.models import User

class Customer(models.Model):
    user=models.OneToOneField(User, on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(max_length=200, null=True, editable=False)
    email = models.CharField(max_length=200, null=True, editable=False)
    balance = models.FloatField(editable=False)
    isNew = models.BooleanField(default=True, editable=False)
    isExisting = models.BooleanField(default=False, editable=False)
    isVerified = models.BooleanField(default=False, editable=False)
    
    def __str__(self):
        return self.name 
        
class priceValue(models.Model):
    value = models.FloatField()
    def __str__(self):
        return '$ '+ str(self.value)
    
class cartegories(models.Model):
    cardName = models.CharField(max_length=200, null=False)
    value = models.OneToOneField(priceValue, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        # return self.cardName +'- '+ str(self.value)
        return f"{self.cardName} - ${self.value.value if self.value else 'N/A'}"

class product(models.Model):
    name = models.CharField(max_length=200, null=False)
    Name = models.ForeignKey(cartegories, on_delete=models.SET_NULL, null=True, blank=True, related_name='products_by_name')
    value2 = models.ForeignKey(cartegories, on_delete=models.SET_NULL, null=True, blank=True, related_name='products_by_value', to_field='value')
    value = models.FloatField()
    cardNo = models.CharField(max_length=200, null=True, default='N/A')
    cardPin = models.CharField(max_length=200, null=True, default='N/A')
    emailAddress = models.CharField(max_length=200, null=True, default='N/A')
    passWord = models.CharField(max_length=200, null=True, default='N/A')
    onOffer = models.BooleanField(default=False, null=True, blank=False)
    isSold = models.BooleanField(default=False, null=True, blank=False) 
    # image = models.ImageField(null=True, blank=True)
    image = models.URLField(null=True)
    def __str__(self):
        # return self.name + '- $'+ str(self.value2)
        return f"{self.name} - ${self.value2.value.value if self.value2 else 'N/A'}"

    
    @property
    def imageURL(self):
        try:
            # url = self.image.url
            url = self.image
        except:
            url = ''
        return url
    
class Flash_Sales(models.Model):
    cardName=models.CharField(max_length=50)
    ImageUrl=models.URLField()
    Worth=models.FloatField(max_length=15)
    price=models.FloatField(max_length=15)
    discount=models.FloatField(max_length=5)

    def __str__(self):
        return self.cardName
    
# class History():
#     pass

class Transactions(models.Model):
    customer = models.ForeignKey(Customer, on_delete=models.SET_NULL, blank=True, null=True)
    amount = models.FloatField()
    Transaction_id = models.CharField(max_length=200, null=True)

    def __str__(self):
        return str(self.id)
    
class Order(models.Model):
    customer = models.ForeignKey(Customer, on_delete=models.SET_NULL, blank=True, null=True)
    date_ordered = models.DateTimeField(auto_now_add=True)
    complete = models.BooleanField(default=False, null=True, blank=False)
    transaction_id = models.CharField(max_length=200, null=True)
    order_amount = models.FloatField(null=True)

    def __str__(self):
        return str(self.id)
    
    @property
    def get_cart_total(self):
        orderitems = self.orderitem_set.all()
        total = sum([item.get_total for item in orderitems])
        return total

    @property
    def get_cart_items(self):
        orderitems = self.orderitem_set.all()
        total = sum([item.quantity for item in orderitems])
        return total

#  Single order several items
class OrderItem(models.Model):
    product = models.ForeignKey(product, on_delete=models.SET_NULL, blank=True, null=True)
    order = models.ForeignKey(Order, on_delete=models.SET_NULL, blank=True, null=True)
    quantity = models.IntegerField(default=0, null=True, blank=False)
    date_added = models.DateTimeField(auto_now_add=True)

    @property
    def get_total(self):
        if self.product is not None:
            total = self.product.value * self.quantity
        else:
            total = 0
        return total
    

class line_chart(models.Model):
    label = models.CharField(max_length=50)
    value = models.FloatField()

    def _str_(self):
        return self.label
class sales_chart(models.Model):
    value=models.FloatField()
    month=models.CharField(max_length=40)
    
    def _str_(self):
        return self.month
class pie_chart(models.Model):
    value=models.FloatField()
    brand=models.CharField(max_length=40)
    
    def _str_(self):
      return self.brand

