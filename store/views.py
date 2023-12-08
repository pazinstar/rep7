from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.core.serializers import serialize
from django.db.models.query import QuerySet
from django.db.models import Model, Q
from django.views.generic import View
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import EmailMessage, send_mail

from .models import *
from .my_captcha import FormWithCaptcha 
from .tokens import generate_token

import stripe
from coinbase_commerce.client import Client
from coinbase_commerce.error import SignatureVerificationError, WebhookInvalidPayload
from coinbase_commerce.webhook import Webhook

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import json
from datetime import datetime
import logging

class DjangoJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (Model, QuerySet)):
            return serialize('json', [obj])
        elif isinstance(obj, datetime.datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        return super(DjangoJSONEncoder, self).default(obj)

# ------------------------------------------Index start---------------------------------------------------------------

company_name = "Darksales-SHC"
current_year = datetime.now().year

def index(request):
    prod = product.objects.all()
    flashcards = Flash_Sales.objects.all()
    context = {
        "company_name": company_name,
        'current_year':current_year,
        'products':prod, 
        'Flash_cards': flashcards,
    }
    return render(request, 'website/index.html', context)
# --------------------------------------------Index end-----------------------------------------------------------------

# ------------------------------------------Dasboard start---------------------------------------------------------------


def dashboard(request):
    prod = product.objects.all() 
    flashcards = Flash_Sales.objects.all()

    if request.user.is_authenticated:
        customer = request.user.customer
        order, created = Order.objects.get_or_create(customer=customer, complete = False)
        items = order.orderitem_set.all()
        cartItems = order.get_cart_items
    else:
        items = []
        order = {'get_cart_items':0, 'get_cart_total':0}
        cartItems = order['get_cart_total']

    context = {
        'products':prod, 
        'Flash_cards': flashcards, 
        'company_name': company_name , 
        'current_year':current_year, 
        'CartItems':cartItems
    }
    return render(request, 'store/dashboard.html', context)
# ------------------------------------------Dashboard End---------------------------------------------------------------

# ------------------------------------------Signup start---------------------------------------------------------------


def signup(request):
    
    if request.method == 'POST':
        
        username = request.POST['username']
        email = request.POST['email']
        pass1 = request.POST['pass1']
        pass2 = request.POST['pass2']

        recaptcha_response = request.POST.get('g-recaptcha-response', None)
        if not recaptcha_response:
            messages.error(request, "Please complete the ReCaptcha!")
           
            return redirect("signup")

        if User.objects.filter(username = username):
            messages.error(request, "Username already exists. Try another one")
            return redirect("signup")
        if User.objects.filter(email = email):
            messages.error(request, "email already exists")
            return redirect("signup")
        if len(username)>10:
            messages.error(request, "Username should not exceed 10 characters")
            return redirect("store/signup")
        
        if pass1 != pass2:
            messages.error(request, "Passwords didn't match")
            return redirect("signup")

        myuser = User.objects.create_user(username, email, pass1)
        myuser.is_active = False
        myuser.save()
        messages.success(request, "Your account has been successfully created. Confirm your email to activate account.")
        customer = Customer(
                            user = myuser,
                            name=myuser,
                            email= email,
                            balance = 0
        )
        customer.save()
        sender = settings.EMAIL_HOST_USER
        recipient = email
        current_site = get_current_site(request)

        subject = "Welcome to Secret Hackers CLub Ecommerce - Confirm Your Account"

        msg2 = render_to_string('store/email_confirmation.html', {
            'name': username,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser),
        })

        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = recipient

        text_part = MIMEText('Plain text version of the message', 'plain')
        html_part = MIMEText(msg2, 'html')

        msg.attach(text_part)
        msg.attach(html_part)

        server = smtplib.SMTP_SSL(settings.EMAIL_HOST, 465)

        server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
        server.sendmail(sender, [recipient], msg.as_string())

        server.quit()


        user = authenticate(request, email=email, password = pass2)
        # login(request, user)
        # if customer.balance == 0:
        #     return redirect('first_time_payment')
        return redirect("signin")
    context = {
        'captcha': FormWithCaptcha
    }
    return render(request, 'store/signup.html', context)
# ------------------------------------------Signup end------------------------------------------------------------------

# ------------------------------------------Signin start-----------------------------------------------------------------
def signin(request):
    if not request.user.is_authenticated:
        
        if request.method == 'POST':
            username = request.POST['username']
            pass1 = request.POST['pass']
            print('pass1')
            recaptcha_response = request.POST.get('g-recaptcha-response', None)
            if not recaptcha_response:
                messages.error(request, "Please complete the ReCaptcha!")
                print('pass2')
                return redirect("signin")
            
            if "@" in username:
                if not User.objects.filter(email = username):
                    messages.error(request, 'email not found!')
                    print('pass3')
                    return redirect("signin")
                user = authenticate(request, email=username, password = pass1)
                # print(user)
                # print(type(username))
            else:
                if not User.objects.filter(username = username):
                    messages.error(request, 'Username not found!')
                    print('pass4')
                    return redirect("signin")
                user = authenticate(username=username, password = pass1)
            if user is not None:
                # print(" : ",request.user.customer.isVerified)
                login(request, user)
                fname = user.first_name
                u_name = user.get_username()
                email = user.email
                pass1 = user.password
                customer = user.customer
                is_new = customer.isNew
                is_verified = customer.isVerified

                if not is_verified:
                    sender = settings.EMAIL_HOST_USER
                    recipient = email
                    current_site = get_current_site(request)
                    subject = "Confirmation of Your Account"

                    msg2 = render_to_string('store/email_confirmation.html', {
                        'name': username,
                        'domain': current_site.domain,
                        'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
                        'token': generate_token.make_token(myuser),
                    })
                    msg = MIMEMultipart('alternative')
                    msg['Subject'] = subject
                    msg['From'] = sender
                    msg['To'] = recipient
                    text_part = MIMEText('Plain text version of the message', 'plain')
                    html_part = MIMEText(msg2, 'html')
                    msg.attach(text_part)
                    msg.attach(html_part)
                    server = smtplib.SMTP_SSL(settings.EMAIL_HOST, 465)
                    server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
                    server.sendmail(sender, [recipient], msg.as_string())
                    server.quit()
                    messages.success(request, "Confirmation link sent to your email!")
                    print('pass5')
                    return redirect("signin")
                else:
                    if is_new:
                        return redirect("first_time_payment")
                    
                        
                return redirect("home")
            else:
                messages.error(request, "Invalid Login Credentials")
                print('pass6')
                return redirect("signin")
    context = {
        'captcha':FormWithCaptcha
        }
    return render(request, 'store/signin.html', context)


# ------------------------------------------Signin end--------------------------------------------------------------------
# ------------------------------------------Signout end--------------------------------------------------------------------
def signout(request):
    logout(request)
    messages.success(request, "Logged out successfully")
    return redirect("signin")
# ------------------------------------------Signout end--------------------------------------------------------------------

# ------------------------------------------market_place start---------------------------------------------------------------


def market_place(request):
    # prod = product.objects.values('value').distinct()
    distinct_values = product.objects.values('value').distinct()
    prod = product.objects.filter(value__in=[item['value'] for item in distinct_values])
    
    # prod = product.objects.all()
    print(prod)
    flashcards = Flash_Sales.objects.all()
    for produ in prod:
        print(produ)
        # print(produ.value)
        # print(produ.id)
        print()

    if request.user.is_authenticated:
        customer = request.user.customer
        order, created = Order.objects.get_or_create(customer=customer, complete = False)
        items = order.orderitem_set.all()
        cartItems = order.get_cart_items
    else:
        items = []
        order = {'get_cart_items':0, 'get_cart_total':0}
        cartItems = order['get_cart_total']

    context = {
        'products':prod, 
        'Flash_cards': flashcards, 
        'company_name': company_name , 
        'current_year': current_year, 
        'CartItems': cartItems
    }
    return render(request, 'store/market_place.html', context)
# ------------------------------------------Market_place end---------------------------------------------------------------

# ------------------------------------------Activity start---------------------------------------------------------------


def activity(request):
    if request.user.is_authenticated:
        customer = request.user.customer
        # transact = transactions.get(customer=customer)
        transactions = Order.objects.filter(customer=customer, complete = True)
        order, created = Order.objects.get_or_create(customer=customer, complete = False)
        cartItems = order.get_cart_items
    else:
        cartItems = 0

    context = {
        'transactions': transactions,
        'company_name': company_name, 
        'CartItems': cartItems
    }
    return render(request, 'store/myactivity.html', context)
# ------------------------------------------Activity end---------------------------------------------------------------

# ------------------------------------------Account start---------------------------------------------------------------
def account(request):
    if not request.user.is_authenticated:
        return redirect('signin')

    if request.user.is_authenticated:
        customer = request.user.customer
        order, created = Order.objects.get_or_create(customer=customer, complete = False)
        cartItems = order.get_cart_items
    else:
        customer=''
        cartItems = 0
    context = {
        'customer': customer,
        'company_name': company_name, 
        'CartItems': cartItems
    }
    return render(request, 'store/myaccount.html', context)
# ------------------------------------------Account End---------------------------------------------------------------

# ------------------------------------------reset_password start---------------------------------------------------------------
def reset_password(request):
    if request.method == 'POST':
        email = request.POST['email']
        # print(email)
        try:
            # myuser = User.objects.get(email = email)
            myuser = Customer.objects.get(email = email)
            username = myuser.username
            # print(username)
          
        except Exception as e:
            myuser = None

        # if not myuser:
        if myuser:
        #     messages.error(request, "Email address not found, please provide a registered email address")
        #     return redirect("reset_password")
        # else:
            messages.success(request, "please check your email for a password reset link")
            sender = settings.EMAIL_HOST_USER
            recipient = email
            current_site = get_current_site(request)

            subject = " Password Reset Request for Your Account"

            msg2 = render_to_string('store/password_reset.html', {
                'name': username,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
                'token': generate_token.make_token(myuser),
            })

            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = sender
            msg['To'] = recipient

            text_part = MIMEText('Plain text version of the message', 'plain')
            html_part = MIMEText(msg2, 'html')
            msg.attach(text_part)
            msg.attach(html_part)
            server = smtplib.SMTP_SSL(settings.EMAIL_HOST, 465)
            server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
            server.sendmail(sender, [recipient], msg.as_string())
            server.quit()

            return redirect("reset_password")
     
    return render(request, 'store/reset_password.html')

# ------------------------------------------reset_password End---------------------------------------------------------------

# ------------------------------------------cart start---------------------------------------------------------------
def cart(request):
    if request.user.is_authenticated:
        customer = request.user.customer
        order, created = Order.objects.get_or_create(customer=customer, complete = False)
        items = order.orderitem_set.all()
        cartItems = order.get_cart_items
    else:
        items = []
        order = {'get_cart_items':0, 'get_cart_total':0}
        cartItems = order['get_cart_total']

    context = {
        'items': items, 
        'order': order,
        'company_name': company_name, 
        'CartItems':cartItems
    }
    return render(request, 'store/cart.html', context)
# ------------------------------------------cart End---------------------------------------------------------------

# ------------------------------------------checkout start---------------------------------------------------------------

def checkout(request):

    if request.user.is_authenticated:
        email = request.user.email
        username = request.user.get_username()
    
        customer = request.user.customer
        order, created = Order.objects.get_or_create(customer=customer, complete = False)
        items = order.orderitem_set.all()
        cartItems = order.get_cart_items

        # return redirect("home")
    else:
        items = []
        order = {'get_cart_items':0, 'get_cart_total':0}
        cartItems = order['get_cart_total']

    context = {
        'username' : username,
        'user_email': email,
        'items': items,
        'company_name': company_name , 
        'order': order, 
        'CartItems':cartItems
    }
    return render(request, 'store/checkout.html', context)
# ------------------------------------------checkout End---------------------------------------------------------------

# ------------------------------------------deposit start---------------------------------------------------------------
def deposit(request):
    if not request.user.is_authenticated:
        return redirect('signin')
    if request.method == 'POST':
        amount = int(request.POST['amount'])
        if amount < 50:
            amount = 50
    else:
        amount = 50
    client = Client(api_key=settings.COINBASE_COMMERCE_API_KEY)
    domain_url = 'https://www.darksales-shc.com/webhook/'
    product = {
        # info to capture in webhook
            'metadata': {
            'customer_id': request.user.id if request.user.is_authenticated else None,
            'customer_username': request.user.username if request.user.is_authenticated else None,
            },
            'name': 'Deposit',

            'local_price': {
                            'amount': amount,
                            'currency': 'USD'
                            },
            'pricing_type': 'fixed_price',
            # 'redirect_url': domain_url + 'dashboard/',
            'redirect_url': domain_url + 'website/index/',
            'cancel_url': domain_url + 'deposit/',
    }
    charge = client.charge.create(**product)
# ---------------------------------------- Stripe ------------------------------------------------------
    stripe.api_key = settings.STRIPE_SECRET_KEY
    session = stripe.checkout.Session.create( 
        payment_method_types = ['card'],
        line_items = [{
            'price': 'price_1OASYGA3uxThpfeVyZ9Iq440',
            'quantity': 1,
        }],
        mode = 'payment',
        success_url = request.build_absolute_uri(reverse('home')) + '?session_id={CHECKOUT_SESSION_ID}',
        cancel_url = request.build_absolute_uri(reverse('first_time_payment')),
    )
    context = {
        'charge':charge, 
        'session_id': session.id,
        'stripe_public_key': settings.STRIPE_PUBLIC_KEY
    }
    # logout(request)
    return render(request, 'store/deposit.html', context)
# ------------------------------------------deposit End---------------------------------------------------------------

# ------------------------------------------process_payment start---------------------------------------------------------------


def process_payment(request):

    context = {

    }
    # return render(request, 'process_payment.html', context)
    return redirect('myaccount')
# ------------------------------------------process_payment End---------------------------------------------------------------

# ------------------------------------------coinbase_webhook start---------------------------------------------------------------

@csrf_exempt
@require_http_methods(['POST'])
def coinbase_webhook(request):
    # customer = request.user.customer
    # is_new = customer.isNew
    is_existing = customer.isExisting
    # After successful deposit, set  is_new = False and is_existing = True
    logger = logging.getLogger(__name__)
    request_data = request.body.decode('utf-8')
    request_sig = request.headers.get('X-CC-Webhook-Signature', None)
    webhook_secret = settings.COINBASE_COMMERCE_WEBHOOK_SHARED_SECRET

    try:
        event = Webhook.construct_event(request_data, request_sig, webhook_secret)
        
    except (SignatureVerificationError, WebhookInvalidPayload) as e:
        return HttpResponse(e, status=400)
    
    # if event['type'] == 'charge:confirmed':
    #         logger.info('Payment confirmed.')
    #         customer_id = event['data']['metadata']['customer_id'] 
    #         customer_username = event['data']['metadata']['customer_username']

    logger.info(f'Received event: id={event.id}, type={event.type}')
    return HttpResponse('ok', status=200)
# ------------------------------------------coinbase_webhook End--------------------------------------------------------------
# ------------------------------------------activate start---------------------------------------------------------------
def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
        customer = myuser.customer
        is_new = customer.isNew
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None
        is_new = True
    if myuser is not None and generate_token.check_token(myuser, token) and is_new:
        myuser.is_active = True
        customer.isVerified = True
        customer.save()
        login(request, myuser)
        return redirect('first_time_payment')
    else:
        messages.error(request, "Activation link expired. Login to activate account!")
        return redirect('signin')
def reset_pass(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None
    if myuser is not None and generate_token.check_token(myuser, token):
        reset_pass_update_url = reverse('reset_pass_update', args=[uidb64, token])  
        return redirect(reset_pass_update_url)
 
    else:
        messages.error(request, "Password reset link expired!!")
        return redirect('reset_password')
    
def reset_pass_update(request, uidb64, token):
    if request.method == 'POST':
        pass1 = request.POST['pass1']
        pass2 = request.POST['pass2']
        if pass1 != pass2:
            messages.error(request, "Passwords didn't match")
            reset_pass_update_url = reverse('reset_pass_update', args=[uidb64, token])  
            return redirect(reset_pass_update_url)
            # return redirect("reset_password")
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            myuser = User.objects.get(pk=uid)
            username = myuser.username
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            myuser = None
        if myuser is not None and generate_token.check_token(myuser, token):
            myuser.set_password(pass2)
            myuser.save()
            messages.success(request, "Password successfully changed")
            return redirect("signin")

    return render(request, 'store/password_update.html')

# ------------------------------------------activate end---------------------------------------------------------------
# ------------------------------------------search start---------------------------------------------------------------
def search(request):
    search = request.GET.get('search')
    payload = []

    if search:
        # objs = product.objects.filter(name__startswith = search)
        objs = product.objects.filter(body_text__icontains = search)
        for obj in objs:
            payload.append({
                'name': obj.name
            })

    return JsonResponse({
        'status':True,
        'payload': payload
    })
# ------------------------------------------search end---------------------------------------------------------------


# ------------------------------------------process_order start---------------------------------------------------------------
def process_order(request):
    data = json.loads(request.body)
    transaction_id= datetime.now().timestamp()
    # form_data = data['form']
       
      
    if request.user.is_authenticated:
        customer = request.user.customer
        order, created = Order.objects.get_or_create(customer=customer, complete = False)
        items = order.orderitem_set.all()
        
        total = float(data['form']['total'])
        email = data['form']['email']
        order.transaction_id = transaction_id
        order.order_amount = total

        retailers = []
        for item in items:
            item_name = item.product.name
            item_value = item.product.value
            item_quantity = item.quantity
            item_data_set = (item_name, item_value, item_quantity)
            retailers.append(item_data_set)

        s_dict = {}
        for rt in retailers:
            brand, worth, quantity = rt[0], rt[1], rt[2]
            brand_products = product.objects.filter(name=brand, value=worth)
            if brand not in s_dict:
                s_dict[brand] = {}

            if len(brand_products) >= quantity:
                selected_products = brand_products[:quantity]
                cN = []
                cP = []
                eM = []
                pd = []
                s_dict[brand][worth] = {}
                for s_product in selected_products:
                    if s_product.cardNo != 'N/A':
                        cN.append(s_product.cardNo)
                        s_dict[brand][worth]['Card No'] = cN

                    if s_product.cardPin != 'N/A':
                        cP.append(s_product.cardPin)
                        s_dict[brand][worth]['Card Pin'] = cP

                    if s_product.emailAddress != 'N/A':
                        eM.append(s_product.emailAddress)
                        s_dict[brand][worth]['Email Address'] = eM

                    if s_product.passWord != 'N/A':
                        pd.append(s_product.passWord)
                        s_dict[brand][worth]['Password'] = pd

        if total == order.get_cart_total:
            ac = Customer.objects.get(name=customer)
            ac.balance = (ac.balance-total)
            sender = settings.EMAIL_HOST_USER
            recipient = email
            current_site = get_current_site(request)
            subject = "E-Gift Card Purchase Confirmation 🎉"

            msg2 = render_to_string('store/purchase_confirmation.html', {
                'items':items,
                'order':order,
                'retailer':s_dict,
            })
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = sender
            msg['To'] = recipient
            text_part = MIMEText('Plain text version of the message', 'plain')
            html_part = MIMEText(msg2, 'html')
            msg.attach(text_part)
            msg.attach(html_part)
            server = smtplib.SMTP_SSL(settings.EMAIL_HOST, 465)
            server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
            server.sendmail(sender, [recipient], msg.as_string())
            server.quit()

            order.complete = True
            ac.save()
            # messages.success(request, "Confirmation link sent to your email!")
        order.save()
        
    return JsonResponse('payment Submitted..', safe=False)

# ------------------------------------------process_order end---------------------------------------------------------------

# ------------------------------------------update_items start---------------------------------------------------------------
def update_items(request):
    data = json.loads(request.body)
    productId = data['productId']
    action = data['action']

    customer = request.user.customer
    prod = product.objects.get(id = productId)
    order, created = Order.objects.get_or_create(customer=customer, complete = False)
    orderItem, created = OrderItem.objects.get_or_create(order=order, product=prod)

    if action == 'add':
        orderItem.quantity = (orderItem.quantity + 1)
    elif action == 'remove':
        orderItem.quantity = (orderItem.quantity - 1)
    orderItem.save()

    if orderItem.quantity <=0:
        orderItem.delete()

    return JsonResponse('Item was added', safe=False)
# ------------------------------------------update_items end---------------------------------------------------------------

#Admin charts
def chart_template_view(request):
    #line chart
    line_data = line_chart.objects.all()
    labels = [item.label for item in line_data]
    values = [item.value for item in line_data]
    
    line_data = {
        'labels': labels,
        'values': values,
    }
    Line_data = json.dumps(line_data, cls=DjangoJSONEncoder)

  #pie chart
    pie_data = pie_chart.objects.all()
    labels = [item.brand for item in pie_data]
    values = [item.value for item in pie_data]
    
    pie_data = {
        'labels': labels,
        'values': values, 
    }

    Pie_data = json.dumps(pie_data, cls=DjangoJSONEncoder)

    #sales_chart
    sales_data = sales_chart.objects.all()
    labels = [item.month for item in sales_data]
    values = [item.value for item in sales_data]
    
    data_sales = {
        'labels': labels,
        'values': values,
    }

    Sales_data = json.dumps(data_sales, cls=DjangoJSONEncoder)
    users=User.objects.count()
    context = {
        'Sales_data': Sales_data,
        'Pie_data':Pie_data,
        'users':users,
        'Line_data': Line_data,
    }

    return render(request, 'store/custom_template.html',context)