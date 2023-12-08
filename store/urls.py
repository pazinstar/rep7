from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name ='index'),
    # path('dashboard/', views.dashboard, name ='dashboard'),
    path('dashboard/', views.dashboard, name ='home'),
    path('signup/', views.signup, name ='signup'),
    path('signin/', views.signin, name ='signin'),
    path('signout/', views.signout, name ='signout'),
    path('market_place/', views.market_place, name ='market_place'),
    path('myactivity/', views.activity, name ='myactivity'),
    path('myaccount/', views.account, name ='myaccount'),
    path('reset_password', views.reset_password, name ='reset_password'),
    path('cart/', views.cart, name ='cart'),
    path('checkout/', views.checkout, name ='checkout'),
    path('deposit/', views.deposit, name ='first_time_payment'),
    path('process_payment/', views.process_payment, name ='process_payment'),
    path('webhook/', views.coinbase_webhook), 
    path('activate/<str:uidb64>/<str:token>', views.activate, name ='activate'),
    path('reset_pass/<str:uidb64>/<str:token>', views.reset_pass, name ='reset_pass'),
    path('get_items/', views.search, name ='search'),
    path('process_order/', views.process_order, name ='process_order'),
    path('update_item/', views.update_items, name ='update_item'),
    path('reset_pass_update/<str:uidb64>/<str:token>', views.reset_pass_update, name ='reset_pass_update'),
    # path('send_pass_email/', views.send_password_reset_email, name ='send_pass_email'),
]