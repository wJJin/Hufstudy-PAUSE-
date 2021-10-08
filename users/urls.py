from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

app_name = 'users'

urlpatterns = [
    path('agreement/', views.AgreementView.as_view(), name='agreement'),
    path('register/', views.RegisterView.as_view(), name='register'),
    path('registerauth/', views.register_success, name='register_success'),
    path('activate/<str:uid64>/<str:token>/', views.activate, name='activate'),
    path('', views.LoginView.as_view(), name='login'),
    path('logout/', views.logout_view, name='logout'),

    path('mypage/', views.mypage_view, name='mypage'),
    path('mypage/update/', views.mypage_update_view, name='mypage_update'),
    path('mypage/delete/', views.mypage_delete_view, name='mypage_delete'),






]