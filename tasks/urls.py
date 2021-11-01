from django.urls import path
from . import views

app_name = 'tasks'

urlpatterns = [
    path('', views.index, name="list"),
    path('delete/<str:pk>/', views.deleteTask, name="delete")
]