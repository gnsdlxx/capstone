from django.urls import path
from . import views
from .views import SignupView, LoginView

urlpatterns = [
    path("signup/", views.SignupView.as_view()),
    path('login/', views.Login),
]
