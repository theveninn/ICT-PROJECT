from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('scan/', views.scan_website, name='scan_website'),
    path('past_scans/', views.past_scans, name='past_scans'),  # Add this line
]
