# myapp/urls.py
from django.urls import path
from . import views
from django.contrib.staticfiles.urls import staticfiles_urlpatterns

urlpatterns = [
    path('', views.task_list, name='task_list'),
    path('process_form1/', views.process_form1, name='process_form1'),
    path('process_form2/', views.process_form2, name='process_form2'),
    path('process_form3/', views.process_form3, name='process_form3'),
    path('show_encrypted_message/', views.show_text, name='show_text'),
    path('show_encrypted_message_fernet/', views.show_text_fernet, name='show_text'),
    path('show_encrypted_message_signer/', views.show_text_signer, name='show_text')

]
urlpatterns += staticfiles_urlpatterns()