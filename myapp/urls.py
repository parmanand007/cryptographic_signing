# myapp/urls.py
from django.urls import path
from . import views
from django.contrib.staticfiles.urls import staticfiles_urlpatterns

urlpatterns = [
    path('tasks/', views.task_list, name='task_list'),
    path('process_form1/', views.process_form1, name='process_form1'),
    path('process_form2/', views.process_form2, name='process_form2'),
    path('process_form3/', views.process_form3, name='process_form3'),
    path('show_encrypted_message/', views.show_text, name='show_text')

]
urlpatterns += staticfiles_urlpatterns()