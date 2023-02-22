from django.shortcuts import render,redirect,get_object_or_404
from django.http import HttpResponse,HttpResponseRedirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.urls import reverse
from django.contrib import messages
from django.contrib.auth.models import User
from employee.models import *
from .forms import UserLogin,UserAddForm
from msilib.schema import ListView
from pyexpat import model
from django.contrib.auth.decorators import user_passes_test
import os
from django.conf import settings
from django.core.exceptions import PermissionDenied, ImproperlyConfigured
from django.http import StreamingHttpResponse, Http404
from django.shortcuts import render
try:
    from django.urls import reverse # pylint: disable=unused-import
except ImportError:
    from django.core.urlresolvers import reverse

from django.utils.module_loading import import_string as import_module
from django.shortcuts import render
from rest_framework import generics, permissions
from rest_framework.response import Response
from knox.models import AuthToken
from .serializers import UserSerializer, RegisterSerializer, LoginUserSerializer
from django.contrib.auth import login
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.contrib.auth.models import User
from rest_framework import status
from django.http import Http404, HttpResponse
from rest_framework.views import APIView
from accounts.serializers import UserSerializer
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import login, authenticate, logout
from rest_framework import permissions
from rest_framework.authtoken.serializers import AuthTokenSerializer
from knox.views import LoginView as KnoxLoginView
from rest_framework import serializers
from rest_framework.permissions import IsAdminUser
from rest_framework import viewsets
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic.detail import DetailView
from django.views import View
from django.http import HttpResponseRedirect, request
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages

 
from django.urls import reverse

from django.views.generic.edit import DeleteView


from django.views.generic.list import ListView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render, redirect 

from django.contrib.auth import get_user_model
from rest_framework.renderers import TemplateHTMLRenderer
from django.shortcuts import get_object_or_404


from django.urls import reverse_lazy
from django.views.generic.edit import DeleteView
from knox.views import LoginView as KnoxLoginView
from django.contrib.auth.mixins import UserPassesTestMixin




def changepassword(request):
	if not request.user.is_authenticated:
		return redirect('/')
	'''
	Please work on me -> success & error messages & style templates
	'''
	if request.method == 'POST':
		form = PasswordChangeForm(request.user, request.POST)
		if form.is_valid():
			user = form.save(commit=True)
			update_session_auth_hash(request,user)

			messages.success(request,'Password changed successfully',extra_tags = 'alert alert-success alert-dismissible show' )
			return redirect('accounts:changepassword')
		else:
			messages.error(request,'Error,changing password',extra_tags = 'alert alert-warning alert-dismissible show' )
			return redirect('accounts:changepassword')
			
	form = PasswordChangeForm(request.user)
	return render(request,'accounts/change_password_form.html',{'form':form})




def register_user_view(request):
	# WORK ON (MESSAGES AND UI) & extend with email field
	if request.method == 'POST':
		form = UserAddForm(data = request.POST)
		if form.is_valid():
			instance = form.save(commit = False)
			instance.save()
			username = form.cleaned_data.get("username")

			messages.success(request,'Account created for {0} !!!'.format(username),extra_tags = 'alert alert-success alert-dismissible show' )
			return redirect('accounts:register')
		else:
			messages.error(request,'Username or password is invalid',extra_tags = 'alert alert-warning alert-dismissible show')
			return redirect('accounts:register')


	form = UserAddForm()
	dataset = dict()
	dataset['form'] = form
	dataset['title'] = 'register users'
	return render(request,'accounts/register.html',dataset)




class Logspe(APIView):
     
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'accounts/login.html'
 

    def get(self, request):
        serializer = LoginUserSerializer()
        if request.accepted_renderer.format == 'html':
            return Response(
                {'serializer': serializer})

    serializer_class = LoginUserSerializer
    permission_classes = (permissions.AllowAny,)
    def post(self, request, *args, **kwargs):
        serializer = LoginUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data
        login(request, user)
        if not serializer.is_valid():
            return Response({'serializer': serializer, 'user': user})
        return redirect('index')
    




def user_profile_view(request):
	'''
	user profile view -> staffs (No edit) only admin/HR can edit.
	'''
	user = request.user
	if user.is_authenticated:
		employee = Employee.objects.filter(user = user).first()
		emergency = Emergency.objects.filter(employee = employee).first()
		relationship = Relationship.objects.filter(employee = employee).first()
		bank = Bank.objects.filter(employee = employee).first()

		dataset = dict()
		dataset['employee'] = employee
		dataset['emergency'] = emergency
		dataset['family'] = relationship
		dataset['bank'] = bank

		return render(request,'dashboard/employee_detail.html',dataset)
	return HttpResponse("Sorry , not authenticated for this,admin or whoever you are :)")





def logout_view(request):
	logout(request)
	return redirect('accounts:login')



def users_list(request):
	employees = Employee.objects.all()
	return render(request,'accounts/users_table.html',{'employees':employees,'title':'Users List'})


def users_unblock(request,id):
	user = get_object_or_404(User,id = id)
	emp = Employee.objects.filter(user = user).first()
	emp.is_blocked = False
	emp.save()
	user.is_active = True
	user.save()

	return redirect('accounts:users')


def users_block(request,id):
	user = get_object_or_404(User,id = id)
	emp = Employee.objects.filter(user = user).first()
	emp.is_blocked = True
	emp.save()
	
	user.is_active = False
	user.save()
	
	return redirect('accounts:users')



def users_blocked_list(request):
	blocked_employees = Employee.objects.all_blocked_employees()
	return render(request,'accounts/all_deleted_users.html',{'employees':blocked_employees,'title':'blocked users list'})