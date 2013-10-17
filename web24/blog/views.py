#_*_coding:utf-8_*_ 
from math import ceil
from django.shortcuts import render, render_to_response
from django.http import HttpResponse, HttpResponseRedirect
from django.template import RequestContext
from django.contrib.auth.models import User 
from blog.models  import Letter, Group,ProUser, Article, Reply
from django.contrib.auth import login, logout, authenticate
from django.core.exceptions import ObjectDoesNotExist
import hashlib


	
def index(request):
	group_list = Group.objects.order_by('-id').all()[:5]
	article_list = Article.objects.order_by('-id').all()[:5]
	return render(request,'index.html',{'group_list': group_list, 'user':request.user,'article_list':article_list})


def p_index(request,id):
	if request.user.is_authenticated():
		group_list = Group.objects.order_by('-id').all()[:5]
		article_list = Article.objects.order_by('-id').all()[:5]
		u = User.objects.get(id=id)
		add_user = u.prouser.attention.all()
		print add_user
	return render(request,'p_index.html',{'group_list': group_list, 'user':request.user,'article_list':article_list,'add_user':add_user})



def people_index(req,id):
	u = User.objects.get(id=id)
	article_list = u.article_set.order_by('-id').all()[:5]
	return render(req,'people_index.html',{'user_name':u,'article_list':article_list})

def login_user(request):
	if request.method == 'POST':
		username = request.POST['username']
		password = request.POST['passwd']
		password = hashlib.sha1(username + password).hexdigest()
		user = authenticate(username=username, password=password)
		id = user.id
		if user is not None:
			login(request, user)
	return HttpResponseRedirect('/p_index/%s' % id)

def sign_user(request):
	if request.method == 'POST':
		username = request.POST['username']
		email = request.POST['email']
		password = request.POST['passwd']
		password = hashlib.sha1(username + password).hexdigest()
        user = User.objects.create_user(username=username,email=email)
        user.set_password(password)
        user.save()
        id = user.id
        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
        return HttpResponseRedirect('/p_index/%s'%id)
	else:
        return HttpResponseRedirect('/index/')

def create_group(request):
	if request.method == 'POST':
		if request.user.is_authenticated():
			user = request.user
			isPublic = request.POST.get('ispub')
			if isPublic == 'True':
				is_done = True
			else:
				is_done = False
			groupname = request.POST.get('groupname')
			groupdesc = request.POST.get('groupdesc')
			group = Group.objects.create(groupname=groupname,master=user,
				isPublic=is_done ,description=groupdesc)
			group.members.add(user)
			group.save()
			return HttpResponseRedirect('/index/')
	return render(request,'create_group.html',{'user':request.user})

def about_group(request):
	if request.user.is_authenticated():
		user = request.user
	else:
		user = ''
	return render(request,'about_group.html',{'user':user})

def view_group(request, id):
	group = Group.objects.get(id=id)

	return render(request, 'my_group.html',{'group':group})


def add_group(request, id):
	try:
		group = Group.objects.get(id=id)
	except ObjectDoesNotExist:
		return HttpResponse('exists group')
	if request.user.is_authenticated():
		user = request.user
		if user not in group.members.all():
			group.members.add(user)
			group.save()
			return HttpResponseRedirect('/group/%s/' % id)
		return HttpResponse('this user is group master or group member')
	return HttpResponse('please login')

def add_member(request, id):
	group = Group.objects.get(id=id)
	if request.method == "POST":
		mem = request.POST.get('member')
		try:
			member = User.objects.get(username=mem)
		except ObjectDoesNotExist:
			return HttpResponse('user dose not exists')
		if member not in group.members.all():
			Letter.objects.create(letter='',post_user=request.user, recv_user=member, invite_id=group.id)
			return HttpResponseRedirect('/group/%s/' % id)
	return render(request, 'add_mem.html', {'group':group})


def blog_me(request, id):
	about_user = User.objects.get(id=id)
	letter_list = about_user.recv.all()
	user = request.user 
	return render(request, 'blog.html', {'about_user': about_user, 'user':user,
					'letter_list':letter_list})

def letter(request, id):
	if request.user.is_authenticated():
		user = request.user
	else:
		user = ""
	about_user = User.objects.get(id=id)
	if request.method == 'POST':
		content = request.POST.get('letter')
		Letter.objects.create(letter=content,post_user=user, recv_user=about_user)
		return HttpResponseRedirect('/blog/%s/' % about_user.id)
	return render(request, 'letter.html',{'user':user, 'about_user':about_user})

def recv_mail(request, id):
	about_user = User.objects.get(id=id)
	letter_list = about_user.recv.all()
	user = request.user 
	return render(request, 'my_mail.html', {'about_user': about_user, 'user':user,
					'letter_list':letter_list})

def attention(request, id):
	about_user = User.objects.get(id=id)
	if request.user.is_authenticated():
		user = request.user
		user.prouser.attention.add(about_user)
		id = id
		return HttpResponseRedirect('/cancel_attention/%s' % id)
	return HttpResponse('attention friends')


def cancel_attention(request,id):
	about_user = User.objects.get(id=id)
	if request.user.is_authenticated():
		user = request.user
		user.prouser.attention.remove(about_user)
	return render(request, 'blog.html', {'about_user':about_user, 'user':user})


def del_group(request, id):
	group = Group.objects.get(id=id)
	grouernam.delete()
	return HttpResponseRedirect('/index/')

def article(request, id):
	group = Group.objects.get(id=id)
	user = request.user
	if request.method == "POST":
		title = request.POST.get('title')
		content = request.POST.get('content')
		Article.objects.create(title=title,content=content,
										author=user,group=group)

		return HttpResponseRedirect('/group/%s/' % id)
	return render(request,'article.html',{'group':group, 'user':user})

def topic(request, id):
	article = Article.objects.get(id=id)
	user = request.user
	if request.method == 'POST':
		content = request.POST.get('content')
		if content:
			Reply.objects.create(content=content, article=article,user=user)	
	return render(request, 'topic.html',{'article':article})

def account(request, id):
	user = request.user
	if request.method == 'POST':
		email = request.POST.get('email',user.email)
		if email:
			user.email = email
		headimg = request.FILES['headimg']
		ProUser.objects.create(user=user,headimg=headimg)
		password = request.POST.get('newpasswd')
		if password:
			password = hashlib.sha1(user.username + password).hexdigest()
			user.set_password(password)
		user.save()
		return HttpResponseRedirect('/account/%s/' % id)

	return render(request, 'account.html', {})

def logout_user(request):
	request.session.clear()
	return HttpResponseRedirect('/index/')

def discover(request):
    groups = Group.objects.filter(isPublic=True)[::-1]
    group_len = len(groups)
    group_list = zip([groups[x] for x in filter(lambda x: x%2==0,xrange(group_len))],[groups[x] for x in filter(lambda x: x%2==1,xrange(group_len))])
    if request.user.is_authenticated():
        user = request.user
        attentioned_list = user.members.all()
    else:
        attentioned_list = []
    return render(request,'discover.html',{'group_list':group_list,'attentioned_list':attentioned_list})
