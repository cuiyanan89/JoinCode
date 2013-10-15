#_*_coding:utf-8_*_ 

from django.contrib import admin
from django.contrib.auth.models import User
from blog.models import ProUser, Letter, Group



class GroupAdmin(admin.ModelAdmin):
	list_display = ('groupname', 'master','create_time')
	search_fields = ('groupname', 'master')
	ordering = ('-create_time',)
	filter_vertical = ('members',)

admin.site.register(ProUser)
admin.site.register(Letter)
admin.site.register(Group, GroupAdmin)