from django.conf.urls import patterns, include, url

urlpatterns = patterns('',

    url(r'^test/$','blog.views.test'),
    url(r'^$', 'blog.views.index'),
    url(r'^index/$', 'blog.views.index'),
    url(r'^login/$', 'blog.views.login_user'),
    url(r'^logout/$', 'blog.views.logout_user'),
    url(r'^regist/$', 'blog.views.sign_user'),
    url(r'^create_group/$', 'blog.views.create_group'),
    url(r'^del_group/(?P<id>\d+)/$', 'blog.views.del_group'),
    url(r'^add_group/(?P<id>\d+)/$', 'blog.views.add_group'),
    url(r'^add_member/(?P<id>\d+)/$', 'blog.views.add_member'),
    url(r'^group/$', 'blog.views.about_group'),
    url(r'^group/(?P<id>\d+)/$', 'blog.views.view_group'),
    url(r'^blog/(?P<id>\d+)/$', 'blog.views.blog_me'),
    url(r'^letter/(?P<id>\d+)/$', 'blog.views.letter'),
    url(r'^my_mail/(?P<id>\d+)/$','blog.views.recv_mail'),
    url(r'^attention/(?P<id>\d+)/$','blog.views.attention'),
    url(r'^account/(?P<id>\d+)/$', 'blog.views.account'),
    url(r'^article/(?P<id>\d+)/$', 'blog.views.article'),
    url(r'^topic/(?P<id>\d+)/$', 'blog.views.topic'),
)
