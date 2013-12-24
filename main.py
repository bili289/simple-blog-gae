#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import jinja2
import re
import os
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

def getUserById(id):
    return User.get_by_id(int(id))
# return a user object from the database with given valid username and password
# none otherwise
def getUser(name, password):
    return User.all().filter('name =', name).get()

def getFollowingBlogs(self):
    follow_blog_list = []
    if self.user:
        blogs = Blog.all().filter('owner_id = ', self.user.name).order('-created')
        follow_user_list = []
        following = Follower.all().fetch(5)
        for f in following:
            if f.me == self.user.name:
                # print f.following
                follow_user_list.append(f)

            b = Blog.by_name(f.following)
            # print 'b', b.owner_id, b.subject
            if b and b.owner_id != self.user.name:
                follow_blog_list.append(b)
    return follow_blog_list


########## database object for user
class User(db.Model):
    name = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def getUserByName(cls, name):
        u = cls.all().filter('name = ', name).get()
        return u


class Blog(db.Model):
    owner_id = db.StringProperty()
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True) # text area like
    created = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def recent_post(cls, limit, onwer_name):
        blogs = cls.all().filter('owner_id = ', onwer_name).order('-created').fetch(limit)
        return blogs;


    @classmethod
    def by_id(cls, id):
        b = cls.get_by_id(int(id))
        return b

    @classmethod
    def by_name(cls, name):
        bs = cls.all()
        u = User.getUserByName(name)
        for b in bs:
            # print b.owner_id
            if u.name== b.owner_id:
                print 'in blog ', b.content
                return b

    @classmethod
    def by_lastest(cls):
        b = cls.all().order('-created')

    def format(self):
        self.content = self.content.replace('\n', '<br>')
        return self

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("blogentry.html", entry = self)

class Comment(db.Model):
    blog_id = db.StringProperty() 
    author = db.StringProperty(required = True)
    comment = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    def render(self):
        self._render_text = self.comment.replace('\n', '<br>')
        return render_str("commententry.html", comment = self)


# list of 'fans' that follwing 'this' user (you)
class Follower(db.Model):
    me = db.StringProperty() 
    following = db.StringProperty() 

    @classmethod
    def is_following(cls, name):
        return cls.all().filter('following = ', name).get()
    @classmethod
    def unfollow(cls, name):
        user = cls.is_following(name)
        if user:
            user.delete()


###########################
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BlogHandler(webapp2.RequestHandler):
    blogs = []
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def get_cookie(self, name):
        val = self.request.cookies.get(name)
        return val
        
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.get_cookie('user_id')
        self.user = uid and getUserById(long(uid))
        follow_blog_list = []
        blogs = Blog.all()
        for b in blogs:
            follow_blog_list.append(b)
        # follow_blog_list.append("stuff")



# re for validating user data in registration form # # # 
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)
# # #  end of re # # # #


class MainHandler(BlogHandler):
    def get(self):
        if self.user:
            self.render('index.html', follow_blog_list = getFollowingBlogs(self), recent = Blog.recent_post(5, self.user.name))
        else:
            self.render('index.html', follow_blog_list = getFollowingBlogs(self))

# for handling registration form
class RegistrationHandler(BlogHandler):
    def get(self):

        # user = self.request.cookies.get('user')
        # print user
        # username = self.request.get('username')
        # self.response.headers.add_header('Set-Cookie', 'user=%s' %username)
        self.render("signup-form.html")

    def post(self):
        have_error = False
        user_exists = False

        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        print 'get data', username, password, verify
        # # set cookie #######
        # # self.response.set_cookie(username, password)
        # cookie = username+"="+password
        # print cookie
        # self.response.headers.add_header('Set-Cookie', str(cookie))

        params = dict(error = username, message = password)

        # check if user user_exist
        # print 'username',username
        # exists = db.GqlQuery("SELECT * from User where name = :username", username=username)

        exists = User.all()
        for e in exists:
            if e.name == username:
                user_exists = True
                break
        # print 'user exists', user_exists
        if user_exists:
            params['error_exists'] = "Username already exists"
            have_error = True

        if len(username) ==0:
            params['error_username'] = "Username can not be empty"
            have_error = True
        elif not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if len(password) == 0:
            params['error_password'] = "Password can not be empty"
            have_error = True
        elif not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            if email:
                new_user = User(name=username, password = password, email = email)
            else:
                new_user = User(name = username, password = password)
            # register new user to the database    
            new_user.put()
            # # set cookie #######
            # self.response.set_cookie(username, password)
            setcookie(self, str(new_user.key().id()))
            # self.redirect('/registration/welcome?username='+username)
            self.redirect('/welcome')

# # # # # # Blog handlers # # # # # # 
class AddBlogHandler(BlogHandler):
    def get(self):
        if self.user:
            # print follow_blog_list
            self.render('newblogentry.html', follow_blog_list = getFollowingBlogs(self), recent = Blog.recent_post(5, self.user.name))
        else:
            self.redirect('/login')
    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        print " ******", subject, content.encode('utf-8')

        if subject and content:
            entry = Blog(owner_id = str(self.user.name), subject =subject, content = content)
            entry.put()

            blogID = entry.key().id()
            # print blogID
            self.redirect('/blog/%s' % str(blogID))
        else:
            params = dict(error = "", message = "")
            params['error'] = "Suject and/or content must not be empty"
            self.render('newblogentry.html', **params)

# Precious stuff <ancestor key> in GAE
# when filling a new comment and click on post button
# it is not obvious that the comment will show up right away
# this is because of 'eventual consistancy query'
# the solution is strong consistant by using ancestor
# i.e specifies the parent before useing <db.Model>.put()
class SingleBlogEntryHandler(BlogHandler):
    def get(self, blog_id):

        key = db.Key.from_path('Blog', long(blog_id))
        blog = db.get(key)
        if not blog:
            self.error(404)
            return
        # get all the comment for this blog
        comments = Comment.all().filter('blog_id = ', blog_id).order('-created')
        for c in comments:
            print 'comment ', c.comment
        self.render('singleentry.html', entry = blog, comments = comments, follow_blog_list = getFollowingBlogs(self), recent = Blog.recent_post(5, self.user.name))

    def post(self, id):
        author = self.request.get('author')
        comment = self.request.get('comment')
        print author, comment, id   
        blog_id = id

        key = db.Key.from_path('Blog', long(blog_id))
        blog = db.get(key)

        if author and comment:
            c = Comment(parent = blog,blog_id = blog_id, author = author, comment = comment)
            c.put()
            self.redirect('/blog/%s' % blog_id)            
        else:
            params = dict(error="", message="")
            params['error'] = "Author and comment cannot be empty"
            self.render('singleentry.html', entry=blog, **params)

        # comments = Comment.all().filter('blog_id = ', blog_id)
        # for c in comments:
        #     print 'comment ', c.comment
 



class MainBlogHandler(BlogHandler):
    def get(self):
        if self.user:
            ok = True;
            # follow_blog_list = []
            # follow_user_list = []

            blogs = Blog.all().filter('owner_id = ', self.user.name).order('-created')

            # following = Follower.all().fetch(5)
            # for f in following:
            #     if f.me == self.user.name:
            #         # print f.following
            #         follow_user_list.append(f)

            #     b = Blog.by_name(f.following)
            #     # print 'b', b.owner_id, b.subject
            #     if b and b.owner_id != self.user.name:
            #         follow_blog_list.append(b)
            self.render('blogmain.html', blogs = blogs,  follow_blog_list = getFollowingBlogs(self), recent = Blog.recent_post(5, self.user.name))
            # if not ok:
            #     self.render('blogmain.html', blogs = blogs) #, follow_user_list = follow_user_list, follow_blog_list = follow_blog_list)
            # else:
            #     self.render('blogmain.html', blogs = blogs,  follow_blog_list = getFollowingBlogs(self))                
        else:
            self.redirect('/login')
# # # # # # # # # # # # # # # # # # # 

 # now user cookie to get username instead of passing in pas parameter
class WelcomeHandler(BlogHandler):
    # def get(self):
    #   username = self.request.get('username')
    #   print 'welcome', username
    #   self.render('welcome.html', username = username)

    def get(self):
        # 1. get cookie
        self.request.cookies.get(name)

# # # # # # # Login handler # # # # # # # # # # # # 
class LoginHandler(BlogHandler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        print username, password
        # find password from database
        # password_from_db = db.GqlQuery("SELECT password from User where username = :username", username=username)
        user = getUser(username, password)
        # print user
        if user:
            # set cookie here
            setcookie(self, str(user.key().id()))
            self.redirect('/blog')
        else:
            self.redirect('/registration')


# # # # # # # Logout handler # # # # # # # # # # # # 
class LogoutHandler(BlogHandler):
    def get(self):
        # delete cookie
        delcookie(self)
        self.redirect('/login')


# # # # # # # Signup handler # # # # # # # # # # # # 
class WelcomeWithCookieHandler(BlogHandler):
    def get(self):
        print 'self.user ', self.user.name
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/registration')


 # # # # # # # Comment handler # # # # # # # # # # # #   
class CommentHandler(BlogHandler):
    def get(self, id):
        # author = self.request.get('author')
        # comment = self.request.get('comment')
        # print author, comment
        self.render('commentform.html')
    def post(self, id):
        author = self.request.get('author')
        comment = self.request.get('comment')
        print author, comment, id   
        blog_id = id

        comment = Comment(blog_id = blog_id, author = author, comment = comment)
        comment.put()
        self.redirect('/blog/'+blog_id)    

class AllCommentsHandler(BlogHandler):
    def get(self, id):
        # author = self.request.get('author')
        # comment = self.request.get('comment')
        # print author, comment
        comments = Comment.all()
        for c in comments:
            print c.comment

        self.render('commentmain.html', comments = comments)
    # def post(self, id):
    #     author = self.request.get('author')
    #     comment = self.request.get('comment')
    #     print author, comment, id   
    #     blog_id = id

    #     comment = Comment(blog_id = blog_id, author = author, comment = comment)
    #     comment.put()
    #     self.redirect('/blog/'+blog_id)  

 # # # # # # # User handler # # # # # # # # # # # # 
# *********# need more work********

class UserHandler(BlogHandler):
    def get(self, id):
        print id
# id is the name of user that we follow
        is_following = Follower.is_following(id)
        # if is_following.name == self.user.name:
        #     self.redirect('/blog')

        if is_following:
            print 'is_following ', is_following.following
        u = User.getUserByName(str(id))
        if u:
            blogs = Blog.all().filter('owner_id = ' , u.name)
            self.render('user.html', user_id = u.name, blogs = blogs, follow = is_following, follow_blog_list = getFollowingBlogs(self))
        else:
            self.render('user.html', user_id = u)

 # # # # # # # User handler # # # # # # # # # # # # 
class EditBlogHandler(BlogHandler):
    def get(self, blog):
        print blog
        b = Blog.by_id(blog)
        self.render('editblog.html', blog = b)
    def post(self, blog_id):
        print 'EditBlogHandler ',blog_id
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            b = Blog.get_by_id(long(blog_id))
            b.subject = subject
            b.content = content
            b.put()
        self.redirect('/blog/'+blog_id)

class FollowHandler(BlogHandler):
    def get(self, id):
        print id
        me = self.user
        following = User.getUserByName(id)
        print me.name, following.name
        f = Follower(parent = me, me = me.name, following = following.name)
        f.put()
        self.redirect('/%s'% id)

# unfollow handler
class UnFollowHandler(BlogHandler):
    def get(self, id):
        unfollow = Follower.unfollow(id)
        self.redirect('/%s'% id)

class UserSearchHandler(BlogHandler):
    def get(self):
        name = self.request.get('name')
        print name
        u = User.getUserByName(name)
        self.render('user_search.html', u = u, query = name)
    def post(self):
        print 'ahhhh'
        self.redirect('/blog')
        # print name
        # u = User.getUserByName(name)
        # self.render('search_user.html', user = u)


# delete cookie from brower by setting empty value
# reset the path in case it was set to /login or /welcome
def delcookie(self):
    self.response.headers.add_header('Set-Cookie', 'user_id=, Path=/')


def setcookie(self, id):
    cookie = "user_id="+id
    print cookie
    self.response.headers.add_header('Set-Cookie', str(cookie))

app = webapp2.WSGIApplication([
    # ('/', MainHandler),
    ('/registration', RegistrationHandler),
    ('/registration/welcome', WelcomeHandler),
    ('/blog/add', AddBlogHandler),
    ('/blog/([0-9]+)', SingleBlogEntryHandler), 
    ('/blog/([0-9]+)/edit', EditBlogHandler),
    ('/blog/?', MainBlogHandler),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler),
    ('/([0-9]+)', UserHandler),
    ('/welcome', WelcomeWithCookieHandler),
    ('/([a-zA-Z]+)', UserHandler),
    ('/search/name', UserSearchHandler),

    ('/follow/add/([a-zA-Z]+)', FollowHandler),
    ('/follow/remove/([a-zA-Z]+)', UnFollowHandler),
    
    ('/', MainHandler)
], debug=True)
