from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
import os
from functools import wraps


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('DATABASE_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
blog_posts = SQLAlchemy(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# CONFIGURE TABLES
class User(UserMixin, blog_posts.Model):
    __tablename__ = "users"
    id = blog_posts.Column(blog_posts.Integer, primary_key=True)
    name = blog_posts.Column(blog_posts.String(500))
    email = blog_posts.Column(blog_posts.String(100), unique=True)
    password = blog_posts.Column(blog_posts.String(100))
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(blog_posts.Model):
    __tablename__ = "blog_posts"
    id = blog_posts.Column(blog_posts.Integer, primary_key=True)
    author_id = blog_posts.Column(blog_posts.Integer, blog_posts.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title = blog_posts.Column(blog_posts.String(250), unique=True, nullable=False)
    subtitle = blog_posts.Column(blog_posts.String(250), nullable=False)
    date = blog_posts.Column(blog_posts.String(250), nullable=False)
    body = blog_posts.Column(blog_posts.Text, nullable=False)
    img_url = blog_posts.Column(blog_posts.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")


class Comment(blog_posts.Model):
    __tablename__ = "comments"
    id = blog_posts.Column(blog_posts.Integer, primary_key=True)
    comment_author_id = blog_posts.Column(blog_posts.Integer, blog_posts.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    post_id = blog_posts.Column(blog_posts.Integer, blog_posts.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    text = blog_posts.Column(blog_posts.Text, nullable=False)


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


if not os.path.isfile('sqlite:///blog.db'):
    blog_posts.create_all()


@app.route('/', methods=['GET', 'POST'])
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():

        # If user's email already exists
        if User.query.filter_by(email=form.email.data).first():
            # Send flash messsage
            flash("You've already signed up with that email, log in instead!")
            # Redirect to /login route.
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hash_and_salted_password,
        )
        blog_posts.session.add(new_user)
        blog_posts.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("The email provided could not be found... Please try again!")
            return redirect(url_for("login"))
        elif not check_password_hash(user.password, password):
            flash("The password provided could not be authenticated... Please try again!")
            return redirect(url_for("login"))
        else:
            login_user(user)
            return redirect(url_for("get_all_posts"))
    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
        new_comment = Comment(
            text=form.comment_text.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        blog_posts.session.add(new_comment)
        blog_posts.session.commit()
    return render_template("post.html", post=requested_post, form=form, logged_in=current_user.is_authenticated)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_anonymous or current_user.id != 1:
            flash("You must be an admin to perform that action.")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


@app.route("/new-post", methods=['GET', 'POST'])
@admin_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        blog_posts.session.add(new_post)
        blog_posts.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@admin_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        blog_posts.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    blog_posts.session.delete(post_to_delete)
    blog_posts.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
