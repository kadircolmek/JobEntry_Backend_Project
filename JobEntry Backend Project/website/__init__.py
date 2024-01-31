from flask import Flask, redirect, session, url_for
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_admin.contrib.sqla import ModelView
from flask_admin import Admin
from flask_babel import Babel

db = SQLAlchemy()
DB_NAME = "jobentry.db"

# Admin email address
ADMIN_USERNAME = "astald"


def is_admin():
    return "username" in session and session["username"] == ADMIN_USERNAME


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "jobentry"
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_NAME}"
    db.init_app(app)
    babel = Babel(app)

    admin = Admin(app, name="JobEntry Admin Panel", template_mode="bootstrap4")

    from .views import views
    from .auth import auth

    app.register_blueprint(views, url_prefix="/")
    app.register_blueprint(auth, url_prefix="/")

    from .models import (
        User,
        Advertisement,
        Testimonial,
        Subscriber,
        ContactQuery,
        JobApplication,
    )

    class CustomModelView(ModelView):
        def is_accessible(self):
            return is_admin()

        def inaccessible_callback(self, name, **kwargs):
            return redirect(url_for("auth.login"))

    admin.add_view(CustomModelView(User, db.session))
    admin.add_view(CustomModelView(Advertisement, db.session))
    admin.add_view(CustomModelView(Testimonial, db.session))
    admin.add_view(CustomModelView(Subscriber, db.session))
    admin.add_view(CustomModelView(ContactQuery, db.session))
    admin.add_view(CustomModelView(JobApplication, db.session))

    @app.context_processor
    def utility_processor():
        def get_user_profile_picture(username):
            user = User.query.filter_by(username=username).first()
            if user:
                return user.profile_picture
            return None

        return dict(get_user_profile_picture=get_user_profile_picture)

    create_database(app)

    return app


def create_database(app):
    app.app_context().push()

    if not path.exists("website/" + DB_NAME):
        db.create_all()
        print("Created Database!")
