from . import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime


# User Tablosu
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(25))
    username = db.Column(db.String(35), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    profile_picture = db.Column(db.String(255))
    is_admin = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f"<User {self.username}>"

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

# Advertisement Tablosu
class Advertisement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    content = db.Column(db.Text)
    location = db.Column(db.String(100))
    employment_type = db.Column(db.String(50))
    category = db.Column(db.String(50)) 
    salary_range = db.Column(db.String(50))
    job_description = db.Column(db.Text)
    responsibilities = db.Column(db.Text)
    qualifications = db.Column(db.Text)
    author = db.Column(db.String(100))  
    created_date = db.Column(db.DateTime, default=datetime.utcnow)

    
    
# Testimonial Table
class Testimonial(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_name = db.Column(db.String(100))
    profession = db.Column(db.String(100))
    comment = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  

    def __repr__(self):
        return f"<Testimonial {self.client_name}>"
    
    
# Subscriber Table
class Subscriber(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)


# Contact Query Table
class ContactQuery(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f"ContactQuery('{self.name}', '{self.email}', '{self.subject}')"
 

# Job Apply Table   
class JobApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('advertisement.id'), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    application_date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"JobApplication('{self.full_name}', '{self.email}')"
    
