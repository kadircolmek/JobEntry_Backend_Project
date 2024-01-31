from datetime import datetime
from functools import wraps
from flask import Blueprint, render_template, redirect, url_for, request, flash, session, abort, current_app
from flask_login import current_user
from passlib.hash import sha256_crypt
from flask_wtf import FlaskForm
from wtforms import Form, StringField, PasswordField, TextAreaField, FileField, validators
from .models import User, Advertisement, Testimonial, Subscriber, ContactQuery, JobApplication
from werkzeug.utils import secure_filename
from . import db, is_admin
import os


auth = Blueprint('auth', __name__)

# User Login Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" in session:
            return f(*args, **kwargs)
        else:
            flash("Please login to view this page!", "danger")
            return redirect(url_for("auth.login"))
    return decorated_function 


# User Register Form
class RegisterForm(Form):
    name = StringField("Name and Surname", validators=[validators.Length(min=4, max=25)])
    username = StringField("Username", validators=[validators.Length(min=5, max=35)])
    email = StringField("E-Mail", validators=[validators.Email(message="Please Enter a Valid Email Address...")])
    password = PasswordField("Password", validators=[
        validators.DataRequired(message="Please Enter a Password..."),
        validators.EqualTo(fieldname="confirm", message="Entered Passwords Do Not Match...")
    ])
    confirm = PasswordField("Verify Password")
    

# User Login Form
class LoginForm(Form):
    username = StringField("Username")
    password = PasswordField("Password") 
    

# Advertisement Form
class AdForm(FlaskForm):
    title = StringField("Advertisement Title", validators=[validators.Length(min=5, max=100)])
    content = TextAreaField("Advertisement Content", validators=[validators.Length(min=10)])
    location = StringField("Location", validators=[validators.Length(max=100)])
    employment_type = StringField("Employment Type", validators=[validators.Length(max=50)])
    category = StringField("Category", validators=[validators.Length(max=50)])
    salary_range = StringField("Salary Range", validators=[validators.Length(max=50)])
    author = StringField("Author", validators=[validators.Length(max=100)])
    job_description = TextAreaField("Job Description")
    responsibilities = TextAreaField("Responsibilities")
    qualifications = TextAreaField("Qualifications")
    
    
# Apply Job Form
class ApplyJobForm(FlaskForm):
    full_name = StringField("Full Name", validators=[validators.Length(min=4, max=100), validators.DataRequired()])
    email = StringField("Email", validators=[validators.Email(message="Please Enter a Valid Email Address..."), validators.DataRequired()])
    resume_file = FileField("Resume File", validators=[validators.DataRequired()]) 


# User Register
@auth.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm(request.form)
    if request.method == "POST" and form.validate():
        name = form.name.data
        username = form.username.data
        email = form.email.data
        password = sha256_crypt.encrypt(form.password.data)
        
        new_user = User(name=name, username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()

        flash("You have been successfully registered...", "success")
        return redirect(url_for("auth.login"))  
    return render_template("login.html", form=form)


# User Login
@auth.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm(request.form)
    if request.method == "POST" and form.validate():
        username = form.username.data
        password_entered = form.password.data
        
        user = User.query.filter_by(username=username).first()
        if user and sha256_crypt.verify(password_entered, user.password):
            session["logged_in"] = True
            session["username"] = username
            flash("You have successfully logged in...", "success")
            return redirect(url_for("views.home"))  
        else:
            flash("Username or password is incorrect!", "danger")
            return redirect(url_for("auth.login"))  
    return render_template("login.html", form=form)


# Advertisement Add
@auth.route("/advertisement", methods=["GET", "POST"])
@login_required
def advertisement():
    form = AdForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        location = form.location.data
        employment_type = form.employment_type.data
        category = form.category.data
        salary_range = form.salary_range.data
        job_description = form.job_description.data
        responsibilities = form.responsibilities.data
        qualifications = form.qualifications.data
        current_time = datetime.now()

        new_advertisement = Advertisement(
            title=title, content=content,
            location=location, employment_type=employment_type, category=category,
            salary_range=salary_range, job_description=job_description,
            responsibilities=responsibilities, qualifications=qualifications,
            author=session["username"], created_date=current_time
        )
        db.session.add(new_advertisement)
        db.session.commit()

        flash("Advertisement Created Successfully", "success")
        return redirect(url_for("views.profile"))

    return render_template("advertisement.html", form=form)



# Advertisement Edit
@auth.route('/edit-ad/<int:ad_id>', methods=['GET', 'POST'])
def edit_ad(ad_id):
    ad = Advertisement.query.get_or_404(ad_id)

    if request.method == 'POST':
        ad.title = request.form['title']
        ad.content = request.form['content']
        ad.location = request.form['location']
        ad.employment_type = request.form['employment_type']
        ad.category = request.form['category']
        ad.salary_range = request.form['salary_range']
        ad.job_description = request.form['job_description']
        ad.responsibilities = request.form['responsibilities']
        ad.qualifications = request.form['qualifications']
        ad.author = request.form['author']
        
        db.session.commit()
        return redirect(url_for('views.profile'))

    return render_template('edit_ad.html', ad=ad)

# Advertisement Delete
@auth.route('/delete-ad/<int:ad_id>', methods=['POST'])
def delete_ad(ad_id):
    ad = Advertisement.query.get_or_404(ad_id)
    db.session.delete(ad)
    db.session.commit()
    return redirect(url_for('views.profile'))


@auth.route('/advertisement/<int:ad_id>')
def advertisement_detail(ad_id):
    ad = Advertisement.query.get(ad_id)
    return render_template('job_detail.html', ad=ad)

# Testimonial Add
@auth.route('/add_testimonial', methods=['POST'])
def add_testimonial():
    client_name = request.form['client_name']
    profession = request.form['profession']
    comment = request.form['comment']

    new_testimonial = Testimonial(client_name=client_name, profession=profession, comment=comment)
    db.session.add(new_testimonial)
    db.session.commit()

    return redirect(url_for('views.testimonial'))


# Add Profile Photos
UPLOAD_FOLDER = 'website/static/uploads'  
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'} 

@auth.route('/upload_profile_picture', methods=['POST'])
@login_required
def upload_profile_picture():
    if 'profile_picture' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('views.profile'))

    file = request.files['profile_picture']

    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('views.profile'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        username = session['username']
        filename = f"{username}.jpg"  
        file.save(os.path.join(UPLOAD_FOLDER, filename))

        current_user = User.query.filter_by(username=username).first()
        current_user.profile_picture = filename
        db.session.commit()

        flash('Profile picture uploaded successfully', 'success')
        return redirect(url_for('views.profile'))
    else:
        flash('Invalid file type. Allowed file types are: png, jpg, jpeg, gif', 'danger')
        return redirect(url_for('views.profile'))

    
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@auth.route('/job-detail/<int:job_id>', methods=['GET', 'POST'])
@login_required
def job_detail(job_id):
    job = Advertisement.query.get_or_404(job_id)

    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        message = request.form['message']

        job_application = JobApplication(
            job_id=job.id,
            full_name=full_name,
            email=email,
            message=message
        )

        db.session.add(job_application)
        db.session.commit()

        flash('Job application submitted successfully!', 'success')
        return redirect(url_for('views.job_detail', job_id=job.id))

    return render_template('job_detail.html', job=job)

   
# Subscriber Button
@auth.route('/subscribe', methods=['POST'])
def subscribe():
    if request.method == 'POST':
        email = request.form['email']
        
        # E-posta veritabanında var mı kontrol et
        existing_email = Subscriber.query.filter_by(email=email).first()
        if existing_email:
            flash('This email is already registered!', 'warning')
        else:
            new_email = Subscriber(email=email)
            db.session.add(new_email)
            db.session.commit()
            flash('Email successfully saved!', 'success')
        
        return redirect(url_for("views.home"))
    
    
# Contact Function 
@auth.route('/contact-query', methods=['POST'])
def contact_query():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message = request.form.get('message')

        new_query = ContactQuery(name=name, email=email, subject=subject, message=message)
        db.session.add(new_query)
        db.session.commit()

        flash('Your query has been submitted successfully!', 'success')
        return redirect(url_for('views.contact'))  

    flash('An error occurred while submitting your query. Please try again.', 'danger')
    return redirect(url_for('views.contact'))



# Logout
@auth.route("/logout")
def logout():
    session.clear()
    flash("You have successfully logged out...", "success")
    return redirect(url_for("views.home"))  


# Create or edit users in the admin panel
@auth.route('/create_or_edit_user', methods=['POST'])
def create_or_edit_user():
    if not is_admin():
        flash('You do not have permission to perform this action', 'danger')
        return redirect(url_for('admin.home'))
