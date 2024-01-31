from flask import Blueprint, render_template, redirect, url_for, session, request, flash
from .models import Advertisement, Testimonial

views = Blueprint('views', __name__)

@views.route('/')
def home():
    last_four_jobs = Advertisement.query.order_by(Advertisement.created_date.desc()).limit(4).all()
    testimonials = Testimonial.query.order_by(Testimonial.timestamp.desc()).limit(5).all()
    return render_template('index.html', testimonials=testimonials, last_four_jobs=last_four_jobs)

@views.route("/about")
def about():
    return render_template ("about.html")

@views.route("contact")
def contact():
    return render_template ("contact.html")

@views.route("/category")
def category():
    return render_template ("category.html")

@views.route("/category/<string:category_name>")
def category_jobs(category_name):
    jobs = Advertisement.query.filter_by(category=category_name).all()
    return render_template("category_jobs.html", category_name=category_name, jobs=jobs)

@views.route("/404")
def error():
    return render_template ("404.html")

@views.route('/job-detail/<int:job_id>')
def job_detail(job_id):
    job = Advertisement.query.get_or_404(job_id)
    return render_template('job-detail.html', job=job)

@views.route('/job-list')
def joblist():
    page = request.args.get('page', 1, type=int)
    per_page = 4
    jobs = Advertisement.query.paginate(page=page, per_page=per_page)
    return render_template("job-list.html", jobs=jobs)

@views.route("/testimonial")
def testimonial():
    testimonials = Testimonial.query.order_by(Testimonial.timestamp.desc()).limit(5).all()
    return render_template('testimonial.html', testimonials=testimonials)

@views.route("/profile")
def profile():
    if 'username' in session:
        user_ads = Advertisement.query.filter_by(author=session['username']).order_by(Advertisement.created_date.desc()).all()
        return render_template("profile.html", user_ads=user_ads)
    else:
        return redirect(url_for("auth.login"))
       
@views.route('/search-results', methods=['POST'])
def search_results():
    search_query = request.form.get('search_query')

    if not search_query:
        flash("Please enter a search query.", "warning")
        return redirect(url_for('views.home'))

    search_results = Advertisement.query.filter(
        (Advertisement.title.ilike(f"%{search_query}%")) | 
        (Advertisement.content.ilike(f"%{search_query}%"))
    ).all()

    return render_template('search_results.html', search_results=search_results)

@views.route('/our_services')
def our_services():
    return render_template ('our_services.html')

@views.route('/privacy')
def privacy():
    return render_template ('privacy.html')

@views.route('/terms')
def terms():
    return render_template ('terms.html')
    

