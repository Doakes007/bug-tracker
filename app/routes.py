from flask import Blueprint, render_template, redirect, url_for, flash, request
from app.models import Bug, User
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from .forms import RegisterForm, LoginForm
from .models import User
from . import db
from app.forms import AssignBugForm, UpdateStatusForm
from app.forms import CommentForm
from app.models import BugComment


# ✅ Define blueprint before using it
main = Blueprint('main', __name__)

@main.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('main.login'))

@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data)
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashed_pw,
            role=form.role.data
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html', form=form)

@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('main.home'))
        flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)

@main.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.login'))

@main.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return "Access Denied: Admins only.", 403
    return render_template('admin.html')

@main.route('/report', methods=['GET', 'POST'])
@login_required
def report_bug():
    from .forms import BugForm
    from .models import Bug
    form = BugForm()
    if form.validate_on_submit():
        new_bug = Bug(
            title=form.title.data,
            description=form.description.data,
            steps_to_reproduce=form.steps_to_reproduce.data,
            severity=form.severity.data,
            status="New",
            created_by=current_user.id
        )
        db.session.add(new_bug)
        db.session.commit()
        flash("Bug reported successfully!", "success")
        return redirect(url_for('main.view_bugs'))
    return render_template('report_bug.html', form=form)

@main.route('/bugs')
@login_required
def view_bugs():
    from app.models import Bug, User
    query = Bug.query

    # Role-based filtering
    if current_user.role == 'admin':
        query = query
    elif current_user.role == 'reporter':
        query = query.filter_by(created_by=current_user.id)
    else:
        query = query.filter(
            (Bug.created_by == current_user.id) |
            (Bug.assigned_to == current_user.id)
        )

    # Apply filters from query parameters
    status = request.args.get('status')
    severity = request.args.get('severity')
    search = request.args.get('search')

    if status:
        query = query.filter_by(status=status)

    if severity:
        query = query.filter_by(severity=severity)

    if search:
        query = query.filter(
            Bug.title.ilike(f"%{search}%") | 
            Bug.description.ilike(f"%{search}%")
        )

    bugs = query.order_by(Bug.created_on.desc()).all()
    return render_template('view_bugs.html', bugs=bugs)

    
@main.route('/assign/<int:bug_id>', methods=['GET', 'POST'])
@login_required
def assign_bug(bug_id):
    if current_user.role != 'admin':
        return "Access Denied", 403

    bug = Bug.query.get_or_404(bug_id)
    form = AssignBugForm()

    # ✅ Set the choices dynamically BEFORE validate_on_submit()
    form.assigned_to.choices = [(u.id, u.username) for u in User.query.all() if u.role in ['dev', 'qa']]

    if form.validate_on_submit():
        bug.assigned_to = form.assigned_to.data
        bug.status = 'Assigned'
        db.session.commit()
        flash(f"Bug '{bug.title}' has been assigned.", "success")
        return redirect(url_for('main.view_bugs'))

    return render_template('assign_bug.html', form=form, bug=bug)



from app.models import Bug, BugHistory
from flask_login import current_user

@main.route('/update/<int:bug_id>', methods=['GET', 'POST'])
@login_required
def update_status(bug_id):
    bug = Bug.query.get_or_404(bug_id)
    form = UpdateStatusForm()

    if form.validate_on_submit():
        old_status = bug.status
        bug.status = form.status.data

        # ✅ Create history record
        history = BugHistory(
            bug_id=bug.id,
            user_id=current_user.id,
            old_status=old_status,
            new_status=bug.status,
            comment=form.comment.data  # If your form supports it
        )
        db.session.add(history)
        db.session.commit()

        flash("Bug status updated!", "success")
        return redirect(url_for('main.view_bugs'))

    return render_template('update_status.html', form=form, bug=bug)

    
@main.route('/dashboard')
@login_required
def dashboard():
    from app.models import Bug, User

    if current_user.role == 'admin':
        total_bugs = Bug.query.count()
        assigned = Bug.query.filter(Bug.assigned_to != None).count()
        users = User.query.count()
        return render_template('dashboards/admin_dashboard.html', total_bugs=total_bugs, assigned=assigned, users=users)

    elif current_user.role == 'dev':
        bugs = Bug.query.filter_by(assigned_to=current_user.id).all()
        return render_template('dashboards/dev_dashboard.html', bugs=bugs)

    elif current_user.role == 'qa':
        bugs = Bug.query.filter_by(assigned_to=current_user.id).all()
        return render_template('dashboards/qa_dashboard.html', bugs=bugs)

    else:  # Reporter
        bugs = Bug.query.filter_by(created_by=current_user.id).all()
        return render_template('dashboards/reporter_dashboard.html', bugs=bugs)
        
@main.route('/admin/users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if current_user.role != 'admin':
        return "Access denied", 403

    users = User.query.all()
    return render_template('admin/manage_users.html', users=users)

@main.route('/admin/update_user/<int:user_id>', methods=['POST'])
@login_required
def update_user_role(user_id):
    if current_user.role != 'admin':
        return "Access denied", 403

    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')

    if new_role in ['admin', 'dev', 'qa', 'reporter']:
        user.role = new_role
        db.session.commit()
        flash(f"Updated role for {user.username} to {new_role}", "success")
    else:
        flash("Invalid role", "danger")

    return redirect(url_for('main.manage_users'))
    
@main.route('/bug/<int:bug_id>', methods=['GET', 'POST'])
@login_required
def bug_detail(bug_id):
    bug = Bug.query.get_or_404(bug_id)
    form = CommentForm()

    if form.validate_on_submit():
        comment = BugComment(
            bug_id=bug.id,
            user_id=current_user.id,
            content=form.content.data
        )
        db.session.add(comment)
        db.session.commit()
        flash("Comment added!", "success")
        return redirect(url_for('main.bug_detail', bug_id=bug.id))

    return render_template('bug_history.html', bug=bug, form=form)

    


        







