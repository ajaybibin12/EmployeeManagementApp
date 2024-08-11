from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from models import db, User, Task
from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_login import login_user, login_required, current_user, logout_user
from forms import SignupForm, LoginForm, TaskForm
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'  # Set a secret key for form CSRF protection
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres@localhost/management_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
migrate = Migrate(app, db)

# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_initial_admin():
    with app.app_context():
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', email='admin@example.com', role='admin')
            admin.set_password('admin')
            db.session.add(admin)
            db.session.commit()
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            employees = User.query.filter(User.role.notin_(['admin'])).all()
            return render_template('index.html', employees=employees)
        elif current_user.role in ['worker', 'supervisor']:
            tasks = Task.query.filter_by(assigned_to_id=current_user.id).all()
            return render_template('index.html', tasks=tasks)
    return redirect(url_for('login'))

@app.route('/create_task', methods=['GET', 'POST'])
@login_required
def create_task():
    if current_user.role not in ['admin', 'manager']:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        assigned_to_id = request.form['assigned_to']

        # Create a new task
        new_task = Task(
            title=title,
            description=description,
            assigned_to_id=assigned_to_id,
            created_by_id=current_user.id
        )
        db.session.add(new_task)
        db.session.commit()
        return redirect(url_for('dashboard'))
    users = User.query.filter(User.role.in_(['worker', 'supervisor'])).all()
    return render_template('create_task.html', users=users)

@app.route('/delete_task/<int:task_id>', methods=['POST'])
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)

    if current_user.role not in ['admin', 'manager']:
        return redirect(url_for('dashboard'))

    # Check if the current user is the creator of the task or has the right role
    if current_user.id != task.created_by_id and current_user.role not in ['admin', 'manager']:
        flash('You do not have permission to delete this task.', 'error')
        return redirect(url_for('dashboard'))

    try:
        db.session.delete(task)
        db.session.commit()
        flash('Task deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting task. Please try again.', 'error')
        print(e)

    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role in ['admin', 'manager']:
        tasks = Task.query.all()  # Fetch all tasks for admins and managers
    else:
        tasks = Task.query.filter_by(assigned_to_id=current_user.id).all()  # Fetch only tasks assigned to the current user

    return render_template('dashboard.html', tasks=tasks)

@app.route('/update_task/<int:task_id>', methods=['POST'])
@login_required
def update_task(task_id):
    task = Task.query.get_or_404(task_id)
    if current_user.id != task.assigned_to_id:
        flash('You are not authorized to update this task.', 'danger')
        return redirect(url_for('dashboard'))

    task.comments = request.form['comments']
    task.completion_percentage = request.form['completion_percentage']
    task.status = request.form['status']

    db.session.commit()
    flash('Task updated successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/review_task/<int:task_id>', methods=['POST'])
@login_required
def review_task(task_id):
    task = Task.query.get_or_404(task_id)
    if current_user.role not in ['admin', 'manager']:
        flash('You are not authorized to review this task.', 'danger')
        return redirect(url_for('dashboard'))

    action = request.form['action']
    if action == 'approve':
        if current_user.role == 'admin' or (current_user.role == 'manager' and task.reviewed_by_id is None):
            task.status = 'submitted'
            task.reviewed_by_id = current_user.id
            flash('Task approved and submitted.', 'success')
        else:
            flash('You do not have the authority to approve this task.', 'danger')
    elif action == 'reject':
        task.status = 'working'
        task.reviewed_by_id = None
        flash('Task rejected. Returned to worker/supervisor.', 'warning')

    db.session.commit()
    return redirect(url_for('dashboard'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password, role=form.role.data)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter(
            (User.username == form.username_or_email.data) | 
            (User.email == form.username_or_email.data)
        ).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username/email and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/task/<int:task_id>')
def task_detail(task_id):
    task = Task.query.get_or_404(task_id)
    return render_template('task_detail.html', task=task)

@app.route('/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    if current_user.role != 'admin':
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        role = request.form['role']

        # Ensure the username is unique
        if User.query.filter_by(username=username).first() is not None:
            flash('Username already exists!', 'danger')
            return redirect(url_for('create_user'))

        new_user = User(username=username, email=email, role=role)
        new_user.set_password(password)  # Set the hashed password

        db.session.add(new_user)
        db.session.commit()
        flash('User created successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('create_user.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_initial_admin()
    app.run(debug=True, port=7000)
