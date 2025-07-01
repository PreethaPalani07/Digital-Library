import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, FileField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, Optional
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit, join_room, leave_room
import logging # For better logging

# --- App Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = b'K\xe5\tw\x05bX\x17\xce\xe1\x17\xb4\x8fcY\xe4\xee\x1c\xca\xae\xca\xa3\xe0m'
 # Change this!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db' # Database will be in the instance folder or root
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads', 'materials') # Subfolder for materials
app.config['ALLOWED_EXTENSIONS'] = {'mp4', 'mov', 'avi', 'mkv', 'pdf', 'doc', 'docx', 'ppt', 'pptx', 'txt'}

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True) # Added exist_ok=True

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
socketio = SocketIO(app, async_mode='eventlet') # Specify async_mode

# Setup logging
logging.basicConfig(level=logging.INFO) # You can set to logging.DEBUG for more verbose output
app.logger.setLevel(logging.INFO)

# --- Helper Functions ---
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# --- Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='student') # 'student', 'teacher', 'admin'

    # Role-specific attributes
    admission_no = db.Column(db.String(50), nullable=True) # For students
    staff_code = db.Column(db.String(50), nullable=True)   # For teachers

    materials_uploaded = db.relationship('Material', backref='uploader', lazy=True, cascade="all, delete-orphan")
    tests_created = db.relationship('Test', backref='creator', lazy=True, cascade="all, delete-orphan")
    test_attempts = db.relationship('TestAttempt', backref='student_user', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def _repr_(self):
        return f"<User {self.username} ({self.role})>"

class Material(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    filename = db.Column(db.String(200), nullable=False)
    file_type = db.Column(db.String(20), nullable=False)
    subject = db.Column(db.String(100), nullable=True)
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def _repr_(self):
        return f"<Material {self.title}>"

class Test(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    questions = db.relationship('Question', backref='test', lazy=True, cascade="all, delete-orphan")
    attempts = db.relationship('TestAttempt', backref='test_taken', lazy=True, cascade="all, delete-orphan")

    def _repr_(self):
        return f"<Test {self.title}>"

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_id = db.Column(db.Integer, db.ForeignKey('test.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    option_a = db.Column(db.String(200), nullable=False)
    option_b = db.Column(db.String(200), nullable=False)
    option_c = db.Column(db.String(200), nullable=True)
    option_d = db.Column(db.String(200), nullable=True)
    correct_option = db.Column(db.String(1), nullable=False)

    def _repr_(self):
        return f"<Question {self.id} for Test {self.test_id}>"

class TestAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    test_id = db.Column(db.Integer, db.ForeignKey('test.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    total_questions = db.Column(db.Integer, nullable=False)
    attempt_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def _repr_(self):
        return f"<TestAttempt by User {self.user_id} on Test {self.test_id} - Score: {self.score}/{self.total_questions}>"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Forms ---
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('student', 'Student'), ('teacher', 'Teacher')], validators=[DataRequired()])
    admission_no = StringField('Admission No (Students only)', validators=[Optional(), Length(max=50)])
    staff_code = StringField('Staff Code (Teachers only)', validators=[Optional(), Length(max=50)])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already registered.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class MaterialUploadForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=150)])
    description = TextAreaField('Description', validators=[Optional()])
    subject = StringField('Subject/Topic', validators=[DataRequired(), Length(max=100)])
    material_file = FileField('Material File (Video, PDF, DOC, PPT)', validators=[DataRequired()])
    submit = SubmitField('Upload Material')

class TestCreationForm(FlaskForm):
    title = StringField('Test Title', validators=[DataRequired(), Length(max=150)])
    subject = StringField('Subject', validators=[DataRequired(), Length(max=100)])
    submit = SubmitField('Create Test & Add Questions')

class QuestionForm(FlaskForm):
    text = TextAreaField('Question Text', validators=[DataRequired()])
    option_a = StringField('Option A', validators=[DataRequired()])
    option_b = StringField('Option B', validators=[DataRequired()])
    option_c = StringField('Option C', validators=[Optional()])
    option_d = StringField('Option D', validators=[Optional()])
    correct_option = SelectField('Correct Option', choices=[('a', 'A'), ('b', 'B'), ('c', 'C'), ('d', 'D')],
                                 validators=[DataRequired()])
    submit = SubmitField('Add Question')


# --- Routes ---
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('dashboard_admin'))
        elif current_user.role == 'teacher':
            return redirect(url_for('dashboard_teacher'))
        else: # student
            return redirect(url_for('dashboard_student'))
    return render_template('index.html', now=datetime.utcnow()) # Added now for footer

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data,
                    email=form.email.data,
                    password_hash=hashed_password,
                    role=form.role.data)

        if form.role.data == 'student':
            app.logger.info(f"Registering student, admission_no from form: {form.admission_no.data}")
            if form.admission_no.data: # Only assign if data is present
                user.admission_no = form.admission_no.data
            else:
                user.admission_no = None # Explicitly set to None if field is empty (optional, DB handles it)
        elif form.role.data == 'teacher':
            app.logger.info(f"Registering teacher, staff_code from form: {form.staff_code.data}")
            if form.staff_code.data:
                user.staff_code = form.staff_code.data
            else:
                user.staff_code = None

        db.session.add(user)
        try:
            db.session.commit()
            app.logger.info(f"User {user.username} registered successfully.")
            flash('Your account has been created! You are now able to log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error during registration commit for user {form.username.data}: {str(e)}", exc_info=True)
            flash(f'An error occurred: {str(e)}. Please try again or contact support.', 'danger')
            # No redirect here, stay on registration page to show errors
    else:
        if request.method == 'POST': # If form validation fails on POST
            app.logger.warning(f"Registration form validation failed: {form.errors}")
            flash('Please correct the errors below.', 'warning')

    return render_template('register.html', title='Register', form=form, now=datetime.utcnow())

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            app.logger.info(f"User {user.username} logged in successfully.")
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            app.logger.warning(f"Login failed for email {form.email.data}.")
            flash('Login Unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', title='Login', form=form, now=datetime.utcnow())

@app.route('/logout')
@login_required
def logout():
    app.logger.info(f"User {current_user.username} logged out.")
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# --- Student Dashboard ---
@app.route('/dashboard/student')
@login_required
def dashboard_student():
    if current_user.role != 'student':
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))
    materials = Material.query.order_by(Material.upload_date.desc()).all()
    tests = Test.query.all()
    return render_template('dashboard_student.html', materials=materials, tests=tests, now=datetime.utcnow())

# --- Teacher Dashboard ---
@app.route('/dashboard/teacher')
@login_required
def dashboard_teacher():
    if current_user.role != 'teacher':
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))
    uploaded_materials = Material.query.filter_by(user_id=current_user.id).order_by(Material.upload_date.desc()).all()
    created_tests = Test.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard_teacher.html',
                           uploaded_materials=uploaded_materials,
                           created_tests=created_tests, now=datetime.utcnow())

# --- Admin Dashboard ---
@app.route('/dashboard/admin')
@login_required
def dashboard_admin():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))
    users = User.query.all()
    materials = Material.query.order_by(Material.upload_date.desc()).all()
    return render_template('dashboard_admin.html', users=users, materials=materials, now=datetime.utcnow())

# --- Material (Content) Management ---
@app.route('/upload_material', methods=['GET', 'POST'])
@login_required
def upload_material():
    if current_user.role not in ['teacher', 'admin']:
        flash('You do not have permission to upload materials.', 'danger')
        return redirect(url_for('index'))

    form = MaterialUploadForm()
    if form.validate_on_submit():
        if form.material_file.data and allowed_file(form.material_file.data.filename):
            filename = secure_filename(form.material_file.data.filename)
            file_ext = filename.rsplit('.', 1)[1].lower()

            timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
            unique_filename = f"{timestamp}_{filename}"

            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            try:
                form.material_file.data.save(file_path)
                new_material = Material(title=form.title.data,
                                        description=form.description.data,
                                        filename=unique_filename,
                                        file_type=file_ext,
                                        subject=form.subject.data,
                                        uploader=current_user)
                db.session.add(new_material)
                db.session.commit()
                app.logger.info(f"Material '{new_material.title}' uploaded by {current_user.username}.")
                flash('Material uploaded successfully!', 'success')
                if current_user.role == 'teacher':
                     return redirect(url_for('dashboard_teacher'))
                else: # admin
                     return redirect(url_for('dashboard_admin'))
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error uploading material: {str(e)}", exc_info=True)
                flash(f'Error uploading material: {str(e)}', 'danger')
        else:
            flash('Invalid file type or no file selected.', 'danger')
    return render_template('upload_material.html', title='Upload Material', form=form, now=datetime.utcnow())

@app.route('/materials')
@login_required
def view_materials():
    search_query = request.args.get('search', '')
    subject_filter = request.args.get('subject', '')

    query = Material.query
    if search_query:
        query = query.filter(Material.title.ilike(f'%{search_query}%') | Material.description.ilike(f'%{search_query}%'))
    if subject_filter:
        query = query.filter(Material.subject.ilike(f'%{subject_filter}%'))

    materials = query.order_by(Material.upload_date.desc()).all()
    subjects_query = db.session.query(Material.subject).distinct().all()
    subjects = [s[0] for s in subjects_query if s[0]]

    return render_template('view_materials.html', materials=materials, subjects=subjects,
                           current_search=search_query, current_subject=subject_filter, now=datetime.utcnow())


@app.route('/uploads/materials/<filename>')
@login_required
def uploaded_file(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        app.logger.error(f"File not found: {filename} in {app.config['UPLOAD_FOLDER']}")
        flash("File not found.", "danger")
        # Redirect to a sensible page, e.g., materials list or dashboard
        if current_user.role == 'student':
            return redirect(url_for('dashboard_student'))
        elif current_user.role == 'teacher':
            return redirect(url_for('dashboard_teacher'))
        else:
            return redirect(url_for('dashboard_admin'))


@app.route('/material/<int:material_id>/delete', methods=['POST'])
@login_required
def delete_material(material_id):
    material = Material.query.get_or_404(material_id)
    if current_user.role == 'admin' or material.user_id == current_user.id:
        try:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], material.filename)
            if os.path.exists(file_path):
                os.remove(file_path)

            db.session.delete(material)
            db.session.commit()
            app.logger.info(f"Material '{material.title}' (ID: {material_id}) deleted by {current_user.username}.")
            flash('Material deleted successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error deleting material ID {material_id}: {str(e)}", exc_info=True)
            flash(f'Error deleting material: {str(e)}', 'danger')
    else:
        flash('You do not have permission to delete this material.', 'danger')

    if current_user.role == 'admin':
        return redirect(url_for('dashboard_admin'))
    elif current_user.role == 'teacher':
        return redirect(url_for('dashboard_teacher'))
    else:
        return redirect(url_for('view_materials'))


# --- Test Management ---
@app.route('/create_test', methods=['GET', 'POST'])
@login_required
def create_test():
    if current_user.role not in ['teacher', 'admin']:
        flash('You do not have permission to create tests.', 'danger')
        return redirect(url_for('index'))
    form = TestCreationForm()
    if form.validate_on_submit():
        new_test = Test(title=form.title.data, subject=form.subject.data, creator=current_user)
        db.session.add(new_test)
        db.session.commit()
        app.logger.info(f"Test '{new_test.title}' created by {current_user.username}.")
        flash('Test created! Now add questions.', 'success')
        return redirect(url_for('add_questions_to_test', test_id=new_test.id))
    return render_template('create_test.html', title='Create Test', form=form, now=datetime.utcnow())

@app.route('/test/<int:test_id>/add_questions', methods=['GET', 'POST'])
@login_required
def add_questions_to_test(test_id):
    test = Test.query.get_or_404(test_id)
    if current_user.id != test.user_id and current_user.role != 'admin':
        flash('You can only add questions to your own tests.', 'danger')
        return redirect(url_for('dashboard_teacher'))

    form = QuestionForm()
    if form.validate_on_submit():
        question = Question(test_id=test.id,
                            text=form.text.data,
                            option_a=form.option_a.data,
                            option_b=form.option_b.data,
                            option_c=form.option_c.data if form.option_c.data else None, # Handle empty optional fields
                            option_d=form.option_d.data if form.option_d.data else None,
                            correct_option=form.correct_option.data)
        db.session.add(question)
        db.session.commit()
        app.logger.info(f"Question added to test '{test.title}' by {current_user.username}.")
        flash('Question added successfully!', 'success')
        form = QuestionForm(formdata=None) # Clear form for next question
        return redirect(url_for('add_questions_to_test', test_id=test_id))

    questions = Question.query.filter_by(test_id=test.id).all()
    return render_template('add_questions.html', title='Add Questions', form=form, test=test, questions=questions, now=datetime.utcnow())


@app.route('/tests')
@login_required
def list_tests():
    tests = Test.query.order_by(Test.title).all()
    return render_template('list_tests.html', tests=tests, now=datetime.utcnow())


@app.route('/take_test/<int:test_id>', methods=['GET', 'POST'])
@login_required
def take_test(test_id):
    if current_user.role != 'student':
        flash('Only students can take tests.', 'danger')
        return redirect(url_for('index'))

    test = Test.query.get_or_404(test_id)

    if request.method == 'POST':
        score = 0
        total_questions = len(test.questions)
        answers = {}

        for question in test.questions:
            submitted_answer = request.form.get(f'question_{question.id}')
            answers[question.id] = submitted_answer
            if submitted_answer and submitted_answer == question.correct_option:
                score += 1

        attempt = TestAttempt(user_id=current_user.id,
                              test_id=test.id,
                              score=score,
                              total_questions=total_questions)
        db.session.add(attempt)
        db.session.commit()
        app.logger.info(f"Student {current_user.username} attempted test '{test.title}', score: {score}/{total_questions}.")
        flash('Test submitted!', 'success')
        session[f'test_answers_{attempt.id}'] = answers
        return redirect(url_for('test_result', attempt_id=attempt.id))

    if not test.questions:
        flash('This test has no questions. Please contact the instructor.', 'warning')
        return redirect(url_for('list_tests'))

    return render_template('take_test.html', test=test, now=datetime.utcnow())


@app.route('/test_result/<int:attempt_id>')
@login_required
def test_result(attempt_id):
    attempt = TestAttempt.query.get_or_404(attempt_id)
    if attempt.user_id != current_user.id and current_user.role not in ['teacher', 'admin']:
        flash('You are not authorized to view this result.', 'danger')
        return redirect(url_for('dashboard_student'))

    test = Test.query.get(attempt.test_id)
    return render_template('test_result.html', attempt=attempt, test=test, now=datetime.utcnow())

@app.route('/test/<int:test_id>/records')
@login_required
def view_test_records(test_id):
    test = Test.query.get_or_404(test_id)
    if current_user.role not in ['teacher', 'admin'] and test.user_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))

    attempts = TestAttempt.query.filter_by(test_id=test.id).order_by(TestAttempt.attempt_date.desc()).all()
    return render_template('view_test_records.html', test=test, attempts=attempts, now=datetime.utcnow())


# --- User Management (Admin) ---
@app.route('/admin/users')
@login_required
def admin_manage_users():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))
    users = User.query.order_by(User.username).all()
    return render_template('admin_manage_users.html', users=users, now=datetime.utcnow())

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))

    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete.id == current_user.id:
        flash('You cannot delete your own account.', 'warning')
        return redirect(url_for('admin_manage_users'))

    try:
        # Cascade deletes are now set in model relationships
        db.session.delete(user_to_delete)
        db.session.commit()
        app.logger.info(f"Admin {current_user.username} deleted user {user_to_delete.username} (ID: {user_id}).")
        flash(f'User {user_to_delete.username} deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting user ID {user_id}: {str(e)}", exc_info=True)
        flash(f'Error deleting user: {str(e)}. Check for related data.', 'danger')
    return redirect(url_for('admin_manage_users'))


# --- Chat ---
chat_users = {} # {sid: username}

@app.route('/chat')
@login_required
def chat():
    teachers = User.query.filter_by(role='teacher').all()
    return render_template('chat.html', current_username=current_user.username, teachers=teachers, now=datetime.utcnow())

@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        chat_users[request.sid] = current_user.username
        app.logger.info(f'Chat client connected: {current_user.username} ({request.sid})')
        join_room('general_chat')
        emit('user_status', {'username': current_user.username, 'status': 'online', 'users_online': list(chat_users.values())}, room='general_chat')
    else:
        app.logger.warning("Unauthenticated user tried to connect to chat.")
        return False # Disconnect unauthenticated users

@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in chat_users:
        username = chat_users.pop(request.sid)
        app.logger.info(f'Chat client disconnected: {username} ({request.sid})')
        leave_room('general_chat')
        emit('user_status', {'username': username, 'status': 'offline', 'users_online': list(chat_users.values())}, room='general_chat')


@socketio.on('send_message')
def handle_send_message(data):
    if current_user.is_authenticated and request.sid in chat_users:
        message = data.get('message')
        # recipient = data.get('recipient') # For future direct messaging

        app.logger.info(f"Chat message from {current_user.username}: {message}")
        emit('receive_message', {
            'username': current_user.username,
            'message': message,
            'timestamp': datetime.utcnow().isoformat() + "Z" # ISO format for JS Date
        }, room='general_chat')
    else:
        app.logger.warning(f"Unauthenticated or unknown SID tried to send chat message: {request.sid}, data: {data}")


# --- Utility: Create Admin and Initialize DB ---
@app.cli.command('create-admin')
def create_admin_user_command():
    """Creates a default admin user."""
    email = input("Enter admin email: ")
    username = input("Enter admin username: ")
    password = input("Enter admin password: ")

    if User.query.filter((User.email == email) | (User.username == username)).first():
        print("Admin user with this email or username already exists.")
        return

    admin_user = User(
        username=username,
        email=email,
        role='admin'
    )
    admin_user.set_password(password)
    db.session.add(admin_user)
    db.session.commit()
    print(f"Admin user {username} created successfully.")

@app.cli.command('init-db')
def init_db_command():
    """Initializes the database and creates tables."""
    with app.app_context(): # Ensure we're in the app context
        db.create_all()
    print("Database initialized and tables created!")
    # Optionally create a default admin if none exists
    if not User.query.filter_by(role='admin').first():
        print("No admin user found. Consider running 'flask create-admin'.")

# Context processor to make 'now' available to all templates for the footer
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}


if __name__ == '_main_':
    # To initialize DB first time:
    # 1. In terminal, run: flask init-db
    # 2. Then run: flask create-admin (and follow prompts)
    #
    # For running the app:
    # Use flask run for development with Flask's built-in server.
    # For SocketIO, it's better to run directly or with a proper WSGI server.
    # socketio.run(app, debug=True, host='0.0.0.0', port=5000, use_reloader=True)
    # Note: use_reloader=True with eventlet might sometimes be unstable.
    # For production: gunicorn -k eventlet -w 1 app:app
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
