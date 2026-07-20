import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from redactor import redact_file, PATTERNS

# ---------------------------------------------------------------------------
# App Configuration
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(basedir, 'instance', 'app.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(basedir, 'instance'), exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    logs = db.relationship('RedactionLog', backref='owner', lazy=True)

    def __repr__(self):
        return f'&lt;User {self.email}&gt;'


class RedactionLog(db.Model):
    __tablename__ = 'redaction_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    filename = db.Column(db.String(256), nullable=False)
    redacted_count = db.Column(db.Integer, default=0)
    categories = db.Column(db.Text, default='')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'&lt;RedactionLog {self.id}&gt;'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')
        if not email or not password:
            flash('Email and password are required.', 'danger')
            return redirect(url_for('register'))
        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'warning')
            return redirect(url_for('register'))
        user = User(email=email, password=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Welcome back!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid email or password.', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected.', 'danger')
            return redirect(url_for('upload'))
        file = request.files['file']
        if file.filename == '':
            flash('No file selected.', 'warning')
            return redirect(url_for('upload'))

        filename = secure_filename(file.filename)
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(input_path)

        # Collect active patterns from checkboxes
        active_patterns = {}
        for cat in PATTERNS:
            active_patterns[cat] = request.form.get(f'pattern_{cat}') == 'on'

        # Custom terms (comma-separated)
        custom_terms_raw = request.form.get('custom_terms', '')
        custom_terms = [t.strip() for t in custom_terms_raw.split(',') if t.strip()]

        style = request.form.get('style', 'custom')
        custom_label = request.form.get('custom_label', '[REDACTED]')

        output_filename = f'redacted_{filename}'
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)

        success, count, counts, err = redact_file(
            input_path, output_path, active_patterns, custom_terms,
            style=style, custom_label=custom_label,
            redact_all=True, case_sensitive=False,
        )

        if not success:
            flash(f'Redaction failed: {err}', 'danger')
            return redirect(url_for('upload'))

        # Log the redaction
        log = RedactionLog(
            user_id=current_user.id,
            filename=filename,
            redacted_count=count,
            categories=str(counts),
        )
        db.session.add(log)
        db.session.commit()

        flash(f'Successfully redacted {count} items from {filename}!', 'success')
        return send_file(output_path, as_attachment=True, download_name=output_filename)

    return render_template('upload.html', patterns=list(PATTERNS.keys()))


@app.route('/dashboard')
@login_required
def dashboard():
    logs = (RedactionLog.query
            .filter_by(user_id=current_user.id)
            .order_by(RedactionLog.timestamp.desc())
            .all())
    total_files = len(logs)
    total_redactions = sum(log.redacted_count for log in logs)
    return render_template(
        'dashboard.html',
        logs=logs,
        total_files=total_files,
        total_redactions=total_redactions,
    )

# ---------------------------------------------------------------------------
# Database initialisation
# ---------------------------------------------------------------------------
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
