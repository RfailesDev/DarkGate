import asyncio
import subprocess
import logging
import os
import sqlite3
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, IntegerField, SelectField, FileField, PasswordField
from wtforms.validators import DataRequired, NumberRange, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash

# ИСПРАВЛЕННЫЕ ИМПОРТЫ (относительный импорт)
from ..common.rule_manager import RuleManager  # .. означает "на уровень выше"
from ..common.certificate_manager import CertificateManager

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-very-secret-key')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
csrf = CSRFProtect(app)

# Initialize managers
rule_manager = RuleManager(db_path='/data/rules.db')
cert_manager = CertificateManager(cert_dir='/certs')


# Setup logging (лучше использовать logging.config)
# Настройка логирования в файл и stdout
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# В файл
file_handler = logging.FileHandler('/app/admin.log')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# В stdout
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)


# Database setup for admin users
def init_admin_db():
    with sqlite3.connect('/data/admin.db') as conn:
        c = conn.cursor()
        c.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')

        # Check if admin user exists, create default if not
        c.execute('SELECT COUNT(*) FROM admin_users')
        if c.fetchone()[0] == 0:
            default_password = os.environ.get('ADMIN_PASSWORD', 'admin')
            password_hash = generate_password_hash(default_password)
            c.execute(
                'INSERT INTO admin_users (username, password_hash) VALUES (?, ?)',
                ('admin', password_hash)
            )
        conn.commit()


init_admin_db()


# Authentication
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)

    return decorated_function


# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])


class RuleForm(FlaskForm):
    domain = StringField('Domain', validators=[DataRequired()])
    target_port = IntegerField('Target Port', validators=[
        DataRequired(),
        NumberRange(min=1, max=65535, message="Port must be between 1 and 65535")
    ])
    https_mode = SelectField('HTTPS Mode', choices=[
        ('http', 'HTTP Only'),
        ('https_terminate', 'HTTPS Termination'),
        ('https_proxy', 'HTTPS Proxy')
    ])


class CertificateForm(FlaskForm):
    domain = StringField('Domain', validators=[DataRequired()])
    cert_file = FileField('Certificate File (PEM)', validators=[DataRequired()])
    key_file = FileField('Private Key File (PEM)', validators=[DataRequired()])


class LetsEncryptForm(FlaskForm):
    domain = StringField('Domain', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])


class PasswordChangeForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])

    def validate_confirm_password(self, field):
        if field.data != self.new_password.data:
            raise ValidationError("Passwords must match")


# Helper functions
def add_rule_to_db(domain, target_port, https_mode):
    try:
        with sqlite3.connect('/data/rules.db') as conn:
            c = conn.cursor()
            c.execute(
                'INSERT INTO rules (domain, target_port, https_mode) VALUES (?, ?, ?)',
                (domain, target_port, https_mode)
            )
            conn.commit()

        # Update in-memory rules
        rule_manager.rules[domain] = {
            'port': target_port,
            'https_mode': https_mode
        }

        # Notify proxy server
        asyncio.run(rule_manager.notify_rule_change(host='proxy', port=8899))

        return True
    except sqlite3.IntegrityError:
        logger.error(f"Rule for domain {domain} already exists")
        return False
    except Exception as e:
        logger.error(f"Error adding rule: {e}")
        return False


def update_rule_in_db(domain, target_port, https_mode):
    try:
        with sqlite3.connect('/data/rules.db') as conn:
            c = conn.cursor()
            c.execute(
                'UPDATE rules SET target_port = ?, https_mode = ?, updated_at = CURRENT_TIMESTAMP WHERE domain = ?',
                (target_port, https_mode, domain)
            )
            conn.commit()

            if c.rowcount == 0:
                logger.error(f"Rule for domain {domain} not found")
                return False

        # Update in-memory rules
        rule_manager.rules[domain] = {
            'port': target_port,
            'https_mode': https_mode
        }

        # Notify proxy server
        asyncio.run(rule_manager.notify_rule_change(host='proxy', port=8899))

        return True
    except Exception as e:
        logger.error(f"Error updating rule: {e}")
        return False


def delete_rule_from_db(domain):
    try:
        with sqlite3.connect('/data/rules.db') as conn:
            c = conn.cursor()
            c.execute('DELETE FROM rules WHERE domain = ?', (domain,))
            conn.commit()

            if c.rowcount == 0:
                logger.error(f"Rule for domain {domain} not found")
                return False

        # Update in-memory rules
        if domain in rule_manager.rules:
            del rule_manager.rules[domain]

        # Notify proxy server
        asyncio.run(rule_manager.notify_rule_change(host='proxy', port=8899))

        return True
    except Exception as e:
        logger.error(f"Error deleting rule: {e}")
        return False


# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        with sqlite3.connect('/data/admin.db') as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute('SELECT * FROM admin_users WHERE username = ?', (username,))
            user = c.fetchone()

            if user and check_password_hash(user['password_hash'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                flash('Login successful!', 'success')
                next_page = request.args.get('next', url_for('index'))
                return redirect(next_page)

            flash('Invalid username or password', 'danger')

    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    rules = rule_manager.get_rules()
    certs = cert_manager.list_certificates()
    return render_template('index.html', rules=rules, cert_count=len(certs))


@app.route('/rules', methods=['GET', 'POST'])
@login_required
def rules():
    form = RuleForm()
    if form.validate_on_submit():
        domain = form.domain.data
        target_port = form.target_port.data
        https_mode = form.https_mode.data

        if add_rule_to_db(domain, target_port, https_mode):
            flash(f'Rule for {domain} added successfully!', 'success')
        else:
            flash(f'Failed to add rule for {domain}', 'danger')

        return redirect(url_for('rules'))

    rules = rule_manager.get_rules()  #  Не нужен await, т.к. get_rules не асинхронная
    return render_template('rules.html', form=form, rules=rules)


@app.route('/rules/<domain>/edit', methods=['GET', 'POST'])
@login_required
def edit_rule(domain):
    rule = rule_manager.get_rule(domain)
    if not rule:
        flash(f'Rule for {domain} not found', 'danger')
        return redirect(url_for('rules'))

    form = RuleForm()
    if request.method == 'GET':
        form.domain.data = domain
        form.target_port.data = rule['port']
        form.https_mode.data = rule.get('https_mode', 'http')

    if form.validate_on_submit():
        target_port = form.target_port.data
        https_mode = form.https_mode.data

        if update_rule_in_db(domain, target_port, https_mode):
            flash(f'Rule for {domain} updated successfully!', 'success')
        else:
            flash(f'Failed to update rule for {domain}', 'danger')

        return redirect(url_for('rules'))

    return render_template('edit_rule.html', form=form, domain=domain)


@app.route('/rules/<domain>/delete', methods=['POST'])
@login_required
def delete_rule(domain):
    if delete_rule_from_db(domain):
        flash(f'Rule for {domain} deleted successfully!', 'success')
    else:
        flash(f'Failed to delete rule for {domain}', 'danger')

    return redirect(url_for('rules'))


@app.route('/certificates')
@login_required
def certificates():
    certs = cert_manager.list_certificates()
    return render_template('certificates.html', certificates=certs)


@app.route('/certificates/upload', methods=['GET', 'POST'])
@login_required
def upload_certificate():
    form = CertificateForm()
    if form.validate_on_submit():
        domain = form.domain.data
        cert_file = form.cert_file.data
        key_file = form.key_file.data

        cert_data = cert_file.read()
        key_data = key_file.read()

        if cert_manager.save_uploaded_cert(domain, cert_data, key_data):
            flash(f'Certificate for {domain} uploaded successfully!', 'success')
        else:
            flash(f'Failed to upload certificate for {domain}', 'danger')

        return redirect(url_for('certificates'))

    return render_template('upload_certificate.html', form=form)


@app.route('/certificates/letsencrypt', methods=['GET', 'POST'])
@login_required
def letsencrypt_certificate():
    form = LetsEncryptForm()
    if form.validate_on_submit():
        domain = form.domain.data
        email = form.email.data

        if cert_manager.request_letsencrypt_cert(domain, email):
            flash(f'Certificate for {domain} obtained successfully!', 'success')
            # Notify proxy to reload certificates
            asyncio.run(rule_manager.notify_rule_change(host='proxy', port=8899))
        else:
            flash(f'Failed to obtain certificate for {domain}', 'danger')

        return redirect(url_for('certificates'))

    return render_template('letsencrypt.html', form=form)


@app.route('/certificates/<domain>/info')
@login_required
def certificate_info(domain):
    cert_path = f'/certs/{domain}/cert.pem'
    cert_info = cert_manager.get_certificate_info(cert_path)

    if not cert_info:
        flash(f'Certificate for {domain} not found', 'danger')
        return redirect(url_for('certificates'))

    return render_template('certificate_info.html', domain=domain, info=cert_info)


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    form = PasswordChangeForm()
    if form.validate_on_submit():
        current_password = form.current_password.data
        new_password = form.new_password.data

        user_id = session.get('user_id')
        with sqlite3.connect('/data/admin.db') as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute('SELECT * FROM admin_users WHERE id = ?', (user_id,))
            user = c.fetchone()

            if not user or not check_password_hash(user['password_hash'], current_password):
                flash('Current password is incorrect', 'danger')
                return render_template('settings.html', form=form)

            # Update password
            password_hash = generate_password_hash(new_password)
            c.execute(
                'UPDATE admin_users SET password_hash = ? WHERE id = ?',
                (password_hash, user_id)
            )
            conn.commit()

            flash('Password updated successfully!', 'success')
            return redirect(url_for('settings'))

    return render_template('settings.html', form=form)


# Добавляем роут для отображения логов
@app.route('/logs')
@login_required
def logs():
    # Получаем логи прокси-сервера (последние N строк)
    try:
        # Используем docker logs, это самый эффективный способ
        proxy_logs_process = subprocess.run(
            ['docker', 'logs', '--tail', '100', 'darkgate-proxy'],  # последние 100 строк
            capture_output=True, text=True, check=True
        )
        proxy_logs = proxy_logs_process.stdout
    except subprocess.CalledProcessError as e:
        proxy_logs = f"Error getting proxy logs: {e}"
    except FileNotFoundError:
        proxy_logs = "Error: Docker command not found.  Is Docker installed and running?"

    # Получаем логи админ-панели (из файла, последние N строк)
    try:
        with open('/app/admin.log', 'r') as f:  # <--  Читаем из файла!
            # Читаем последние N строк (эффективно)
            log_lines = f.readlines()
            admin_logs = "".join(log_lines[-100:])  # Последние 100 строк

    except FileNotFoundError:
        admin_logs = "Admin log file not found."
    except Exception as e:
        admin_logs = f"Error reading admin logs: {e}"

    return render_template('logs.html', proxy_logs=proxy_logs, admin_logs=admin_logs)



# Сигнал для уведомления прокси-сервера после старта приложения и входа в application context
@app.context_processor
def inject_notify_proxy():
    def notify_proxy():
        asyncio.run(rule_manager.notify_rule_change(host='proxy', port=8899))  # Изменено!
    return dict(notify_proxy=notify_proxy)