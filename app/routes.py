from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User
from app.forms import LoginForm, RegisterForm, RequestResetForm, ResetPasswordForm, TwoFactorForm
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
import io
import base64

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return redirect(url_for('main.login'))

# --- АВТОРИЗАЦИЯ ---

@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            session['pre_2fa_user_id'] = user.id
            return redirect(url_for('main.two_factor'))
        flash('Неверные данные', 'danger')
    return render_template('login.html', form=form)

@main.route('/two_factor', methods=['GET', 'POST'])
def two_factor():
    if 'pre_2fa_user_id' not in session:
        return redirect(url_for('main.login'))

    user = User.query.get(session['pre_2fa_user_id'])
    form = TwoFactorForm()

    if form.validate_on_submit():
        if user.verify_totp(form.token.data):
            login_user(user)
            session.pop('pre_2fa_user_id', None)
            return redirect(url_for('main.dashboard'))
        flash('Неверный код подтверждения', 'danger')

    return render_template('two_factor.html', form=form)

@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))

# --- РЕГИСТРАЦИЯ ---

@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed = generate_password_hash(form.password.data)
        otp_secret = pyotp.random_base32()
        user = User(username=form.username.data, password=hashed, otp_secret=otp_secret)
        db.session.add(user)
        db.session.commit()
        flash('Регистрация прошла успешно. Отсканируйте QR-код для настройки 2FA.', 'info')
        return redirect(url_for('main.show_qr', username=user.username))
    return render_template('register.html', form=form)

# --- КАБИНЕТ ---

@main.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)

# --- СБРОС ПАРОЛЯ ---

@main.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            token = user.get_reset_token()
            reset_url = url_for('main.reset_token', token=token, _external=True)
            print(f'\nСсылка для сброса пароля:\n{reset_url}\n')
            flash('Ссылка для сброса отправлена (смотри консоль).', 'info')
        else:
            flash('Пользователь не найден.', 'danger')
        return redirect(url_for('main.login'))
    return render_template('reset_request.html', form=form)

@main.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    user = User.verify_reset_token(token)
    if not user:
        flash('Недействительный или истёкший токен', 'warning')
        return redirect(url_for('main.reset_request'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed = generate_password_hash(form.password.data)
        user.password = hashed
        db.session.commit()
        flash('Пароль обновлён. Теперь вы можете войти.', 'success')
        return redirect(url_for('main.login'))
    return render_template('reset_token.html', form=form)

# --- QR-КОД ДЛЯ 2FA ---

@main.route('/show_qr/<username>')
def show_qr(username):
    user = User.query.filter_by(username=username).first()
    if not user or not user.otp_secret:
        flash('Пользователь не найден или секрет отсутствует', 'danger')
        return redirect(url_for('main.login'))

    uri = user.get_totp_uri()
    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    img_b64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

    return render_template('show_qr.html', img_data=img_b64, username=user.username)
