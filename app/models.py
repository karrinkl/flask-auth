from app import db, login_manager
from flask_login import UserMixin
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask import current_app
import pyotp

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=True)  # Для 2FA

    def get_reset_token(self):
        """Генерация токена для сброса пароля"""
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token, max_age=1800):
        """Проверка токена. Возвращает пользователя или None"""
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token, max_age=max_age)['user_id']
        except Exception:
            return None
        return User.query.get(user_id)

    def get_totp_uri(self):
        """Генерация URI для подключения к Google Authenticator"""
        return f'otpauth://totp/FlaskAuth:{self.username}?secret={self.otp_secret}&issuer=FlaskAuth'

    def verify_totp(self, token):
        """Проверка одноразового кода 2FA"""
        totp = pyotp.TOTP(self.otp_secret)
        return totp.verify(token)
