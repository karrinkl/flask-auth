from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length

class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')

class RegisterForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Зарегистрироваться')

class RequestResetForm(FlaskForm):
    username = StringField('Ваш логин', validators=[DataRequired()])
    submit = SubmitField('Получить ссылку для сброса')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Новый пароль', validators=[DataRequired()])
    submit = SubmitField('Сбросить пароль')

class TwoFactorForm(FlaskForm):
    token = StringField('Код подтверждения', validators=[DataRequired()])
    submit = SubmitField('Подтвердить')
