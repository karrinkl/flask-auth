Flask Auth - система аутентификации с 2FA и сбросом пароля

Простой  веб-проект на Flask с полной системой авторизации, регистрацией, двухфакторной аутентификацией (2FA) и функцией сброса пароля.


Функциональность

✅ Регистрация пользователей
✅ Вход с проверкой пароля
✅ Поддержка Google Authenticator (2FA)
✅ Сброс пароля по токену (выводится в консоль)
✅ Защита маршрутов с `@login_required`
✅ Современный интерфейс на Bootstrap 5

Запуск проекта

1. Клонируй репозиторий
git clone https://github.com/your-username/flask-auth-lab.git
cd flask-auth-lab

2. Создай и активируй виртуальное окружение
python -m venv venv
venv\Scripts\activate  # Windows (или source venv/bin/activate  # для macOS/Linux)

3. Установи зависимости
pip install -r requirements.txt

4. Инициализируй базу данных
в терминале вводим: python
после вставляем:
from app import create_app, db
app = create_app()
app.app_context().push()
db.create_all()
exit()

5. Запусти сервер
python run.py

И наконец открой в браузере:
http://127.0.0.1:5000

🛡 Двухфакторная аутентификация
1. После регистрации отображается QR-код
2. Отсканируй его через Google Authenticator
3. При входе система запросит код подтверждения

Сделано в учебных целях
