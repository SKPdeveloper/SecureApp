# server.py
import os
import sqlite3
import hashlib
import secrets
import jwt
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import logging
from logging.handlers import RotatingFileHandler
from functools import wraps

# Завантаження змінних середовища
load_dotenv()

app = Flask(__name__)
CORS(app)  # Включення CORS для взаємодії з клієнтом

# Налаштування логгера для моніторингу подій безпеки
if not os.path.exists('logs'):
    os.makedirs('logs')
file_handler = RotatingFileHandler('logs/security.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)

# Секретний ключ для JWT токенів (в реальному додатку використовувати змінні середовища)
SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(32))

# Ініціалізація бази даних
def init_db():
    conn = sqlite3.connect('secure_remote_work.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP,
        two_factor_enabled BOOLEAN DEFAULT 0,
        two_factor_secret TEXT,
        is_active BOOLEAN DEFAULT 1
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS personal_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        data_type TEXT NOT NULL,
        data_value TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT,
        user_agent TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    conn.commit()
    conn.close()

# Виклик ініціалізації бази даних
init_db()

# Функція для валідації номера телефону
def validate_phone_number(phone):
    import re
    
    # Видалення всіх нецифрових символів, крім +
    cleaned_phone = re.sub(r'[^\d+]', '', phone)
    
    # Перевірка формату +38XXXXXXXXXX
    if cleaned_phone.startswith('+38') and len(cleaned_phone) == 13 and cleaned_phone[1:].isdigit():
        return True, cleaned_phone
    
    # Якщо номер починається з 0 і містить 10 цифр, додаємо +38
    elif cleaned_phone.startswith('0') and len(cleaned_phone) == 10 and cleaned_phone.isdigit():
        fixed_phone = '+38' + cleaned_phone
        return True, fixed_phone
    
    return False, None

# Функція для валідації імені та прізвища
def validate_name(name):
    # Перевіряємо кожен символ у імені/прізвищі
    allowed_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzАБВГДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯабвгдеєжзиіїйклмнопрстуфхцчшщьюяҐґ '-")
    
    for char in name:
        if char not in allowed_chars:
            return False
    
    return True

# Функція для валідації пароля
def validate_password(password):
    # Мінімум 8 символів
    if len(password) < 8:
        return False, "Пароль повинен містити не менше 8 символів"
    
    # Наявність цифри
    if not any(c.isdigit() for c in password):
        return False, "Пароль повинен містити хоча б одну цифру"
    
    # Наявність великої літери
    if not any(c.isupper() for c in password):
        return False, "Пароль повинен містити хоча б одну велику літеру"
    
    # Наявність спеціального символу
    if not any(c in "!@#$%^&*()-_=+[]{}|;:'\",.<>/?`~" for c in password):
        return False, "Пароль повинен містити хоча б один спеціальний символ"
    
    return True, ""

# Функція для хешування паролів
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    # Використання PBKDF2 через hashlib для безпечного хешування паролів
    hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), 
                                  salt.encode('utf-8'), 100000)
    password_hash = hash_obj.hex()
    return password_hash, salt

# Створення JWT токенів
def create_token(user_id):
    # Використовуємо datetime.now() з UTC
    try:
        # Для новіших версій Python (3.11+)
        from datetime import UTC
        current_time = datetime.now(UTC)
        expiration = current_time + timedelta(hours=1)  # Токен дійсний 1 годину
    except ImportError:
        # Для старіших версій Python
        import datetime as dt
        current_time = datetime.now(dt.timezone.utc)
        expiration = current_time + timedelta(hours=1)  # Токен дійсний 1 годину
    
    # Важливо! Переконуємося що user_id це рядок
    user_id_str = str(user_id)
    
    payload = {
        'exp': expiration,
        'iat': current_time,
        'sub': user_id_str  # Використовуємо рядкове представлення
    }
    
    app.logger.info(f"Створюємо токен для user_id: {user_id_str} (тип: {type(user_id_str).__name__})")
    
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    app.logger.info(f"Токен створено: {token[:15]}...")
    
    return token

# Перевірка токенів
def verify_token(token):
    try:
        # Для відлагодження - виведемо токен
        app.logger.info(f"Верифікація токена (початок): {token[:10]}...")
        
        # Декодування токена
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        
        # Перевіримо тип поля sub
        sub_value = payload.get('sub')
        sub_type = type(sub_value).__name__
        app.logger.info(f"Поле 'sub' в токені: {sub_value} (тип: {sub_type})")
        
        app.logger.info(f"Токен успішно декодовано. User ID: {payload['sub']}")
        return payload['sub']
    except jwt.ExpiredSignatureError:
        app.logger.warning("Токен прострочений")
        return None  # Токен прострочений
    except jwt.InvalidTokenError as e:
        app.logger.warning(f"Недійсний токен: {str(e)}")
        return None  # Недійсний токен
    except Exception as e:
        app.logger.error(f"Помилка при перевірці токена: {str(e)}")
        return None

# Декоратор для захисту маршрутів
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        # Для відлагодження
        app.logger.info(f"Заголовок Authorization: {auth_header}")
        
        if auth_header:
            try:
                # Перевіряємо чи є префікс "Bearer "
                if "Bearer " in auth_header:
                    # Вилучаємо токен без пробілів
                    token = auth_header.split("Bearer ")[1].strip()
                else:
                    token = auth_header.strip()
                
                # Виявлення пробілів у токені
                if ' ' in token:
                    app.logger.warning(f"Токен містить пробіли, очищаємо: '{token}'")
                    token = token.replace(' ', '')
                
                app.logger.info(f"Отриманий токен (після обробки): {token[:10]}...")
            except IndexError:
                app.logger.warning("Невірний формат токена")
                return jsonify({'message': 'Невірний формат токена'}), 401
            except Exception as e:
                app.logger.error(f"Помилка при обробці заголовка: {str(e)}")
                return jsonify({'message': 'Помилка при обробці заголовка'}), 401
        
        if not token:
            app.logger.warning("Токен автентифікації відсутній")
            return jsonify({'message': 'Токен автентифікації відсутній'}), 401
        
        user_id = verify_token(token)
        if not user_id:
            app.logger.warning("Токен недійсний або прострочений")
            return jsonify({'message': 'Токен недійсний або прострочений'}), 401
        
        # Конвертуємо user_id назад у число, оскільки в БД це INT
        try:
            user_id = int(user_id)
        except ValueError:
            app.logger.error(f"Неможливо конвертувати user_id '{user_id}' в число")
            return jsonify({'message': 'Помилка автентифікації'}), 401
        
        # Запис у журнал аудиту
        conn = sqlite3.connect('secure_remote_work.db')
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO audit_log (user_id, action, ip_address, user_agent)
        VALUES (?, ?, ?, ?)
        ''', (user_id, f.__name__, request.remote_addr, request.user_agent.string))
        conn.commit()
        conn.close()
        
        app.logger.info(f"Успішна авторизація для user_id: {user_id}")
        return f(user_id, *args, **kwargs)
    
    return decorated

# Маршрути API

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Перевірка наявності всіх необхідних полів
    required_fields = ['username', 'password', 'email', 'first_name', 'last_name']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Відсутні обов\'язкові поля'}), 400
    
    # Валідація імені та прізвища
    if not validate_name(data['first_name']):
        return jsonify({'error': 'Ім\'я містить неприпустимі символи. Використовуйте лише літери.'}), 400
    
    if not validate_name(data['last_name']):
        return jsonify({'error': 'Прізвище містить неприпустимі символи. Використовуйте лише літери.'}), 400
    
    # Валідація пароля
    is_valid_password, password_error = validate_password(data['password'])
    if not is_valid_password:
        return jsonify({'error': f'Слабкий пароль: {password_error}'}), 400
    
    # Підключення до БД
    conn = sqlite3.connect('secure_remote_work.db')
    cursor = conn.cursor()
    
    # Перевірка, чи існує вже користувач
    cursor.execute('SELECT id FROM users WHERE username = ?', (data['username'],))
    if cursor.fetchone():
        conn.close()
        return jsonify({'error': 'Користувач з таким ім\'ям вже існує'}), 409
    
    # Перевірка, чи існує вже email
    cursor.execute('SELECT id FROM users WHERE email = ?', (data['email'],))
    if cursor.fetchone():
        conn.close()
        return jsonify({'error': 'Цей email вже використовується'}), 409
    
    # Хешування пароля
    password_hash, salt = hash_password(data['password'])
    
    # Збереження користувача в БД
    try:
        cursor.execute('''
        INSERT INTO users (username, password_hash, salt, email, first_name, last_name, created_at)
        VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
        ''', (data['username'], password_hash, salt, data['email'], data['first_name'], data['last_name']))
        
        user_id = cursor.lastrowid
        
        # Запис у журнал аудиту
        cursor.execute('''
        INSERT INTO audit_log (user_id, action, ip_address, user_agent)
        VALUES (?, ?, ?, ?)
        ''', (user_id, 'register', request.remote_addr, request.user_agent.string))
        
        conn.commit()
        
        app.logger.info(f'Новий користувач зареєстрований: {data["username"]}')
        
        return jsonify({
            'message': 'Користувач успішно зареєстрований',
            'user_id': user_id
        }), 201
    
    except Exception as e:
        conn.rollback()
        app.logger.error(f'Помилка реєстрації: {str(e)}')
        return jsonify({'error': str(e)}), 500
    
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    
    # Перевірка наявності всіх необхідних полів
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Відсутні обов\'язкові поля'}), 400
    
    # Підключення до БД
    conn = sqlite3.connect('secure_remote_work.db')
    cursor = conn.cursor()
    
    # Пошук користувача
    cursor.execute('SELECT id, password_hash, salt, is_active FROM users WHERE username = ?', 
                  (data['username'],))
    user = cursor.fetchone()
    
    if not user:
        # Запис у журнал про невдалу спробу входу
        app.logger.warning(f'Невдала спроба входу для неіснуючого користувача: {data["username"]}')
        conn.close()
        return jsonify({'error': 'Невірне ім\'я користувача або пароль'}), 401
    
    user_id, stored_hash, salt, is_active = user
    
    if not is_active:
        app.logger.warning(f'Спроба входу для деактивованого користувача: {data["username"]}')
        conn.close()
        return jsonify({'error': 'Обліковий запис деактивовано'}), 403
    
    # Перевірка пароля
    password_hash, _ = hash_password(data['password'], salt)
    
    if password_hash != stored_hash:
        # Запис у журнал про невдалу спробу входу
        app.logger.warning(f'Невдала спроба входу для користувача: {data["username"]}')
        cursor.execute('''
        INSERT INTO audit_log (user_id, action, ip_address, user_agent)
        VALUES (?, ?, ?, ?)
        ''', (user_id, 'failed_login', request.remote_addr, request.user_agent.string))
        conn.commit()
        conn.close()
        return jsonify({'error': 'Невірне ім\'я користувача або пароль'}), 401
    
    # Оновлення часу останнього входу
    cursor.execute('UPDATE users SET last_login = datetime("now") WHERE id = ?', (user_id,))
    
    # Запис у журнал про успішний вхід
    cursor.execute('''
    INSERT INTO audit_log (user_id, action, ip_address, user_agent)
    VALUES (?, ?, ?, ?)
    ''', (user_id, 'login', request.remote_addr, request.user_agent.string))
    
    conn.commit()
    conn.close()
    
    # Створення токена
    token = create_token(user_id)
    
    app.logger.info(f'Користувач увійшов: {data["username"]}')
    
    return jsonify({
        'message': 'Вхід успішний',
        'token': token,
        'user_id': user_id
    }), 200

@app.route('/api/personal-data', methods=['POST'])
@token_required
def add_personal_data(user_id):
    data = request.get_json()
    
    if not data or 'data_type' not in data or 'data_value' not in data:
        return jsonify({'error': 'Відсутні обов\'язкові поля'}), 400
    
    # Валідація даних в залежності від типу
    if data['data_type'] == 'Номер телефону':
        is_valid, validated_phone = validate_phone_number(data['data_value'])
        if not is_valid:
            return jsonify({'error': 'Невірний формат номера телефону. Використовуйте формат +38XXXXXXXXXX або 0XXXXXXXXX.'}), 400
        data['data_value'] = validated_phone
    
    elif data['data_type'] in ['Ім\'я', 'Прізвище']:
        if not validate_name(data['data_value']):
            return jsonify({'error': f'Невірний формат {data["data_type"].lower()}. Використовуйте лише літери.'}), 400
    
    # Підключення до БД
    conn = sqlite3.connect('secure_remote_work.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
        INSERT INTO personal_data (user_id, data_type, data_value, created_at, updated_at)
        VALUES (?, ?, ?, datetime('now'), datetime('now'))
        ''', (user_id, data['data_type'], data['data_value']))
        
        data_id = cursor.lastrowid
        
        conn.commit()
        
        app.logger.info(f'Додано персональні дані для користувача ID {user_id}, тип: {data["data_type"]}')
        
        return jsonify({
            'message': 'Персональні дані успішно додано',
            'data_id': data_id
        }), 201
    
    except Exception as e:
        conn.rollback()
        app.logger.error(f'Помилка при додаванні персональних даних: {str(e)}')
        return jsonify({'error': str(e)}), 500
    
    finally:
        conn.close()

@app.route('/api/personal-data', methods=['GET'])
@token_required
def get_personal_data(user_id):
    # Підключення до БД
    conn = sqlite3.connect('secure_remote_work.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
        SELECT id, data_type, data_value, created_at, updated_at
        FROM personal_data
        WHERE user_id = ?
        ''', (user_id,))
        
        rows = cursor.fetchall()
        
        personal_data = []
        for row in rows:
            personal_data.append({
                'id': row[0],
                'data_type': row[1],
                'data_value': row[2],
                'created_at': row[3],
                'updated_at': row[4]
            })
        
        app.logger.info(f'Користувач ID {user_id} отримав персональні дані')
        
        return jsonify(personal_data), 200
    
    except Exception as e:
        app.logger.error(f'Помилка при отриманні персональних даних: {str(e)}')
        return jsonify({'error': str(e)}), 500
    
    finally:
        conn.close()

@app.route('/api/personal-data/<int:data_id>', methods=['PUT'])
@token_required
def update_personal_data(user_id, data_id):
    data = request.get_json()
    
    if not data or 'data_value' not in data:
        return jsonify({'error': 'Відсутні обов\'язкові поля'}), 400
    
    # Підключення до БД
    conn = sqlite3.connect('secure_remote_work.db')
    cursor = conn.cursor()
    
    try:
        # Перевірка, чи є дані і чи належать вони даному користувачу
        cursor.execute('''
        SELECT data_type FROM personal_data
        WHERE id = ? AND user_id = ?
        ''', (data_id, user_id))
        
        result = cursor.fetchone()
        if not result:
            conn.close()
            return jsonify({'error': 'Персональні дані не знайдено або доступ заборонено'}), 404
        
        data_type = result[0]
        
        # Валідація даних в залежності від типу
        if data_type == 'Номер телефону':
            is_valid, validated_phone = validate_phone_number(data['data_value'])
            if not is_valid:
                return jsonify({'error': 'Невірний формат номера телефону. Використовуйте формат +38XXXXXXXXXX або 0XXXXXXXXX.'}), 400
            data['data_value'] = validated_phone
        
        elif data_type in ['Ім\'я', 'Прізвище']:
            if not validate_name(data['data_value']):
                return jsonify({'error': f'Невірний формат {data_type.lower()}. Використовуйте лише літери.'}), 400
        
        # Оновлення даних
        cursor.execute('''
        UPDATE personal_data
        SET data_value = ?, updated_at = datetime('now')
        WHERE id = ? AND user_id = ?
        ''', (data['data_value'], data_id, user_id))
        
        conn.commit()
        
        app.logger.info(f'Оновлено персональні дані ID {data_id} для користувача ID {user_id}, тип: {data_type}')
        
        return jsonify({
            'message': 'Персональні дані успішно оновлено',
            'data_id': data_id
        }), 200
    
    except Exception as e:
        conn.rollback()
        app.logger.error(f'Помилка при оновленні персональних даних: {str(e)}')
        return jsonify({'error': str(e)}), 500
    
    finally:
        conn.close()

@app.route('/api/personal-data/<int:data_id>', methods=['DELETE'])
@token_required
def delete_personal_data(user_id, data_id):
    # Підключення до БД
    conn = sqlite3.connect('secure_remote_work.db')
    cursor = conn.cursor()
    
    try:
        # Перевірка, чи є дані і чи належать вони даному користувачу
        cursor.execute('''
        SELECT id FROM personal_data
        WHERE id = ? AND user_id = ?
        ''', (data_id, user_id))
        
        if not cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Персональні дані не знайдено або доступ заборонено'}), 404
        
        # Видалення даних
        cursor.execute('''
        DELETE FROM personal_data
        WHERE id = ? AND user_id = ?
        ''', (data_id, user_id))
        
        conn.commit()
        
        app.logger.info(f'Видалено персональні дані ID {data_id} для користувача ID {user_id}')
        
        return jsonify({
            'message': 'Персональні дані успішно видалено'
        }), 200
    
    except Exception as e:
        conn.rollback()
        app.logger.error(f'Помилка при видаленні персональних даних: {str(e)}')
        return jsonify({'error': str(e)}), 500
    
    finally:
        conn.close()

@app.route('/api/change-password', methods=['POST'])
@token_required
def change_password(user_id):
    data = request.get_json()
    
    if not data or 'current_password' not in data or 'new_password' not in data:
        return jsonify({'error': 'Відсутні обов\'язкові поля'}), 400
    
    # Валідація нового пароля
    is_valid_password, password_error = validate_password(data['new_password'])
    if not is_valid_password:
        return jsonify({'error': f'Слабкий пароль: {password_error}'}), 400
    
    # Підключення до БД
    conn = sqlite3.connect('secure_remote_work.db')
    cursor = conn.cursor()
    
    try:
        # Отримання поточного хешу та солі
        cursor.execute('SELECT password_hash, salt FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return jsonify({'error': 'Користувача не знайдено'}), 404
        
        stored_hash, salt = user
        
        # Перевірка поточного пароля
        current_password_hash, _ = hash_password(data['current_password'], salt)
        
        if current_password_hash != stored_hash:
            conn.close()
            return jsonify({'error': 'Невірний поточний пароль'}), 401
        
        # Хешування нового пароля
        new_password_hash, new_salt = hash_password(data['new_password'])
        
        # Оновлення пароля в БД
        cursor.execute('''
        UPDATE users
        SET password_hash = ?, salt = ?
        WHERE id = ?
        ''', (new_password_hash, new_salt, user_id))
        
        # Запис у журнал аудиту
        cursor.execute('''
        INSERT INTO audit_log (user_id, action, ip_address, user_agent)
        VALUES (?, ?, ?, ?)
        ''', (user_id, 'change_password', request.remote_addr, request.user_agent.string))
        
        conn.commit()
        
        app.logger.info(f'Користувач ID {user_id} змінив пароль')
        
        return jsonify({'message': 'Пароль успішно змінено'}), 200
        
    except Exception as e:
        conn.rollback()
        app.logger.error(f'Помилка при зміні пароля: {str(e)}')
        return jsonify({'error': str(e)}), 500
        
    finally:
        conn.close()

@app.route('/api/setup-2fa', methods=['POST'])
@token_required
def setup_2fa(user_id):
    data = request.get_json()
    
    if not data or 'secret' not in data or 'code' not in data:
        return jsonify({'error': 'Відсутні обов\'язкові поля'}), 400
    
    # Перевірка коду
    import pyotp
    totp = pyotp.TOTP(data['secret'])
    
    if not totp.verify(data['code']):
        return jsonify({'error': 'Невірний код 2FA'}), 400
    
    # Підключення до БД
    conn = sqlite3.connect('secure_remote_work.db')
    cursor = conn.cursor()
    
    try:
        # Оновлення налаштувань 2FA
        cursor.execute('''
        UPDATE users
        SET two_factor_enabled = 1, two_factor_secret = ?
        WHERE id = ?
        ''', (data['secret'], user_id))
        
        # Запис у журнал аудиту
        cursor.execute('''
        INSERT INTO audit_log (user_id, action, ip_address, user_agent)
        VALUES (?, ?, ?, ?)
        ''', (user_id, 'setup_2fa', request.remote_addr, request.user_agent.string))
        
        conn.commit()
        
        app.logger.info(f'Користувач ID {user_id} налаштував 2FA')
        
        return jsonify({'message': 'Двофакторну автентифікацію успішно налаштовано'}), 200
        
    except Exception as e:
        conn.rollback()
        app.logger.error(f'Помилка при налаштуванні 2FA: {str(e)}')
        return jsonify({'error': str(e)}), 500
        
    finally:
        conn.close()

@app.route('/api/logout', methods=['POST'])
@token_required
def logout(user_id):
    # Записуємо у журнал вихід користувача
    conn = sqlite3.connect('secure_remote_work.db')
    cursor = conn.cursor()
    
    cursor.execute('''
    INSERT INTO audit_log (user_id, action, ip_address, user_agent)
    VALUES (?, ?, ?, ?)
    ''', (user_id, 'logout', request.remote_addr, request.user_agent.string))
    
    conn.commit()
    conn.close()
    
    app.logger.info(f'Користувач ID {user_id} вийшов з системи')
    
    # У реальному додатку можна додати токен у чорний список
    return jsonify({'message': 'Вихід успішний'}), 200

@app.route('/api/get-activity-log', methods=['GET'])
@token_required
def get_activity_log(user_id):
    # Підключення до БД
    conn = sqlite3.connect('secure_remote_work.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
        SELECT action, timestamp, ip_address, user_agent
        FROM audit_log
        WHERE user_id = ?
        ORDER BY timestamp DESC
        LIMIT 50
        ''', (user_id,))
        
        rows = cursor.fetchall()
        
        activity_log = []
        for row in rows:
            activity_log.append({
                'action': row[0],
                'timestamp': row[1],
                'ip_address': row[2],
                'user_agent': row[3]
            })
        
        app.logger.info(f'Користувач ID {user_id} отримав журнал активності')
        
        return jsonify(activity_log), 200
    
    except Exception as e:
        app.logger.error(f'Помилка при отриманні журналу активності: {str(e)}')
        return jsonify({'error': str(e)}), 500
    
    finally:
        conn.close()

# Запуск веб-сервера
if __name__ == '__main__':
    # В продакшн використовувати WSGI сервер, як Gunicorn
    # В продакшн використовувати HTTPS
    app.run(debug=False, host='0.0.0.0', port=5000)