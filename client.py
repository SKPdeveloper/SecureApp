# Функція для входу
def login(username, password):
    try:
        response = requests.post(
            f"{API_URL}/login",
            json={"username": username, "password": password},
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            data = response.json()
            st.session_state.token = data['token']
            st.session_state.user_id = data['user_id']
            st.session_state.username = username
            st.session_state.last_activity = datetime.now()
            # Встановлюємо час закінчення сесії (15 хвилин)
            st.session_state.session_expiry = datetime.now() + timedelta(minutes=15)
            
            # Виведення деталей токена для відлагодження
            print(f"Отримано токен: {st.session_state.token[:15]}...")
            print(f"User ID: {st.session_state.user_id}")
            
            # Тест токена - виконуємо запит до API
            print("Тестуємо токен з заголовками:")
            headers = get_auth_headers()
            print(f"Headers: {headers}")
            
            return True
        else:
            error_msg = response.json().get('error', 'Невідома помилка при вході')
            st.error(f"Помилка: {error_msg}")
            return False
            
    except Exception as e:
        st.error(f"Помилка підключення до сервера: {str(e)}")
        return False# client.py
import streamlit as st
import requests
import json
import os
import re
from datetime import datetime, timedelta
import time
import pyotp
import qrcode
from io import BytesIO

# URL API сервера
API_URL = "http://localhost:5000/api"

# Налаштування стану сесії
if 'token' not in st.session_state:
    st.session_state.token = None
if 'user_id' not in st.session_state:
    st.session_state.user_id = None
if 'username' not in st.session_state:
    st.session_state.username = None
if 'last_activity' not in st.session_state:
    st.session_state.last_activity = datetime.now()
if 'session_expiry' not in st.session_state:
    st.session_state.session_expiry = None

# Функція для валідації номера телефону
def validate_phone_number(phone):
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
    # Дозволяємо лише літери, пробіли та деякі спеціальні символи (апостроф, дефіс)
    if re.match(r'^[A-Za-zА-Яа-яІіЇїЄєҐґ\s\'\-]+$', name):
        return True
    return False

# Функція для перевірки надійності пароля
def validate_password(password):
    strength = 0
    feedback = []
    
    # Мінімум 8 символів
    if len(password) >= 8:
        strength += 1
    else:
        feedback.append("Пароль повинен містити не менше 8 символів")
    
    # Наявність цифри
    if any(c.isdigit() for c in password):
        strength += 1
    else:
        feedback.append("Пароль повинен містити хоча б одну цифру")
    
    # Наявність великої літери
    if any(c.isupper() for c in password):
        strength += 1
    else:
        feedback.append("Пароль повинен містити хоча б одну велику літеру")
    
    # Наявність спеціального символу
    if any(c in "!@#$%^&*()-_=+[]{}|;:'\",.<>/?`~" for c in password):
        strength += 1
    else:
        feedback.append("Пароль повинен містити хоча б один спеціальний символ")
    
    return strength, feedback

# Функція для перевірки часу неактивності та автоматичного виходу
def check_session():
    if st.session_state.token and st.session_state.session_expiry:
        current_time = datetime.now()
        
        # Відображення залишку часу сесії
        time_left = st.session_state.session_expiry - current_time
        minutes_left = int(time_left.total_seconds() // 60)
        seconds_left = int(time_left.total_seconds() % 60)
        
        # Якщо час сесії закінчився
        if time_left.total_seconds() <= 0:
            st.session_state.token = None
            st.session_state.user_id = None
            st.session_state.username = None
            st.session_state.session_expiry = None
            st.warning("Сесія закінчилася через неактивність. Будь ласка, увійдіть знову.")
            time.sleep(1)
            st.experimental_rerun()
        
        # Оновлення часу сесії при взаємодії з додатком
        if current_time - st.session_state.last_activity > timedelta(seconds=5):  # перевіряємо кожні 5 секунд
            st.session_state.last_activity = current_time
            
        return f"Сесія завершиться через: {minutes_left:02d}:{seconds_left:02d}"
    
    return None

# Функція для створення заголовків з токеном
def get_auth_headers():
    if not st.session_state.token:
        return {"Content-Type": "application/json"}
    
    # Додаємо логування на стороні клієнта
    token_part = st.session_state.token[:10] + "..." if st.session_state.token else "None"
    print(f"Використовуємо токен: {token_part}")
    
    # Перевіряємо наявність пробілів у токені
    if ' ' in st.session_state.token:
        print(f"УВАГА! Токен містить пробіли")
        # Прибираємо зайві пробіли
        token = st.session_state.token.replace(' ', '')
    else:
        token = st.session_state.token
    
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

# Функція для реєстрації
def register(username, password, email, first_name, last_name):
    try:
        response = requests.post(
            f"{API_URL}/register",
            json={
                "username": username, 
                "password": password, 
                "email": email,
                "first_name": first_name,
                "last_name": last_name
            },
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 201:
            st.success("Реєстрація успішна! Тепер ви можете увійти.")
            return True
        else:
            error_msg = response.json().get('error', 'Невідома помилка при реєстрації')
            st.error(f"Помилка: {error_msg}")
            return False
            
    except Exception as e:
        st.error(f"Помилка підключення до сервера: {str(e)}")
        return False



# Функція для виходу
def logout():
    if st.session_state.token:
        try:
            response = requests.post(
                f"{API_URL}/logout",
                headers=get_auth_headers()
            )
            
            # Очищення стану сесії незалежно від відповіді сервера
            st.session_state.token = None
            st.session_state.user_id = None
            st.session_state.username = None
            st.session_state.session_expiry = None
            
            if response.status_code == 200:
                st.success("Ви успішно вийшли з системи.")
            else:
                st.warning("Вихід з системи, але виникла помилка на сервері.")
                
        except Exception as e:
            st.warning(f"Локальний вихід з системи. Помилка з'єднання з сервером: {str(e)}")
            st.session_state.token = None
            st.session_state.user_id = None
            st.session_state.username = None
            st.session_state.session_expiry = None

# Функція для додавання персональних даних
def add_personal_data(data_type, data_value):
    try:
        response = requests.post(
            f"{API_URL}/personal-data",
            json={"data_type": data_type, "data_value": data_value},
            headers=get_auth_headers()
        )
        
        if response.status_code == 201:
            st.success("Персональні дані успішно додано.")
            return True
        elif response.status_code == 401:
            st.error("Помилка авторизації. Будь ласка, увійдіть знову.")
            time.sleep(2)
            logout()
            st.rerun()
        else:
            try:
                error_msg = response.json().get('error', 'Невідома помилка при додаванні даних')
            except:
                error_msg = f"Код відповіді: {response.status_code}"
            st.error(f"Помилка: {error_msg}")
            return False
            
    except Exception as e:
        st.error(f"Помилка підключення до сервера: {str(e)}")
        return False

# Функція для отримання персональних даних
def get_personal_data():
    try:
        # Виведемо заголовки для відлагодження
        headers = get_auth_headers()
        print(f"Headers in get_personal_data: {headers}")
        
        response = requests.get(
            f"{API_URL}/personal-data",
            headers=headers
        )
        
        print(f"Response status: {response.status_code}")
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401:
            st.error("Помилка авторизації. Будь ласка, увійдіть знову.")
            time.sleep(2)
            logout()
            st.rerun()
        else:
            try:
                error_msg = response.json().get('error', 'Невідома помилка при отриманні даних')
            except:
                error_msg = f"Код відповіді: {response.status_code}"
            st.error(f"Помилка: {error_msg}")
            return []
            
    except Exception as e:
        st.error(f"Помилка підключення до сервера: {str(e)}")
        return []

# Функція для оновлення персональних даних
def update_personal_data(data_id, data_value):
    try:
        response = requests.put(
            f"{API_URL}/personal-data/{data_id}",
            json={"data_value": data_value},
            headers=get_auth_headers()
        )
        
        if response.status_code == 200:
            st.success("Персональні дані успішно оновлено.")
            return True
        elif response.status_code == 401:
            st.error("Помилка авторизації. Будь ласка, увійдіть знову.")
            time.sleep(2)
            logout()
            st.rerun()
        else:
            try:
                error_msg = response.json().get('error', 'Невідома помилка при оновленні даних')
            except:
                error_msg = f"Код відповіді: {response.status_code}"
            st.error(f"Помилка: {error_msg}")
            return False
            
    except Exception as e:
        st.error(f"Помилка підключення до сервера: {str(e)}")
        return False

# Функція для видалення персональних даних
def delete_personal_data(data_id):
    try:
        response = requests.delete(
            f"{API_URL}/personal-data/{data_id}",
            headers=get_auth_headers()
        )
        
        if response.status_code == 200:
            st.success("Персональні дані успішно видалено.")
            return True
        elif response.status_code == 401:
            st.error("Помилка авторизації. Будь ласка, увійдіть знову.")
            time.sleep(2)
            logout()
            st.rerun()
        else:
            try:
                error_msg = response.json().get('error', 'Невідома помилка при видаленні даних')
            except:
                error_msg = f"Код відповіді: {response.status_code}"
            st.error(f"Помилка: {error_msg}")
            return False
            
    except Exception as e:
        st.error(f"Помилка підключення до сервера: {str(e)}")
        return False

# Функція для зміни пароля
def change_password(current_password, new_password):
    try:
        response = requests.post(
            f"{API_URL}/change-password",
            json={"current_password": current_password, "new_password": new_password},
            headers=get_auth_headers()
        )
        
        if response.status_code == 200:
            st.success("Пароль успішно змінено.")
            return True
        else:
            error_msg = response.json().get('error', 'Невідома помилка при зміні пароля')
            st.error(f"Помилка: {error_msg}")
            return False
            
    except Exception as e:
        st.error(f"Помилка підключення до сервера: {str(e)}")
        return False

# Функція для генерації QR-коду для двофакторної автентифікації
def generate_2fa_qrcode(username):
    # Генерація секретного ключа
    secret = pyotp.random_base32()
    
    # Створення URL для QR-коду
    totp = pyotp.TOTP(secret)
    provisioning_url = totp.provisioning_uri(name=username, issuer_name="SecureRemoteWorkApp")
    
    # Генерація QR-коду
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(provisioning_url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer)
    buffer.seek(0)
    
    return secret, buffer

# Функція для налаштування двофакторної автентифікації
def setup_2fa(secret, code):
    try:
        response = requests.post(
            f"{API_URL}/setup-2fa",
            json={"secret": secret, "code": code},
            headers=get_auth_headers()
        )
        
        if response.status_code == 200:
            st.success("Двофакторну автентифікацію успішно налаштовано.")
            return True
        else:
            error_msg = response.json().get('error', 'Невідома помилка при налаштуванні 2FA')
            st.error(f"Помилка: {error_msg}")
            return False
            
    except Exception as e:
        st.error(f"Помилка підключення до сервера: {str(e)}")
        return False

# Функція для отримання журналу активності
def get_activity_log():
    try:
        response = requests.get(
            f"{API_URL}/get-activity-log",
            headers=get_auth_headers()
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            error_msg = response.json().get('error', 'Невідома помилка при отриманні журналу активності')
            st.error(f"Помилка: {error_msg}")
            return []
            
    except Exception as e:
        st.error(f"Помилка підключення до сервера: {str(e)}")
        return []

# Виведення токена для debug
def debug_token():
    if st.session_state.token:
        st.sidebar.text_area("Поточний токен", st.session_state.token, height=100)
        headers = get_auth_headers()
        st.sidebar.text_area("Заголовки", str(headers), height=100)
    else:
        st.sidebar.error("Токен відсутній")

# Головний заголовок програми
st.title("Захищена система для віддаленої роботи")

# Бічна панель для навігації
menu = st.sidebar.selectbox(
    "Меню",
    ["Вхід", "Реєстрація", "Особистий кабінет", "Персональні дані", "Безпека"] 
    if not st.session_state.token else 
    ["Особистий кабінет", "Персональні дані", "Безпека", "Вихід"]
)

# Відображення таймера сесії
if st.session_state.token:
    session_info = check_session()
    if session_info:
        st.sidebar.info(session_info)
    
    # Відображення інформації про токен
    with st.sidebar.expander("Інформація про авторизацію"):
        st.text(f"Токен: {st.session_state.token[:10]}...")
        st.text(f"ID користувача: {st.session_state.user_id}")
        st.text(f"Заголовки: {get_auth_headers()}")
        
        if st.button("Тест токена"):
            try:
                response = requests.get(f"{API_URL}/personal-data", headers=get_auth_headers())
                st.text(f"Код відповіді: {response.status_code}")
                st.text(f"Заголовки запиту: {get_auth_headers()}")
                if response.status_code == 200:
                    st.success("Токен працює!")
                else:
                    st.error(f"Помилка авторизації: {response.status_code}")
            except Exception as e:
                st.error(f"Помилка запиту: {str(e)}")

# Відображення різних сторінок в залежності від вибору меню
if menu == "Вхід" and not st.session_state.token:
    st.header("Вхід до системи")
    
    with st.form("login_form"):
        username = st.text_input("Ім'я користувача")
        password = st.text_input("Пароль", type="password")
        submit_button = st.form_submit_button("Увійти")
        
        if submit_button:
            if username and password:
                if login(username, password):
                    st.success("Вхід успішний!")
                    time.sleep(1)
                    st.rerun()
            else:
                st.error("Будь ласка, заповніть всі поля.")

elif menu == "Реєстрація" and not st.session_state.token:
    st.header("Реєстрація в системі")
    
    with st.form("register_form"):
        first_name = st.text_input("Ім'я")
        last_name = st.text_input("Прізвище")
        username = st.text_input("Логін")
        email = st.text_input("Email")
        password = st.text_input("Пароль", type="password")
        password_confirm = st.text_input("Підтвердження пароля", type="password")
        
        # Валідація даних
        validation_passed = True
        
        # Перевірка імені та прізвища
        if first_name and not validate_name(first_name):
            st.error("Ім'я може містити лише літери, пробіли, апостроф та дефіс.")
            validation_passed = False
            
        if last_name and not validate_name(last_name):
            st.error("Прізвище може містити лише літери, пробіли, апостроф та дефіс.")
            validation_passed = False
        
        # Перевірка надійності пароля
        if password:
            strength, feedback = validate_password(password)
            
            if strength == 0:
                st.error("Дуже слабкий пароль: " + ", ".join(feedback))
                validation_passed = False
            elif strength == 1:
                st.error("Слабкий пароль: " + ", ".join(feedback))
                validation_passed = False
            elif strength == 2:
                st.warning("Середній пароль: " + ", ".join(feedback))
                validation_passed = False
            elif strength == 3:
                st.info("Хороший пароль: " + ", ".join(feedback))
            elif strength == 4:
                st.success("Сильний пароль")
        
        submit_button = st.form_submit_button("Зареєструватися")
        
        if submit_button:
            if first_name and last_name and username and email and password and password_confirm:
                if password != password_confirm:
                    st.error("Паролі не співпадають.")
                elif "@" not in email or "." not in email:
                    st.error("Введіть дійсний email.")
                elif validation_passed:
                    if register(username, password, email, first_name, last_name):
                        st.info("Тепер ви можете увійти до системи.")
            else:
                st.error("Будь ласка, заповніть всі поля.")

elif menu == "Особистий кабінет" and st.session_state.token:
    st.header(f"Вітаємо, {st.session_state.username}!")
    
    st.info("""
    Це захищена система для віддаленої роботи. 
    Ваші дані захищені сучасними методами шифрування та контролю доступу.
    """)
    
    st.subheader("Рекомендації з безпеки:")
    st.markdown("""
    * Регулярно змінюйте пароль
    * Не використовуйте один і той самий пароль на різних сервісах
    * Не передавайте свої облікові дані третім особам
    * Налаштуйте двофакторну автентифікацію у розділі "Безпека"
    * Завжди виходьте з системи після завершення роботи
    """)
    
    # Відображення часу останньої активності
    st.text(f"Остання активність: {st.session_state.last_activity.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Журнал активності
    st.subheader("Останні дії:")
    activity_log = get_activity_log()
    
    if activity_log:
        for i, activity in enumerate(activity_log[:5]):  # Показуємо лише 5 останніх дій
            st.text(f"{activity['timestamp']} - {activity['action']} - IP: {activity['ip_address']}")
    else:
        st.info("Журнал активності порожній.")

elif menu == "Персональні дані" and st.session_state.token:
    st.header("Мої персональні дані")
    
    # Тест підключення
    test_connection = st.checkbox("Перевірити підключення")
    if test_connection:
        try:
            test_response = requests.get(f"{API_URL}/personal-data", headers=get_auth_headers())
            st.write(f"Код відповіді: {test_response.status_code}")
            st.write(f"Токен: {st.session_state.token[:10]}...")
            st.write(f"Заголовки запиту: {get_auth_headers()}")
            try:
                st.write(f"Відповідь: {test_response.json()}")
            except:
                st.write(f"Відповідь не в форматі JSON: {test_response.text}")
        except Exception as e:
            st.error(f"Помилка підключення: {str(e)}")
    
    # Форма для додавання персональних даних
    with st.expander("Додати нові дані", expanded=True):
        with st.form("personal_data_form"):
            data_type = st.selectbox(
                "Тип даних", 
                ["Номер телефону", "Ім'я", "Прізвище", "Адреса", "Паспортні дані", "ІПН", "Банківські реквізити", "Інше"]
            )
            data_value = st.text_input("Значення")
            submit_button = st.form_submit_button("Зберегти")
            
            if submit_button:
                if data_type and data_value:
                    # Валідація даних в залежності від типу
                    if data_type == "Номер телефону":
                        is_valid, validated_phone = validate_phone_number(data_value)
                        if not is_valid:
                            st.error("Невірний формат номера телефону. Використовуйте формат +38XXXXXXXXXX або 0XXXXXXXXX.")
                        else:
                            add_personal_data(data_type, validated_phone)
                            st.rerun()
                    elif data_type in ["Ім'я", "Прізвище"]:
                        if not validate_name(data_value):
                            st.error(f"Невірний формат {data_type.lower()}. Використовуйте лише літери.")
                        else:
                            add_personal_data(data_type, data_value)
                            st.rerun()
                    else:
                        add_personal_data(data_type, data_value)
                        st.rerun()
                else:
                    st.error("Будь ласка, заповніть всі поля.")
    
    # Відображення існуючих персональних даних
    st.subheader("Мої збережені дані")
    personal_data = get_personal_data()
    
    if personal_data:
        for item in personal_data:
            with st.expander(f"{item['data_type']} (додано: {item['created_at']})"):
                current_value = item['data_value']
                st.text(f"Поточне значення: {current_value}")
                st.text(f"Оновлено: {item['updated_at']}")
                
                # Редагування даних
                new_value = st.text_input(f"Нове значення для {item['data_type']}", key=f"edit_{item['id']}")
                
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("Оновити", key=f"update_{item['id']}"):
                        if new_value:
                            # Валідація даних в залежності від типу
                            if item['data_type'] == "Номер телефону":
                                is_valid, validated_phone = validate_phone_number(new_value)
                                if not is_valid:
                                    st.error("Невірний формат номера телефону. Використовуйте формат +38XXXXXXXXXX або 0XXXXXXXXX.")
                                else:
                                    update_personal_data(item['id'], validated_phone)
                                    st.rerun()
                            elif item['data_type'] in ["Ім'я", "Прізвище"]:
                                if not validate_name(new_value):
                                    st.error(f"Невірний формат {item['data_type'].lower()}. Використовуйте лише літери.")
                                else:
                                    update_personal_data(item['id'], new_value)
                                    st.rerun()
                            else:
                                update_personal_data(item['id'], new_value)
                                st.rerun()
                
                with col2:
                    if st.button("Видалити", key=f"delete_{item['id']}"):
                        delete_personal_data(item['id'])
                        st.rerun()
    else:
        st.info("У вас поки немає збережених персональних даних.")

elif menu == "Безпека" and st.session_state.token:
    st.header("Налаштування безпеки")
    
    # Зміна пароля
    st.subheader("Зміна пароля")
    with st.form("change_password_form"):
        current_password = st.text_input("Поточний пароль", type="password")
        new_password = st.text_input("Новий пароль", type="password")
        confirm_password = st.text_input("Підтвердження нового пароля", type="password")
        
        # Перевірка надійності пароля
        if new_password:
            strength, feedback = validate_password(new_password)
            
            if strength < 3:
                st.error("Пароль недостатньо надійний: " + ", ".join(feedback))
                is_strong_password = False
            else:
                is_strong_password = True
                if strength == 3:
                    st.info("Хороший пароль")
                elif strength == 4:
                    st.success("Сильний пароль")
        
        submit_button = st.form_submit_button("Змінити пароль")
        
        if submit_button:
            if not current_password or not new_password or not confirm_password:
                st.error("Будь ласка, заповніть всі поля.")
            elif new_password != confirm_password:
                st.error("Новий пароль та підтвердження не співпадають.")
            elif not is_strong_password:
                st.error("Новий пароль недостатньо надійний. Підвищіть його надійність.")
            else:
                if change_password(current_password, new_password):
                    st.success("Пароль успішно змінено!")
    
    # Налаштування двофакторної автентифікації
    st.subheader("Двофакторна автентифікація")
    
    if st.button("Налаштувати двофакторну автентифікацію"):
        secret, qr_code_img = generate_2fa_qrcode(st.session_state.username)
        
        st.image(qr_code_img, caption="QR-код для Google Authenticator або іншого додатку для 2FA")
        st.info(f"Секретний ключ: {secret}")
        st.markdown("""
        1. Відскануйте QR-код за допомогою Google Authenticator або іншого додатку для двофакторної автентифікації
        2. Збережіть секретний ключ у надійному місці на випадок втрати доступу до додатку
        3. Введіть код із додатку для підтвердження налаштування
        """)
        
        verification_code = st.text_input("Введіть код із додатку для 2FA", key="2fa_setup_code")
        if st.button("Підтвердити"):
            if verification_code:
                setup_2fa(secret, verification_code)
            else:
                st.error("Будь ласка, введіть код із додатку.")
    
    # Журнал активності
    st.subheader("Журнал активності")
    st.info("Тут відображаються останні дії з вашим обліковим записом для виявлення підозрілої активності.")
    
    activity_log = get_activity_log()
    
    if activity_log:
        for activity in activity_log:
            st.text(f"{activity['timestamp']} - {activity['action']} - IP: {activity['ip_address']} - {activity['user_agent']}")
    else:
        st.info("Журнал активності порожній.")

elif menu == "Вихід" and st.session_state.token:
    st.header("Вихід із системи")
    
    if st.button("Підтвердити вихід"):
        logout()
        st.rerun()
    
    st.warning("Будь ласка, завжди виходьте з системи після завершення роботи для захисту своїх даних.")

else:
    # Якщо користувач не авторизований і намагається отримати доступ до захищених сторінок
    if not st.session_state.token and menu in ["Особистий кабінет", "Персональні дані", "Безпека", "Вихід"]:
        st.warning("Для доступу до цієї сторінки необхідно увійти до системи.")
        st.rerun()

# Інформація про захист даних у нижньому колонтитулі
st.markdown("---")
st.markdown("""
<small>© 2025 Захищена система для віддаленої роботи. Всі дані шифруються та зберігаються відповідно до вимог законодавства про захист персональних даних.</small>
""", unsafe_allow_html=True)