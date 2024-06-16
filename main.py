from flask import Flask, request, render_template, jsonify, redirect, url_for, session
from flask_mysqldb import MySQL
from flask_mail import Mail, Message
from dotenv import load_dotenv
import os
import hashlib
import hmac
import random
import string
from comm_passwords import dict_comm_passwords

load_dotenv()  # Load environment variables from .env file

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')  # Load the secret key from the environment variable

# MySQL configuration
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')

# Flask-Mail configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS').lower() in ['true', '1', 't']
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

mail = Mail(app)
mysql = MySQL(app)

common_passwords = dict_comm_passwords

def generate_salt():
    return os.urandom(16).hex()

def hash_password(password, salt):
    return hmac.new(salt.encode(), password.encode(), hashlib.sha256).hexdigest()

def validate_password(password):
    if password in dict_comm_passwords:
        return False
    
    minLength = 10
    hasUppercase = any(c.isupper() for c in password)
    hasLowercase = any(c.islower() for c in password)
    hasNumbers = any(c.isdigit() for c in password)
    hasSpecialChars = any(c in "!@#$%^&*(),.?\":{}|<>" for c in password)

    return len(password) >= minLength and hasUppercase and hasLowercase and hasNumbers and hasSpecialChars

def send_email(to_email, subject, body):
    msg = Message(subject, recipients=[to_email])
    msg.body = body
    try:
        print("Attempting to send email...")
        mail.send(msg)
        print(f'Successfully sent email to {to_email}')
        return True
    except Exception as e:
        print(f'Failed to send email to {to_email}: {e}')
        return False

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        data = request.json
        email = data.get('email')

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            user_id = user[0]
            random_value = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
            hashed_value = hashlib.sha1(random_value.encode()).hexdigest()

            cursor.execute("UPDATE users SET reset_token = %s WHERE id = %s", (hashed_value, user_id))
            mysql.connection.commit()
            cursor.close()

            email_body = f'Your password reset token is: {random_value}'
            email_sent = send_email(email, 'Password Reset', email_body)
            if email_sent:
                return jsonify({'message': 'A reset token has been sent to your email.', 'redirect': url_for('enter_token')}), 200
            else:
                return jsonify({'error': 'Failed to send email. Please try again.'}), 500
        else:
            cursor.close()
            return jsonify({'error': 'Email not found.'}), 404

    return render_template('forgot_password.html')

@app.route('/enter_token', methods=['GET', 'POST'])
def enter_token():
    if request.method == 'POST':
        data = request.json
        token = data.get('token')

        hashed_token = hashlib.sha1(token.encode()).hexdigest()
        print(f"Submitted token: {token}")
        print(f"Hashed submitted token: {hashed_token}")

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT id FROM users WHERE reset_token = %s", (hashed_token,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            session['reset_user_id'] = user[0]
            return jsonify({'message': 'Token verified. Please reset your password.', 'redirect': url_for('change_password')}), 200
        else:
            return jsonify({'error': 'Invalid token.'}), 400

    return render_template('enter_token.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        data = request.json
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')

        if new_password != confirm_password:
            return jsonify({'error': 'Passwords do not match.'}), 400

        if 'reset_user_id' not in session:
            return jsonify({'error': 'Session expired. Please try again.'}), 400
        
        if not validate_password(new_password):
            return jsonify({'error': 'Password does not meet the required criteria'}), 400

        user_id = session['reset_user_id']
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT salt FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if user:
            salt = user[0]
            hashed_password = hash_password(new_password, salt)

            cursor.execute("UPDATE users SET password_hash = %s, reset_token = NULL, failed_attempts = 0, is_locked = FALSE WHERE id = %s", 
                           (hashed_password, user_id))
            mysql.connection.commit()
            cursor.close()
            session.pop('reset_user_id', None)

            return jsonify({'message': 'Password has been changed successfully.', 'redirect': url_for('login')}), 200
        else:
            cursor.close()
            return jsonify({'error': 'Invalid user.'}), 400

    return render_template('change_password.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.json

        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        if not all([username, email, password, confirm_password]):
            return jsonify({'error': 'All fields are required'}), 400

        if password != confirm_password:
            return jsonify({'error': 'Passwords do not match'}), 400
        
        if not validate_password(password):
            return jsonify({'error': 'Password does not meet the required criteria'}), 400

        salt = generate_salt()
        password_hash = hash_password(password, salt)

        cursor = mysql.connection.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, salt) VALUES (%s, %s, %s, %s)",
                (username, email, password_hash, salt)
            )
            mysql.connection.commit()
        except Exception as e:
            return jsonify({'error': str(e)}), 500
        finally:
            cursor.close()

        return jsonify({'message': 'User registered successfully', 'redirect': url_for('login')}), 201

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.json

        email = data.get('email')
        password = data.get('password')

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT id, username, password_hash, salt, failed_attempts, is_locked FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            user_id, username, stored_password_hash, salt, failed_attempts, is_locked = user
            if is_locked:
                return jsonify({'error': 'Account is locked. Please reset your password by using "Forgot Password".'}), 401

            password_hash = hash_password(password, salt)
            if hmac.compare_digest(stored_password_hash, password_hash):
                cursor = mysql.connection.cursor()
                cursor.execute("UPDATE users SET failed_attempts = 0 WHERE id = %s", (user_id,))
                mysql.connection.commit()
                cursor.close()

                session['username'] = username
                return jsonify({'message': 'Login successful', 'redirect': url_for('home')}), 200
            else:
                failed_attempts += 1
                if failed_attempts >= 3:
                    cursor = mysql.connection.cursor()
                    cursor.execute("UPDATE users SET failed_attempts = %s, is_locked = TRUE WHERE id = %s", (failed_attempts, user_id))
                    mysql.connection.commit()
                    cursor.close()
                    return jsonify({'error': 'Account is locked. Please reset your password using "Forgot Password".'}), 401
                else:
                    cursor = mysql.connection.cursor()
                    cursor.execute("UPDATE users SET failed_attempts = %s WHERE id = %s", (failed_attempts, user_id))
                    mysql.connection.commit()
                    cursor.close()
                    return jsonify({'error': 'Invalid email or password. Attempt {} of 3.'.format(failed_attempts)}), 401

        return jsonify({'error': 'Invalid email or password'}), 401

    return render_template('login.html')

@app.route('/home', methods=['GET'])
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('home.html', username=session['username'])

@app.route('/clients', methods=['POST'])
def add_client():
    data = request.json
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    cell_phone = data.get('cell_phone')
    browsing_package = data.get('browsing_package')

    cursor = mysql.connection.cursor()
    try:
        cursor.execute(
            "INSERT INTO clients (first_name, last_name, cell_phone, browsing_package) VALUES (%s, %s, %s, %s)",
            (first_name, last_name, cell_phone, browsing_package)
        )
        mysql.connection.commit()
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

    return jsonify({'message': 'Client added successfully'}), 201

@app.route('/clients', methods=['GET'])
def get_clients():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM clients")
    clients = cursor.fetchall()
    cursor.close()

    return jsonify(clients), 200

@app.route('/clients/<int:client_id>', methods=['PUT'])
def update_client(client_id):
    data = request.json
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    cell_phone = data.get('cell_phone')
    browsing_package = data.get('browsing_package')

    cursor = mysql.connection.cursor()
    try:
        cursor.execute(
            "UPDATE clients SET first_name = %s, last_name = %s, cell_phone = %s, browsing_package = %s WHERE id = %s",
            (first_name, last_name, cell_phone, browsing_package, client_id)
        )
        mysql.connection.commit()
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

    return jsonify({'message': 'Client updated successfully'}), 200

@app.route('/clients/search', methods=['GET'])
def search_clients():
    term = request.args.get('term')
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM clients WHERE first_name LIKE %s OR last_name LIKE %s OR cell_phone=%s", (f"%{term}%", f"%{term}%", f"%{term}%"))
    clients = cursor.fetchall()
    cursor.close()
    
    if clients:
        return jsonify([{'id': client[0], 'first_name': client[1], 'last_name': client[2], 'cell_phone': client[3], 'browsing_package': client[4]} for client in clients]), 200
    else:
        return jsonify({'error': 'No clients found.'}), 404

if __name__ == '__main__':
    app.run(debug=True)
