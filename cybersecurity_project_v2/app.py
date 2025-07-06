from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import pyotp
import qrcode
import io
import base64
import smtplib
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Email configuration
ADMIN_EMAIL = 'youremail@gmail.com'  # Put your email
ADMIN_PASSWORD = 'yourpassword'      # Gmail App Password (recommended, don't use your real password)

# User model
class User(UserMixin):
    def __init__(self, id, username, password, otp_secret):
        self.id = id
        self.username = username
        self.password = password
        self.otp_secret = otp_secret

# Load user for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return User(id=user[0], username=user[1], password=user[2], otp_secret=user[3])
    return None

# Initialize database
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            otp_secret TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        otp_secret = pyotp.random_base32()

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password, otp_secret) VALUES (?, ?, ?)",
                           (username, password, otp_secret))
            conn.commit()
            conn.close()
            return redirect(url_for('show_qr', username=username))
        except sqlite3.IntegrityError:
            conn.close()
            flash('El nombre de usuario ya existe.')
            return redirect(url_for('register'))
    return render_template('register.html')

@app.route('/show_qr/<username>')
def show_qr(username):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT otp_secret FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    if user:
        otp_secret = user[0]
        otp_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(name=username, issuer_name="Bufete JurisPana")
        qr = qrcode.make(otp_uri)
        buf = io.BytesIO()
        qr.save(buf)
        img_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
        return render_template('show_qr.html', qr_code=img_b64)
    return redirect(url_for('register'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        token = request.form['token']
        user_ip = request.remote_addr

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and password == user[2]:
            totp = pyotp.TOTP(user[3])
            if totp.verify(token):
                user_obj = User(id=user[0], username=user[1], password=user[2], otp_secret=user[3])
                login_user(user_obj)

                if user_ip != '127.0.0.1':
                    send_alert_email(username, user_ip)

                return redirect(url_for('dashboard'))
            else:
                flash('Código MFA incorrecto.')
        else:
            flash('Usuario o contraseña incorrectos.')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Email alert function
def send_alert_email(username, ip_address):
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
            smtp.starttls()
            smtp.login(ADMIN_EMAIL, ADMIN_PASSWORD)
            subject = 'Alerta de Seguridad - Bufete JurisPana'
            body = f'Se detectó un intento de inicio de sesión desde una IP no reconocida ({ip_address}) para el usuario: {username}.'
            msg = f'Subject: {subject}\n\n{body}'
            smtp.sendmail(ADMIN_EMAIL, ADMIN_EMAIL, msg)
    except Exception as e:
        print(f'Error al enviar correo: {e}')

if __name__ == '__main__':
    app.run(debug=True)
