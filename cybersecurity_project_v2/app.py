import pyotp  # Import pyotp before using it
import sqlite3
import qrcode
import io
import base64
import smtplib

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

# Admin credentials
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin123'
ADMIN_OTP_SECRET = pyotp.random_base32()

# Email config
ADMIN_EMAIL = 'paul.zerpa@utp.ac.pa'
ADMIN_EMAIL_PASSWORD = '123'  # Use an App Password if you're using Gmail

# Flask app setup
app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin):
    def __init__(self, id, username, password, otp_secret):
        self.id = id
        self.username = username
        self.password = password
        self.otp_secret = otp_secret

# Load user from database
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

# Init DB
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

        if user:
            user_id, db_username, db_password, otp_secret = user
            totp = pyotp.TOTP(otp_secret)

            if password == db_password and totp.verify(token):
                user_obj = User(id=user_id, username=db_username, password=db_password, otp_secret=otp_secret)
                login_user(user_obj)

                # Send email alert (you could add IP tracking to avoid spam)
                send_alert_email(username, user_ip)

                if username == ADMIN_USERNAME:
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('dashboard'))
            else:
                flash("Credenciales o token incorrectos.")
        else:
            flash("Usuario no encontrado.")

        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.username != ADMIN_USERNAME:
        return redirect(url_for('dashboard'))

    return '''
    <h2>Bienvenido Administrador</h2>
    <p>Este es el panel exclusivo del administrador.</p>
    <a href="/logout">Cerrar Sesión</a>
    '''

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Email alert
def send_alert_email(username, ip_address):
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
            smtp.starttls()
            smtp.login(ADMIN_EMAIL, ADMIN_EMAIL_PASSWORD)
            subject = 'Alerta de Seguridad - Bufete JurisPana'
            body = f'Se detectó un intento de inicio de sesión desde una IP no reconocida ({ip_address}) para el usuario: {username}.'
            msg = f'Subject: {subject}\n\n{body}'
            smtp.sendmail(ADMIN_EMAIL, ADMIN_EMAIL, msg)
    except Exception as e:
        print(f'Error al enviar correo: {e}')

if __name__ == '__main__':
    app.run(debug=True)


