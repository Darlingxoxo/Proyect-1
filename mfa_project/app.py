from flask import Flask, render_template, request, redirect, session, url_for
import pyotp

app = Flask(__name__)
app.secret_key = "clave_super_secreta"

# Simulamos una base de datos de usuarios
USERS = {
    "abogado1": {
        "password": "clave123",
        "mfa_secret": pyotp.random_base32()
    }
}

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form["username"]
        pwd = request.form["password"]
        if user in USERS and USERS[user]["password"] == pwd:
            session["user"] = user
            return redirect(url_for("mfa"))
        return "Login incorrecto"
    return render_template("login.html")

@app.route('/mfa', methods=["GET", "POST"])
def mfa():
    user = session.get("user")
    if not user:
        return redirect(url_for("login"))
    totp = pyotp.TOTP(USERS[user]["mfa_secret"])
    if request.method == "POST":
        code = request.form["code"]
        if totp.verify(code):
            session["mfa_passed"] = True
            return redirect(url_for("dashboard"))
        return "Código incorrecto"
    return render_template("mfa.html")

@app.route('/dashboard')
def dashboard():
    if not session.get("user") or not session.get("mfa_passed"):
        return redirect(url_for("login"))
    return render_template("dashboard.html")

if __name__ == "__main__":
    app.run(debug=True)
