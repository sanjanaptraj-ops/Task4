from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import bcrypt

app = Flask(__name__)
app.secret_key = "secure_secret_key"

# Create Database
def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password BLOB NOT NULL
        )
    """)

    conn.commit()
    conn.close()

init_db()

@app.route("/")
def home():
    return redirect(url_for("login"))

# Registration
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if len(username) < 3:
            flash("Username must be at least 3 characters")
            return redirect(url_for("register"))

        if len(password) < 6:
            flash("Password must be at least 6 characters")
            return redirect(url_for("register"))

        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        )

        try:
            conn = sqlite3.connect("database.db")
            cursor = conn.cursor()

            cursor.execute(
                "INSERT INTO users(username,password) VALUES (?,?)",
                (username, hashed_password)
            )

            conn.commit()
            conn.close()

            flash("Registration Successful")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("Username already exists")

    return render_template("register.html")

# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        )

        user = cursor.fetchone()
        conn.close()

        if user and bcrypt.checkpw(
            password.encode("utf-8"),
            user[2]
        ):
            session["user"] = username
            return redirect(url_for("dashboard"))

        flash("Invalid Username or Password")

    return render_template("login.html")

# Dashboard
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        username=session["user"]
    )

# Logout
@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Logged Out Successfully")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
