from db import get_users_connection
from flask import request, redirect, render_template, session, flash, url_for
from server import app
from urllib.parse import urlparse
import bcrypt


# -----------------------------
# Validación de Open Redirect
# -----------------------------
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(target)
    return test_url.netloc == "" or test_url.netloc == ref_url.netloc


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('dashboard'))

    next_url = request.args.get('next', url_for('dashboard'))

    # Validación de redirección
    if not is_safe_url(next_url):
        next_url = url_for('dashboard')

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_users_connection()

        # SQL Injection FIX (correcto)
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        conn.close()

        # -----------------------------
        # Seguridad de contraseña
        # -----------------------------
        if user:

            # Si aún hay hashes antiguos (compatibilidad con MD5 del sistema)
            stored_password = user['password'].encode()

            try:
                password_valid = bcrypt.checkpw(password.encode(), stored_password)
            except ValueError:
                # fallback por si hay hashes antiguos (MD5 en migración)
                password_valid = False

            if password_valid:
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                session['company_id'] = user['company_id']
                session.permanent = True

                return redirect(next_url)

        flash("Invalid username or password", "danger")
        return render_template('auth/login.html', next_url=next_url)

    return render_template('auth/login.html', next_url=next_url)


@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))
#cambio commit