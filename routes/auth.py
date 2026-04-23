from db import get_users_connection
from flask import request, redirect, render_template, session, flash, url_for
from server import app
from urllib.parse import urlparse, urljoin # Se añade urljoin para robustez
import bcrypt

# -----------------------------
# 1. Validación de Open Redirect (CWE-601)
# -----------------------------
def is_safe_url(target):
    # Corrección: El informe exige validar contra el netloc del host
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

# -----------------------------
# 2. Forzado de HTTPS (CWE-319) - IMPLEMENTADO
# -----------------------------
@app.before_request
def force_https():
    if not request.is_secure:
        return redirect(request.url.replace("http://", "https://"))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('dashboard'))

    next_url = request.args.get('next', url_for('dashboard'))

    # Validación de redirección (Sección 2.3)
    if not is_safe_url(next_url):
        next_url = url_for('dashboard')

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # -----------------------------
        # 3. Validación de entrada (Sección 2.1)
        # -----------------------------
        if not username.isalnum():
            flash("Invalid input format", "danger")
            return render_template('auth/login.html', next_url=next_url)

        conn = get_users_connection()

        # -----------------------------
        # 4. Corrección CWE-200 y CWE-89 (Sección 2.1)
        # -----------------------------
        # Cambiamos SELECT * por columnas específicas como pide el informe
        user = conn.execute(
            "SELECT id, username, password, role, company_id FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        conn.close()

        # -----------------------------
        # 5. Seguridad de contraseña (Sección 2.2)
        # -----------------------------
        if user:
            stored_password = user['password']
            if isinstance(stored_password, str):
                stored_password = stored_password.encode('utf-8')

            try:
                # Uso estricto de bcrypt como pide el informe
                if bcrypt.checkpw(password.encode('utf-8'), stored_password):
                    session.clear() # Limpieza de sesión previa por seguridad
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['role'] = user['role']
                    session['company_id'] = user['company_id']
                    session.permanent = True

                    return redirect(next_url)
            except (ValueError, TypeError):
                # Falla silenciosa ante hashes mal formados (MD5 antiguo)
                pass

        flash("Invalid username or password", "danger")
        return render_template('auth/login.html', next_url=next_url)

    return render_template('auth/login.html', next_url=next_url)

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))
