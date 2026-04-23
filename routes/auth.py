from flask import Blueprint, request, render_template, redirect, url_for, session, flash
import bcrypt
from db import get_db
from urllib.parse import urlparse, urljoin

auth = Blueprint('auth', __name__)

# ---------------------------------------------------------
# 1. Validación de Open Redirect
# ---------------------------------------------------------
def is_safe_url(target):
    """
    Asegura que la redirección sea interna al mismo dominio.
    """
    if not target:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

# ---------------------------------------------------------
# Login
# ---------------------------------------------------------
@auth.route('/login', methods=['GET', 'POST'])
def login():
    db = get_db()
    
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    # Capturamos el destino de redirección
    next_url = request.args.get('next')

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # A. Validación Alfanumérica (Sección 2.1)
        if not username.isalnum():
            flash("Formato de usuario inválido.", "danger")
            return render_template('login.html', next=next_url)

        # B. Consulta Segura y Control de Columnas (CWE-89 / CWE-200)
        # Cambiamos SELECT * por columnas específicas
        user = db.execute(
            "SELECT id, username, password, role FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        # C. Verificación de Hash con Bcrypt (Sección 2.2)
        if user:
            stored_hash = user['password']
            if isinstance(stored_hash, str):
                stored_hash = stored_hash.encode('utf-8')

            try:
                if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                    # Login exitoso: Limpiamos sesión previa (Fijación de Sesión)
                    session.clear()
                    
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['role'] = user['role']
                    session.permanent = True

                    # D. Validación de Redirección (Sección 2.3)
                    if not is_safe_url(next_url):
                        return redirect(url_for('dashboard'))
                    
                    return redirect(next_url)
            except (ValueError, TypeError):
                # Fallo silencioso si el hash es MD5 antiguo o está corrupto
                pass

        flash("Credenciales inválidas.", "danger")
        return render_template('login.html', next=next_url)

    return render_template('login.html', next=next_url)

@auth.route('/logout')
def logout():
    session.clear()
    flash("Sesión cerrada.", "info")
    return redirect(url_for('auth.login'))
