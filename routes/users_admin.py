from flask import Blueprint, request, session, render_template, flash, redirect, url_for
from db import get_users_connection, get_data_connection
import bcrypt

user_admin = Blueprint('user_admin', __name__)

def admin_required():
    return session.get('role') == 'admin'

# -----------------------------
# LISTAR USUARIOS
# -----------------------------
@user_admin.route('/admin/users')
def admin_users():
    if not admin_required():
        return render_template('errors/403.html'), 403

    conn = get_users_connection()
    # Se especifican columnas para evitar fuga de información sensible
    users = conn.execute("SELECT id, username, role, company_id FROM users").fetchall()
    conn.close()

    return render_template('admin/admin_users.html', users=users)

# -----------------------------
# CREAR USUARIO 
# -----------------------------
@user_admin.route('/admin/users/add', methods=['POST'])
def add_user():
    if not admin_required():
        return render_template('errors/403.html'), 403

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    role = request.form.get('role')
    company_id = request.form.get('company_id') if role == 'owner' else None

    # Validaciones básicas
    if not username or not password or role not in ['admin', 'user', 'owner']:
        flash("Invalid input data.", "danger")
        return redirect(url_for('user_admin.admin_users'))

    # Validación Alfanumérica (Sección 2.1)
    if not username.isalnum():
        flash("Username must be alphanumeric.", "danger")
        return redirect(url_for('user_admin.admin_users'))

    # Hashing con Bcrypt (Sustituye MD5 inseguro)
    password_bytes = password.encode('utf-8')
    hashed_pw = bcrypt.hashpw(password_bytes, bcrypt.gensalt())

    conn = get_users_connection()

    # Evitar duplicados usando consulta parametrizada
    existing = conn.execute(
        "SELECT id FROM users WHERE username = ?", (username,)
    ).fetchone()

    if existing:
        conn.close()
        flash("Username already exists.", "danger")
        return redirect(url_for('user_admin.admin_users'))

    # Inserción Segura
    if company_id and company_id.isdigit():
        conn.execute(
            "INSERT INTO users (username, password, role, company_id) VALUES (?, ?, ?, ?)",
            (username, hashed_pw, role, company_id)
        )
    else:
        conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, hashed_pw, role)
        )

    conn.commit()
    conn.close()

    flash("User created successfully.", "success")
    return redirect(url_for('user_admin.admin_users'))

# -----------------------------
# EDITAR USUARIO
# -----------------------------
@user_admin.route('/admin/users/edit', methods=['POST'])
def edit_user():
    if not admin_required():
        return render_template('errors/403.html'), 403

    username = request.form.get('username')
    new_role = request.form.get('role')
    company_id = request.form.get('company_id') if new_role == 'owner' else None

    if new_role not in ['admin', 'user', 'owner']:
        flash("Invalid role.", "danger")
        return redirect(url_for('user_admin.admin_users'))

    conn = get_users_connection()

    if company_id and company_id.isdigit():
        conn.execute(
            "UPDATE users SET role = ?, company_id = ? WHERE username = ?",
            (new_role, company_id, username)
        )
    else:
        conn.execute(
            "UPDATE users SET role = ?, company_id = NULL WHERE username = ?",
            (new_role, username)
        )

    conn.commit()
    conn.close()

    flash("User updated.", "success")
    return redirect(url_for('user_admin.admin_users'))

# -----------------------------
# ELIMINAR USUARIO
# -----------------------------
@user_admin.route('/admin/users/delete', methods=['POST'])
def delete_user():
    if not admin_required():
        return render_template('errors/403.html'), 403

    username = request.form.get('username')

    # Seguridad: Un admin no puede borrarse a sí mismo
    if username == session.get('username'):
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for('user_admin.admin_users'))

    conn = get_users_connection()
    conn.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()

    flash("User deleted.", "warning")
    return redirect(url_for('user_admin.admin_users'))
