from flask import request, redirect, render_template, session, flash
from server import app
from db import get_users_connection, get_data_connection, hash_password


# =========================
# LISTAR USUARIOS
# =========================
@app.route('/admin/users')
def admin_users():
    if session.get('role') != 'admin':
        return render_template('errors/403.html'), 403

    conn_u = get_users_connection()
    users = conn_u.execute(
        "SELECT id, username, role, company_id FROM users"
    ).fetchall()
    conn_u.close()

    conn_d = get_data_connection()
    companies = conn_d.execute(
        "SELECT id, name FROM companies"
    ).fetchall()
    conn_d.close()

    return render_template('admin/admin_users.html', users=users, companies=companies)


# =========================
# CREAR USUARIO (SEGURO)
# =========================
@app.route('/admin/users/add', methods=['POST'])
def add_user():
    if session.get('role') != 'admin':
        return render_template('errors/403.html'), 403

    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role')
    company_id = request.form.get('company_id') if role == 'owner' else None

    # 🔒 Validaciones
    if not username or not password or role not in ['admin', 'user', 'owner']:
        flash("Invalid input.", "danger")
        return redirect('/admin/users')

    conn = get_users_connection()

    # Evitar duplicados
    existing = conn.execute(
        "SELECT id FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if existing:
        conn.close()
        flash("Username already exists.", "danger")
        return redirect('/admin/users')

    hashed_pw = hash_password(password)

    # ✅ CONSULTA SEGURA (SIN SQLi)
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
    return redirect('/admin/users')


# =========================
# EDITAR USUARIO (SEGURO)
# =========================
@app.route('/admin/users/edit', methods=['POST'])
def edit_user():
    if session.get('role') != 'admin':
        return render_template('errors/403.html'), 403

    username = request.form.get('username')
    new_role = request.form.get('role')
    company_id = request.form.get('company_id') if new_role == 'owner' else None

    # 🔒 Validación de rol
    if new_role not in ['admin', 'user', 'owner']:
        flash("Invalid role.", "danger")
        return redirect('/admin/users')

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
    return redirect('/admin/users')


# =========================
# ELIMINAR USUARIO (SEGURO)
# =========================
@app.route('/admin/users/delete', methods=['POST'])
def delete_user():
    if session.get('role') != 'admin':
        return render_template('errors/403.html'), 403

    username = request.form.get('username')

    if not username:
        flash("Invalid user.", "danger")
        return redirect('/admin/users')

    # 🔒 Evitar que un admin se borre a sí mismo
    if username == session.get('username'):
        flash("You cannot delete your own account.", "danger")
        return redirect('/admin/users')

    conn = get_users_connection()
    conn.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()

    flash("User deleted.", "warning")
    return redirect('/admin/users')