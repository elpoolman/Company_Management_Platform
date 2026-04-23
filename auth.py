from flask import Blueprint, request, render_template, redirect, url_for, session
import bcrypt
from db import get_db

auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    db = get_db()

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        user = db.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if user:
            stored_hash = user['password']

            if isinstance(stored_hash, str):
                stored_hash = stored_hash.encode('utf-8')

            if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                session.clear()
                session['user_id'] = user['id']
                session['role'] = user['role']

                return redirect(url_for('dashboard'))

        return "Invalid credentials", 401

    return render_template('login.html')


@auth.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))