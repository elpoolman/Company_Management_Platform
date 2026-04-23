import sqlite3
import os
import bcrypt

DB_DIR = os.path.join(os.path.dirname(__file__), '..', 'db')
USERS_DB = os.path.join(DB_DIR, 'users.db')
DATA_DB = os.path.join(DB_DIR, 'data.db')


#  Hash seguro de contraseñas (bcrypt)
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def ensure_users_db():
    ensure_data_db()

    if not os.path.exists(USERS_DB):
        os.makedirs(DB_DIR, exist_ok=True)
        conn = sqlite3.connect(USERS_DB)
        c = conn.cursor()

        c.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT,
            company_id INTEGER
        )
        """)

        #  Contraseñas seguras con bcrypt
        users = [
            ('alice', hash_password('password1'), 'user', None),
            ('bob', hash_password('password2'), 'owner', 1),
            ('admin', hash_password('admin123'), 'admin', None)
        ]

        c.executemany(
            "INSERT INTO users (username, password, role, company_id) VALUES (?, ?, ?, ?)",
            users
        )

        conn.commit()
        conn.close()


def ensure_data_db():
    if not os.path.exists(DATA_DB):
        os.makedirs(DB_DIR, exist_ok=True)
        conn = sqlite3.connect(DATA_DB)
        c = conn.cursor()

        c.execute("""
        CREATE TABLE companies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            description TEXT,
            owner TEXT
        )
        """)

        c.execute("""
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER,
            user TEXT,
            comment TEXT
        )
        """)

        # Datos iniciales
        c.execute(
            "INSERT INTO companies (name, description, owner) VALUES (?, ?, ?)",
            ('Insegura Corp', 'A very insecure company.', 'bob')
        )

        comments = [
            (1, 'alice', 'This company is extremely insecure!'),
            (1, 'admin', 'I agree, there are many vulnerabilities here.'),
            (1, 'bob', 'We need to improve security immediately.'),

            (2, 'alice', 'Flameera is doing great with security!'),
            (2, 'admin', 'Top-tier measures! I recommend this company for security.'),
            (2, 'bob', 'Our security is state-of-the-art! Flameera is the future.')
        ]

        c.executemany(
            "INSERT INTO comments (company_id, user, comment) VALUES (?, ?, ?)",
            comments
        )

        c.execute(
            "INSERT INTO companies (name, description, owner) VALUES (?, ?, ?)",
            ('Flameera', 'A cutting-edge company with top security measures.', 'bob')
        )

        conn.commit()
        conn.close()


def get_users_connection():
    ensure_users_db()
    conn = sqlite3.connect(USERS_DB)
    conn.row_factory = sqlite3.Row
    return conn


def get_data_connection():
    ensure_data_db()
    conn = sqlite3.connect(DATA_DB)
    conn.row_factory = sqlite3.Row
    return conn