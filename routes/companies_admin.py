from flask import request, redirect, render_template, session, flash, url_for
from server import app
from db import get_data_connection
from urllib.parse import urlparse, urljoin

# -----------------------------
# 1. Validación de Redirección Abierta (CWE-601 - Sección 2.3)
# -----------------------------
def is_safe_url(target):
    if not target:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

# -----------------------------
# 2. Forzado de HTTPS (CWE-319 - Sección 2.5)
# -----------------------------
@app.before_request
def force_https():
    if not request.is_secure and app.env != 'development':
        return redirect(request.url.replace("http://", "https://"))

# =========================
# AÑADIR EMPRESA (SEGURO)
# =========================
@app.route('/admin/companies/add', methods=['GET', 'POST'])
def admin_add_company():
    # Control de Acceso (CWE-284)
    if session.get('role') != 'admin':
        return render_template('errors/403.html'), 403

    if request.method == 'POST':
        company_name = request.form.get('company_name', '').strip()
        owner = request.form.get('owner', '').strip()

        # A. Validación de entrada (Sección 2.1)
        if not company_name or not owner:
            flash("All fields are required.", "danger")
            return redirect(url_for('admin_add_company'))

        # B. Sanitización Alfanumérica para el nombre de empresa (Opcional pero recomendado por Pablo)
        # Sustituimos espacios por nada para la comprobación isalnum o usamos regex
        if not company_name.replace(" ", "").isalnum():
            flash("Invalid characters in company name.", "danger")
            return redirect(url_for('admin_add_company'))

        conn = get_data_connection()

        # C. CONSULTA PARAMETRIZADA (ANTI-SQLi - CWE-89)
        conn.execute(
            "INSERT INTO companies (name, owner) VALUES (?, ?)",
            (company_name, owner)
        )

        conn.commit()
        conn.close()

        flash("Company created successfully.", "success")
        
        # Redirección Segura
        next_page = request.args.get('next')
        if not is_safe_url(next_page):
            next_page = url_for('admin_list_companies') # Asumiendo que esta es la ruta de lista
        return redirect(next_page)

    return render_template('admin/admin_companies.html')


# =========================
# ELIMINAR EMPRESA (SEGURO)
# =========================
@app.route('/admin/companies/delete', methods=['POST'])
def delete_company():
    if session.get('role') != 'admin':
        return render_template('errors/403.html'), 403

    company_id = request.form.get('company')

    # Validación de tipo de dato (CWE-20)
    if not company_id or not company_id.isdigit():
        flash("Invalid company ID.", "danger")
        return redirect(url_for('admin_list_companies'))

    conn = get_data_connection()

    # D. ELIMINACIÓN PARAMETRIZADA Y EN CASCADA MANUAL
    # Evita que queden comentarios huérfanos en la DB
    conn.execute("DELETE FROM companies WHERE id = ?", (company_id,))
    conn.execute("DELETE FROM comments WHERE company_id = ?", (company_id,))

    conn.commit()
    conn.close()

    flash("Company and associated comments deleted.", "warning")
    return redirect(url_for('admin_list_companies'))
