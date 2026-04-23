from flask import request, redirect, render_template, session, flash
from server import app
from db import get_data_connection
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)

# =========================
# LISTAR EMPRESAS
# =========================
@app.route('/admin/companies')
def admin_list_companies():
    if session.get('role') != 'admin':
        return render_template('errors/403.html'), 403

    conn = get_data_connection()
    companies = conn.execute("SELECT * FROM companies").fetchall()
    conn.close()

    return render_template('admin/admin_companies.html', companies=companies)


# =========================
# AÑADIR EMPRESA (SEGURO)
# =========================
@app.route('/admin/companies/add', methods=['GET', 'POST'])
def admin_add_company():
    if session.get('role') != 'admin':
        return render_template('errors/403.html'), 403

    if request.method == 'POST':
        company_name = request.form.get('company_name')
        owner = request.form.get('owner')

        # Validación básica
        if not company_name or not owner:
            flash("All fields are required.", "danger")
            return redirect('/admin/companies/add')

        conn = get_data_connection()

        #  CONSULTA PARAMETRIZADA (ANTI-SQLi)
        conn.execute(
            "INSERT INTO companies (name, owner) VALUES (?, ?)",
            (company_name, owner)
        )

        conn.commit()
        conn.close()

        flash("Company created successfully.", "success")
        return redirect('/admin/companies')

    return render_template('admin/admin_companies.html')


# =========================
# ELIMINAR EMPRESA (SEGURO)
# =========================
@app.route('/admin/companies/delete', methods=['POST'])
def delete_company():
    if session.get('role') != 'admin':
        return render_template('errors/403.html'), 403

    company = request.form.get('company')

    # Validar que sea número
    if not company or not company.isdigit():
        flash("Invalid company ID.", "danger")
        return redirect('/admin/companies')

    conn = get_data_connection()

    #    PARAMETRIZADO
    conn.execute("DELETE FROM companies WHERE id = ?", (company,))
    conn.execute("DELETE FROM comments WHERE company_id = ?", (company,))

    conn.commit()
    conn.close()

    flash("Company deleted.", "warning")
    return redirect('/admin/companies')