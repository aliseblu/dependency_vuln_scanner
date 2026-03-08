from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from app.models import db, Vulnerability
from app.services.osv_sync import sync_osv_to_db

admin_bp = Blueprint('admin', __name__)


@admin_bp.before_request
@login_required
def check_admin():
    if not current_user.is_admin:
        return "拒绝访问：需要管理员权限", 403


@admin_bp.route('/vulns', methods=['GET', 'POST'])
def manage_vulns():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'sync':
            pkg_name = request.form.get('pkg_name')
            msg = sync_osv_to_db(pkg_name)
            flash(msg)
        elif action == 'add':
            v = Vulnerability(
                id=request.form.get('vid'),
                package_name=request.form.get('pkg_name'),
                summary=request.form.get('summary'),
                severity=request.form.get('severity'),
                affected_versions='[{"introduced": "0"}]'  # 默认格式
            )
            db.session.add(v)
            db.session.commit()
            flash('手动添加漏洞成功')
        return redirect(url_for('admin.manage_vulns'))

    vulns = Vulnerability.query.limit(100).all()
    return render_template('admin_vuln.html', vulns=vulns)