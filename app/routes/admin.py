from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from app.models import db, Vulnerability, User
from app.services.osv_sync import sync_osv_to_db

admin_bp = Blueprint('admin', __name__)


@admin_bp.before_request
@login_required
def check_admin():
    # 鉴权：拦截所有非管理员请求
    if not current_user.is_admin:
        return "拒绝访问：需要管理员权限", 403


@admin_bp.route('/vulns', methods=['GET', 'POST'])
def manage_vulns():
    if request.method == 'POST':
        action = request.form.get('action')

        # ================= 漏洞库维护逻辑 =================
        if action == 'sync':
            pkg_name = request.form.get('pkg_name')
            msg = sync_osv_to_db(pkg_name)
            flash(msg, 'info')

        elif action == 'add':
            v = Vulnerability(
                id=request.form.get('vid'),
                package_name=request.form.get('pkg_name'),
                summary=request.form.get('summary'),
                severity=request.form.get('severity'),
                affected_versions='[{"introduced": "0"}]'  # 默认影响所有版本
            )
            db.session.add(v)
            db.session.commit()
            flash('手动添加漏洞成功', 'success')

        elif action == 'delete_vuln':
            vid = request.form.get('vid')
            v = Vulnerability.query.get(vid)
            if v:
                db.session.delete(v)
                db.session.commit()
                flash(f'漏洞 {vid} 已从本地库删除', 'success')

        # ================= 用户管理逻辑 =================
        elif action == 'set_admin':
            user_id = request.form.get('user_id')
            u = User.query.get(user_id)
            if u:
                u.is_admin = True
                db.session.commit()
                flash(f'已将用户 {u.username} 提升为管理员', 'success')

        elif action == 'cancel_admin':
            user_id = request.form.get('user_id')
            u = User.query.get(user_id)
            if u and u.id != current_user.id:  # 防止取消自己的权限
                u.is_admin = False
                db.session.commit()
                flash(f'已取消用户 {u.username} 的管理员权限', 'warning')
            elif u and u.id == current_user.id:
                flash('禁止操作：您不能取消自己的管理员权限！', 'danger')

        elif action == 'delete_user':
            user_id = request.form.get('user_id')
            u = User.query.get(user_id)
            if u and u.id != current_user.id:  # 防止删除自己
                # 级联删除：先删除该用户的所有检测历史，防止外键约束报错
                for scan in u.scans:
                    db.session.delete(scan)
                db.session.delete(u)
                db.session.commit()
                flash(f'已彻底删除用户 {u.username} 及其关联的检测记录', 'success')
            elif u and u.id == current_user.id:
                flash('禁止操作：您不能删除当前正在使用的账号！', 'danger')

        return redirect(url_for('admin.manage_vulns'))

    # GET 请求：同时渲染漏洞列表和用户列表
    vulns = Vulnerability.query.order_by(Vulnerability.id.desc()).limit(100).all()
    users = User.query.all()
    return render_template('admin_vuln.html', vulns=vulns, users=users)