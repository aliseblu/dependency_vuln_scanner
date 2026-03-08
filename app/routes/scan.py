from flask import Blueprint, request, render_template, redirect, url_for, Response, current_app
from flask_login import login_required, current_user
import os
import json
from datetime import datetime
from app.models import db, ScanHistory
from app.services.parser import parse_dependency_file
from app.services.matcher import match_vulnerabilities

scan_bp = Blueprint('scan', __name__)


@scan_bp.route('/', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files: return render_template("upload.html", error="未上传文件")
        file = request.files['file']

        allowed_files = ['requirements.txt', 'setup.py', 'Pipfile']
        if file.filename not in allowed_files:
            return render_template("upload.html", error="只支持 requirements.txt, setup.py, Pipfile")

        save_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file.filename)
        file.save(save_path)

        # 1. 解析提取
        deps = parse_dependency_file(save_path, file.filename)
        # 2. 本地漏洞比对
        results = match_vulnerabilities(deps)

        # 3. 记录检测历史
        history = ScanHistory(
            user_id=current_user.id,
            project_name=file.filename,
            report_data=json.dumps(results)
        )
        db.session.add(history)
        db.session.commit()

        return render_template("result.html", scan_result=results, project_name=file.filename)
    return render_template("upload.html")


@scan_bp.route('/history')
@login_required
def history():
    scans = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.scan_time.desc()).all()
    return render_template('history.html', scans=scans)


@scan_bp.route('/export_txt', methods=['POST'])
@login_required
def export_txt():
    scan_data = request.form.get('scan_data')
    project_name = request.form.get('project_name', 'Unknown')
    if not scan_data: return "No data to export", 400

    results = json.loads(scan_data)
    lines = [
        "========================================",
        "      Python 项目组件漏洞检测报告      ",
        "========================================",
        f"项目文件: {project_name}",
        f"检测时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "----------------------------------------",
        "组件清单及风险评估："
    ]

    for dep in results:
        lines.append(f"\n[-] 组件: {dep['name']} | 版本: {dep['version'] if dep['version'] else '未指定'}")
        if dep['vulnerabilities']:
            for v in dep['vulnerabilities']:
                lines.append(f"    [!] 发现漏洞: {v['id']} (严重程度: {v['severity']})")
                lines.append(f"        描述: {v['summary']}")
                lines.append(f"        修复建议: 建议参考官方通告升级至安全修复版本。")
        else:
            lines.append("    [+] 状态: 安全，未发现本地已知漏洞")

    return Response(
        "\n".join(lines),
        mimetype="text/plain",
        headers={"Content-disposition": "attachment; filename=vuln_report.txt"}
    )