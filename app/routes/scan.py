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
        if 'file' not in request.files:
            return render_template("upload.html", error="未上传文件")

        files = request.files.getlist('file')
        all_results = {}
        valid_file_count = 0

        for file in files:
            if file.filename == '':
                continue

            fname = file.filename.lower()
            is_valid = False
            # 模糊匹配逻辑，增加 .txt 后缀支持
            if 'requirements' in fname or 'req' in fname or fname.endswith('.txt'):
                is_valid = True
            elif 'setup.py' in fname:
                is_valid = True
            elif 'pipfile' in fname:
                is_valid = True

            if not is_valid:
                continue

            save_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file.filename)
            file.save(save_path)

            deps = parse_dependency_file(save_path, file.filename)
            print(f"DEBUG: 从文件 {file.filename} 中提取到的依赖列表: {deps}")  # 添加此行
            results = match_vulnerabilities(deps)

            all_results[file.filename] = results
            valid_file_count += 1

            history = ScanHistory(user_id=current_user.id, project_name=file.filename, report_data=json.dumps(results))
            db.session.add(history)

        db.session.commit()

        if valid_file_count == 0:
            return render_template("upload.html",
                                   error="未发现有效的配置文件。仅支持上传 .txt, .py, .toml 或 Pipfile 类型的文件。")

        return render_template("result.html", all_results=all_results)

    # GET 请求返回初始页面 (上一次缺失的就是这一句)
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
    if not scan_data: return "No data to export", 400

    all_results = json.loads(scan_data)
    lines = [
        "========================================",
        "   SCA 批量依赖组件漏洞检测报告 (合并版)  ",
        "========================================",
        f"导出时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"检测文件总数: {len(all_results)}",
        "========================================"
    ]

    for project_name, results in all_results.items():
        lines.append(f"\n>>> 目标文件: {project_name}")
        lines.append("----------------------------------------")
        for dep in results:
            lines.append(f"[-] 组件: {dep['name']} | 版本: {dep['version'] if dep['version'] else '未指定'}")
            if dep['vulnerabilities']:
                for v in dep['vulnerabilities']:
                    lines.append(f"    [!] 发现漏洞: {v['id']} (严重程度: {v['severity']})")
                    lines.append(f"        描述: {v['summary']}")
            else:
                lines.append("    [+] 状态: 安全")
        lines.append("\n")

    return Response(
        "\n".join(lines),
        mimetype="text/plain",
        headers={"Content-disposition": "attachment; filename=batch_vuln_report.txt"}
    )