import requests
import json
from app.models import db, Vulnerability


def sync_osv_to_db(package_name):
    """管理员通过调用此函数，拉取特定组件的漏洞并存入本地 MySQL"""
    url = "https://api.osv.dev/v1/query"
    payload = {"package": {"name": package_name, "ecosystem": "PyPI"}}
    try:
        # 强制使用 POST 请求，解决 405 报错问题
        resp = requests.post(url, json=payload, timeout=15)

        if resp.status_code == 200:
            vulns = resp.json().get("vulns", [])
            count = 0
            for v in vulns:
                vid = v.get('id')
                # 如果本地库已经存在该漏洞，则跳过
                if Vulnerability.query.get(vid):
                    continue

                # --- 核心修复：更健壮的严重程度提取逻辑 ---
                severity = "High"  # 默认兜底为高危

                # 尝试从 OSV 数据的 database_specific 中获取现成的文本分级
                db_specific = v.get("database_specific", {})
                if "severity" in db_specific:
                    sev_text = db_specific.get("severity", "").upper()
                    if sev_text == "CRITICAL":
                        severity = "Critical"
                    elif sev_text == "HIGH":
                        severity = "High"
                    elif sev_text in ["MODERATE", "MEDIUM"]:
                        severity = "Medium"
                    elif sev_text == "LOW":
                        severity = "Low"

                # 提取版本影响范围 (引入版本和修复版本)
                affected_ranges = []
                for affected in v.get('affected', []):
                    for ranges in affected.get('ranges', []):
                        for event in ranges.get('events', []):
                            if 'introduced' in event or 'fixed' in event:
                                affected_ranges.append(event)

                # 构建数据库模型并插入
                new_vuln = Vulnerability(
                    id=vid,
                    package_name=package_name,
                    summary=v.get('summary', '暂无详细描述'),
                    severity=severity,
                    affected_versions=json.dumps(affected_ranges)
                )
                db.session.add(new_vuln)
                count += 1

            db.session.commit()
            return f"成功同步 {count} 条漏洞记录。"
        else:
            return f"同步失败，OSV 接口拒绝了请求，状态码: {resp.status_code}"

    except Exception as e:
        return f"同步发生异常: {str(e)}"