import requests
import json
from app.models import db, Vulnerability


def sync_osv_to_db(package_name):
    """管理员通过调用此函数，拉取特定组件的漏洞并存入本地 MySQL"""
    url = "https://api.osv.dev/v1/query"
    payload = {"package": {"name": package_name, "ecosystem": "PyPI"}}
    try:
        resp = requests.post(url, json=payload, timeout=10)
        if resp.status_code == 200:
            vulns = resp.json().get("vulns", [])
            count = 0
            for v in vulns:
                vid = v.get('id')
                if Vulnerability.query.get(vid): continue  # 已存在则跳过

                severity = "Low"
                if v.get('severity'):
                    score = v['severity'][0]['score']
                    if "CRITICAL" in score or float(score[-3:]) >= 9.0:
                        severity = "Critical"
                    elif float(score[-3:]) >= 7.0:
                        severity = "High"
                    elif float(score[-3:]) >= 4.0:
                        severity = "Medium"

                # 提取版本影响范围
                affected_ranges = []
                for affected in v.get('affected', []):
                    for ranges in affected.get('ranges', []):
                        for event in ranges.get('events', []):
                            if 'introduced' in event or 'fixed' in event:
                                affected_ranges.append(event)

                new_vuln = Vulnerability(
                    id=vid,
                    package_name=package_name,
                    summary=v.get('summary', 'No summary'),
                    severity=severity,
                    affected_versions=json.dumps(affected_ranges)
                )
                db.session.add(new_vuln)
                count += 1
            db.session.commit()
            return f"成功同步 {count} 条漏洞记录。"
    except Exception as e:
        return f"同步失败: {str(e)}"
    return "未发现新漏洞。"