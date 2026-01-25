import requests

OSV_API_URL = "https://api.osv.dev/v1/query"

def query_osv(package_name, version):
    """
    查询 OSV 漏洞
    """
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "PyPI"
        },
        "version": version
    }

    try:
        resp = requests.post(OSV_API_URL, json=payload, timeout=10)
        if resp.status_code != 200:
            return []

        data = resp.json()
        return data.get("vulns", [])
    except Exception:
        return []
