from app import db
from flask_login import UserMixin
from datetime import datetime

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    scans = db.relationship('ScanHistory', backref='user', lazy='dynamic')

class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'
    id = db.Column(db.String(64), primary_key=True) # OSV ID 或 CVE ID
    package_name = db.Column(db.String(128), index=True, nullable=False)
    summary = db.Column(db.String(255))
    severity = db.Column(db.String(32)) # Critical, High, Medium, Low
    affected_versions = db.Column(db.Text) # JSON 格式存储受影响版本区间

class ScanHistory(db.Model):
    __tablename__ = 'scan_history'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    project_name = db.Column(db.String(128))
    scan_time = db.Column(db.DateTime, default=datetime.utcnow)
    report_data = db.Column(db.Text) # 存储检测结果 JSON