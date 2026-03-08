import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard-to-guess-string'
    # 请替换为你本地的 MySQL 用户名和密码
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:522615LIjin!@localhost/vuln_scanner_db?charset=utf8mb4'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 限制上传大小为16MB