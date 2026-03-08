from app import create_app
from app.models import db

app = create_app()

if __name__ == '__main__':
    # 启动时自动创建所有数据库表
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)