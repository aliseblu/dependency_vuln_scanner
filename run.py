from flask import Flask
from app.routes.upload import upload_bp

def create_app():
    app = Flask(__name__)
    app.config['UPLOAD_FOLDER'] = 'uploads'
    app.secret_key = 'dev-secret'

    app.register_blueprint(upload_bp)
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
