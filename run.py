from flask import Flask
from app.routes.upload import upload_bp

def create_app():
    app = Flask(__name__)
    app.config['UPLOAD_FOLDER'] = 'uploads'
    app.secret_key = 'dev-secret'

    app.register_blueprint(upload_bp)

    @app.route('/')
    def index():
        return 'Dependency Vulnerability Scanner Running! Go to /upload to upload file.'

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
