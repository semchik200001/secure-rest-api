import os
import secrets

from flask import Flask, jsonify

from . import db
from .auth import auth_bp
from .api import api_bp


def create_app(config=None):
    app = Flask(__name__)
    app.json.ensure_ascii = False

    app.config.update(
        DATABASE=os.environ.get("DATABASE_PATH", "data.sqlite3"),
        JWT_SECRET=os.environ.get("JWT_SECRET"),
        JWT_TTL_MINUTES=int(os.environ.get("JWT_TTL_MINUTES", "30")),
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if config:
        app.config.update(config)

    if not app.config["JWT_SECRET"]:
        # Без секрета из окружения генерируем случайный: токены не переживут
        # перезапуск, но и угадать ключ подписи невозможно.
        app.config["JWT_SECRET"] = secrets.token_urlsafe(64)
        app.logger.warning("JWT_SECRET не задан, используется случайный ключ")

    db.init_app(app)
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(400)
    def bad_request(_):
        return jsonify(error="Некорректный запрос"), 400

    @app.errorhandler(404)
    def not_found(_):
        return jsonify(error="Не найдено"), 404

    @app.errorhandler(405)
    def method_not_allowed(_):
        return jsonify(error="Метод не поддерживается"), 405

    @app.errorhandler(413)
    def too_large(_):
        return jsonify(error="Слишком большой запрос"), 413

    @app.errorhandler(500)
    def internal_error(_):
        return jsonify(error="Внутренняя ошибка сервера"), 500

    return app
