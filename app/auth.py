import re
import sqlite3
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from flask import Blueprint, current_app, g, jsonify, request

from .db import get_db

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

JWT_ALGORITHM = "HS256"
AUTH_SCHEME = "Bearer"
BCRYPT_ROUNDS = 12
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
PASSWORD_MIN_LEN = 8
PASSWORD_MAX_BYTES = 72  # bcrypt учитывает только первые 72 байта

# Хэш-заглушка: проверяем пароль даже для несуществующего пользователя,
# чтобы время ответа не выдавало, есть такой логин в базе или нет.
_DUMMY_HASH = bcrypt.hashpw(b"dummy-password", bcrypt.gensalt(BCRYPT_ROUNDS))


def hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(BCRYPT_ROUNDS)).decode("ascii")


def check_password(password, password_hash):
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))


def create_token(user_id, username):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": now,
        "exp": now + timedelta(minutes=current_app.config["JWT_TTL_MINUTES"]),
    }
    return jwt.encode(payload, current_app.config["JWT_SECRET"], algorithm=JWT_ALGORITHM)


def decode_token(token):
    # Список алгоритмов задан явно: токены с alg=none или другим алгоритмом отклоняются.
    return jwt.decode(
        token,
        current_app.config["JWT_SECRET"],
        algorithms=[JWT_ALGORITHM],
        options={"require": ["sub", "iat", "exp"]},
    )


def jwt_required():
    """Middleware: проверяет заголовок Authorization: Bearer <token>.

    Возвращает ответ 401, если токена нет или он недействителен,
    иначе кладёт текущего пользователя в g.user.
    """
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme != AUTH_SCHEME or not token:
        return jsonify(error="Требуется авторизация"), 401

    try:
        payload = decode_token(token)
    except jwt.ExpiredSignatureError:
        return jsonify(error="Срок действия токена истёк"), 401
    except jwt.InvalidTokenError:
        return jsonify(error="Недействительный токен"), 401

    user = get_db().execute(
        "SELECT id, username FROM users WHERE id = ?", (payload["sub"],)
    ).fetchone()
    if user is None:
        return jsonify(error="Недействительный токен"), 401

    g.user = user
    return None


def _read_credentials():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None, None
    username = data.get("username")
    password = data.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        return None, None
    return username.strip(), password


@auth_bp.post("/register")
def register():
    username, password = _read_credentials()
    if username is None:
        return jsonify(error="Нужны поля username и password"), 400
    if not USERNAME_RE.fullmatch(username):
        return jsonify(error="Логин: 3-32 символа, латиница, цифры, _ . -"), 400
    if len(password) < PASSWORD_MIN_LEN or len(password.encode("utf-8")) > PASSWORD_MAX_BYTES:
        return jsonify(error="Пароль: от 8 символов и не длиннее 72 байт"), 400

    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, hash_password(password)),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="Пользователь уже существует"), 409

    return jsonify(id=cur.lastrowid, username=username), 201


@auth_bp.post("/login")
def login():
    username, password = _read_credentials()
    if username is None:
        return jsonify(error="Нужны поля username и password"), 400

    user = get_db().execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()

    password_ok = False
    if len(password.encode("utf-8")) <= PASSWORD_MAX_BYTES:
        if user is not None:
            password_ok = check_password(password, user["password_hash"])
        else:
            bcrypt.checkpw(password.encode("utf-8"), _DUMMY_HASH)

    if not password_ok:
        # Одинаковое сообщение для неверного логина и неверного пароля.
        return jsonify(error="Неверный логин или пароль"), 401

    token = create_token(user["id"], user["username"])
    return jsonify(
        access_token=token,
        token_type=AUTH_SCHEME,
        expires_in=current_app.config["JWT_TTL_MINUTES"] * 60,
    )
