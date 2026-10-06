from flask import Blueprint, g, jsonify, request
from markupsafe import escape

from .auth import jwt_required
from .db import get_db

api_bp = Blueprint("api", __name__, url_prefix="/api")

TITLE_MAX_LEN = 200
BODY_MAX_LEN = 5000

# Все эндпоинты блюпринта /api защищены: before_request выполняется до любого
# обработчика и прерывает запрос с 401, если JWT не прошёл проверку.
api_bp.before_request(jwt_required)


def serialize_post(row):
    # Пользовательские данные экранируются при выводе: <script> превращается
    # в &lt;script&gt; и не исполнится, даже если клиент вставит его в HTML.
    return {
        "id": row["id"],
        "title": str(escape(row["title"])),
        "body": str(escape(row["body"])),
        "author": str(escape(row["author"])),
        "created_at": row["created_at"],
    }


@api_bp.get("/data")
def get_data():
    rows = get_db().execute(
        """
        SELECT p.id, p.title, p.body, p.created_at, u.username AS author
        FROM posts p
        JOIN users u ON u.id = p.author_id
        ORDER BY p.id DESC
        LIMIT 100
        """
    ).fetchall()
    return jsonify(user=str(escape(g.user["username"])), posts=[serialize_post(r) for r in rows])


@api_bp.post("/posts")
def create_post():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Ожидается JSON с полями title и body"), 400

    title = data.get("title")
    body = data.get("body")
    if not isinstance(title, str) or not isinstance(body, str):
        return jsonify(error="Поля title и body должны быть строками"), 400

    title, body = title.strip(), body.strip()
    if not title or len(title) > TITLE_MAX_LEN:
        return jsonify(error=f"title: от 1 до {TITLE_MAX_LEN} символов"), 400
    if not body or len(body) > BODY_MAX_LEN:
        return jsonify(error=f"body: от 1 до {BODY_MAX_LEN} символов"), 400

    db = get_db()
    cur = db.execute(
        "INSERT INTO posts (author_id, title, body) VALUES (?, ?, ?)",
        (g.user["id"], title, body),
    )
    db.commit()

    row = db.execute(
        """
        SELECT p.id, p.title, p.body, p.created_at, u.username AS author
        FROM posts p
        JOIN users u ON u.id = p.author_id
        WHERE p.id = ?
        """,
        (cur.lastrowid,),
    ).fetchone()
    return jsonify(serialize_post(row)), 201
