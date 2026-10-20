import os, sqlite3, bcrypt, jwt, datetime
from functools import wraps
from flask import Flask, request, jsonify, g
from markupsafe import escape

app = Flask(__name__)
SECRET_KEY = "dev-secret-change-in-production-2026-secure"
DB_PATH = "app.db"

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db: db.close()

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL)""")
        # 只在空库时预置种子数据，避免每次启动重复插入
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            h = bcrypt.hashpw(b"password123", bcrypt.gensalt())
            conn.execute("INSERT INTO users (username, password_hash) VALUES (?,?)", ("alice", h))
        if conn.execute("SELECT COUNT(*) FROM posts").fetchone()[0] == 0:
            conn.execute("INSERT INTO posts (title, content) VALUES (?,?)", ("First post", "Hello <script>alert(1)</script>"))
        conn.commit()

# JWT 校验中间件
def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "missing token"}), 401
        try:
            payload = jwt.decode(auth.split(" ", 1)[1], SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "token expired"}), 401
        except jwt.InvalidTokenError as e:
            print("\n!!! JWT 报错原因:", e, "\n")
            return jsonify({"error": "invalid token"}), 401
        request.user = payload
        return f(*args, **kwargs)
    return wrapper

# 接口 1：登录 (POST /auth/login)
@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username, password = data.get("username", ""), data.get("password", "")
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    
    # SQLi防护：参数化查询（?）
    row = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if row is None or not bcrypt.checkpw(password.encode(), row["password_hash"]):
        return jsonify({"error": "invalid credentials"}), 401
    
    token = jwt.encode({
        "sub": str(row["id"]), "username": row["username"],
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    }, SECRET_KEY, algorithm="HS256")
    return jsonify({"token": token})

# 接口 2：获取数据（受保护） (GET /api/data)
@app.route("/api/data")
@token_required
def get_data():
    rows = get_db().execute("SELECT id, title FROM posts").fetchall()
    return jsonify([dict(r) for r in rows])

# 接口 3：发帖（自己设计的，受保护） (POST /api/posts)
@app.route("/api/posts", methods=["POST"])
@token_required
def create_post():
    data = request.get_json(silent=True) or {}
    title, content = data.get("title", "").strip(), data.get("content", "").strip()
    if not title or not content:
        return jsonify({"error": "title and content required"}), 400
    
    db = get_db()
    # SQLi防护：参数化查询
    db.execute("INSERT INTO posts (title, content) VALUES (?,?)", (title, content))
    db.commit()
    
    # XSS防护：使用 escape() 对返回的字符串进行 HTML 转义，防止脚本执行
    return jsonify({
        "id": db.execute("SELECT last_insert_rowid()").fetchone()[0],
        "title": str(escape(title)), 
        "content": str(escape(content))
    }), 201

if __name__ == "__main__":
    init_db()
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", port=5000)