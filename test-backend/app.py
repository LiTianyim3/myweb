import os
import random
import time
from typing import Final
from flask import Flask, request, jsonify, session, g
import pymysql
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_mailman import Mail, EmailMessage
from pymysql import err as pymysql_err

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# CORS 配置
CORS(app, supports_credentials=True,
     resources={r"/api/*": {"origins": ["http://localhost:8080"]}})

# 邮件验证码设置
CODE_LIFETIME_SEC: Final[int] = 300
verification_codes: dict[str, tuple[str, float]] = {}

# 数据库配置
DB_CONFIG = {
    "host": "127.0.0.1", "port": 3306,
    "user": "root", "password": "12345678",
    "database": "myweb", "charset": "utf8mb4"
}

# 邮件服务配置
app.config.update(
    MAIL_SERVER="smtp.qq.com",
    MAIL_PORT=587,                    # 改为587端口
    MAIL_USE_TLS=True,               # 改为TLS
    MAIL_USE_SSL=False,              # 关闭SSL
    MAIL_USERNAME="2713250855@qq.com",
    MAIL_PASSWORD="sipdxibzchypdeig",
    MAIL_DEFAULT_SENDER=("勾八", "2713250855@qq.com")
)
mail = Mail(app)

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = pymysql.connect(**DB_CONFIG)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db:
        db.close()

def _send_email(to_addr: str, code: str):
    msg = EmailMessage(
        subject="密码重置验证码",
        body=f"您的验证码是：{code}，{CODE_LIFETIME_SEC//60} 分钟内有效。",
        to=[to_addr]
    )
    with mail.get_connection() as conn:
        conn.send_messages([msg])

def _code_valid(email: str, code: str) -> bool:
    tup = verification_codes.get(email)
    if not tup:
        return False
    saved, ts = tup
    if time.time() - ts > CODE_LIFETIME_SEC:
        verification_codes.pop(email, None)
        return False
    return saved == code

# 注册
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    username = data.get('username')
    email    = data.get('email')
    password = data.get('password')
    if not (username and email and password):
        return jsonify(success=False, message='字段缺失'), 400

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM users WHERE username=%s", (username,))
        if cur.fetchone():
            return jsonify(success=False, message='用户名已存在'), 400
        cur.execute("SELECT id FROM users WHERE email=%s", (email,))
        if cur.fetchone():
            return jsonify(success=False, message='邮箱已存在'), 400
        cur.execute(
            "INSERT INTO users(username,email,password_hash) VALUES(%s,%s,%s)",
            (username, email, password)
        )
    conn.commit()
    return jsonify(success=True, message='注册成功'), 201

# 登录
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    if not (username and password):
        return jsonify(success=False, message='字段缺失'), 400

    conn = get_db()
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        cur.execute(
            "SELECT id, username, email FROM users WHERE username=%s AND password_hash=%s",
            (username, password)
        )
        user = cur.fetchone()
        if not user:
            return jsonify(success=False, message='用户名或密码错误'), 401

    conn.commit()
    session['user_id'] = user['id']
    return jsonify(success=True, message='登录成功', user=user), 200

# 重置密码—发送验证码
@app.post("/api/reset-password/send-code")
def send_reset_code():
    data = request.get_json() or {}
    email = data.get("email")
    if not email:
        return jsonify(success=False, message="邮箱不能为空"), 400

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM users WHERE email=%s", (email,))
        if not cur.fetchone():
            return jsonify(success=False, message="邮箱未注册"), 404

    code = "".join(random.choices("0123456789", k=6))
    verification_codes[email] = (code, time.time())
    try:
        _send_email(email, code)
    except Exception as e:
        return jsonify(success=False, message=f"邮件发送失败: {e}"), 500

    return jsonify(success=True, message="验证码已发送，请查收"), 200

# 重置密码—确认
@app.post("/api/reset-password/confirm")
def reset_password_with_code():
    data = request.get_json() or {}
    email    = data.get("email")
    code     = data.get("code")
    new_pass = data.get("new_password")
    if not all([email, code, new_pass]):
        return jsonify(success=False, message="参数不完整"), 400
    if not _code_valid(email, code):
        return jsonify(success=False, message="验证码无效或已过期"), 400

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET password_hash=%s WHERE email=%s",
                (new_pass, email)
            )
        conn.commit()
        verification_codes.pop(email, None)
    except Exception as e:
        conn.rollback()
        return jsonify(success=False, message=f"密码重置失败: {e}"), 500

    return jsonify(success=True, message="密码已重置，请使用新密码登录"), 200

# 获取当前用户信息
@app.route('/api/me', methods=['GET'])
def get_user():
    if 'user_id' not in session:
        return jsonify(success=False, message='未登录'), 401
    conn = get_db()
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        cur.execute("SELECT id, username, email FROM users WHERE id=%s", (session['user_id'],))
        user = cur.fetchone()
    return jsonify(success=True, user=user), 200

if __name__ == '__main__':
    app.run(debug=True)