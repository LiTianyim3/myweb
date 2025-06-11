from flask import Flask, request, jsonify, session, g
import pymysql
import pymysql.cursors
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_mailman import Mail, EmailMessage
import random, time
from typing import Final


app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
CORS(app, supports_credentials=True,
     resources={r"/api/*": {"origins": ["http://localhost:8080"]}})
CODE_LIFETIME_SEC: Final[int] = 300
verification_codes: dict[str, tuple[str, float]] = {}

DB_CONFIG = {
    "host": "127.0.0.1", "port": 3306,
    "user": "root", "password": "12345678",
    "database": "myweb", "charset": "utf8mb4"
}

app.config.update(
    MAIL_SERVER="smtp.qq.com",
    MAIL_PORT=465,
    MAIL_USE_SSL=True,
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

def _send_email(to_addr: str, code: str):
    """发送邮件验证码"""
    msg = EmailMessage(
        subject="密码重置验证码",
        body=f"您的验证码是：{code}，{CODE_LIFETIME_SEC//60}分钟内有效。",
        to=[to_addr]
    )
    with mail.get_connection() as conn:
        conn.send_messages([msg])

def _code_valid(email: str, code: str) -> bool:
    """校验缓存中的验证码及有效期"""
    tup = verification_codes.get(email)
    if not tup: return False
    saved, ts = tup
    if time.time() - ts > CODE_LIFETIME_SEC:
        verification_codes.pop(email, None)
        return False
    return saved == code

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db:
        db.close()


# 注册
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')  # 明文密码

    if not (username and email and password):
        return jsonify(success=False, message='字段缺失'), 400

    conn = get_db()
    with conn.cursor() as cursor:
        # 检查用户名／邮箱唯一
        cursor.execute("SELECT id FROM users WHERE username=%s", (username,))
        if cursor.fetchone():
            return jsonify(success=False, message='用户名已存在'), 400
        cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
        if cursor.fetchone():
            return jsonify(success=False, message='邮箱已存在'), 400

        # 插入用户，直接存储明文密码到 password_hash 字段
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
            (username, email, password)
        )
    conn.commit()
    return jsonify(success=True, message='注册成功'), 201

# 登录
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')  # 前端传来的明文

    if not (username and password):
        return jsonify(success=False, message='字段缺失'), 400

    conn = get_db()
    with conn.cursor(pymysql.cursors.DictCursor) as cursor:
        # 直接用用户名+明文密码查表
        cursor.execute(
            "SELECT id, username, email FROM users WHERE username=%s AND password_hash=%s",
            (username, password)
        )
        user = cursor.fetchone()
        if not user:
            return jsonify(success=False, message='用户名或密码错误'), 401

    conn.commit()
    session['user_id'] = user['id']
    return jsonify(success=True, message='登录成功', user=user), 200


@app.post("/api/reset-password/send-code")
def send_reset_code():
    data = request.get_json() or {}
    email = data.get("email")
    if not email:
        return jsonify(success=False, message="邮箱不能为空"), 400

    # 可选：检查用户是否存在
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM users WHERE email=%s", (email,))
        if not cur.fetchone():
            return jsonify(success=False, message="邮箱未注册"), 404

    # 生成并缓存验证码
    code = "".join(random.choices("0123456789", k=6))
    verification_codes[email] = (code, time.time())

    # 异步/同步 发送
    try:
        _send_email(email, code)
    except Exception as e:
        return jsonify(success=False, message=f"邮件发送失败: {e}"), 500

    return jsonify(success=True, message="验证码已发送，请查收"), 200


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
            # 更新用户密码（明文存储，仅测试用）
            cur.execute(
                "UPDATE users SET password_hash=%s WHERE email=%s",
                (new_pass, email)
            )
        conn.commit()
        # 删除已用验证码
        verification_codes.pop(email, None)
    except Exception as e:
        conn.rollback()
        return jsonify(success=False, message=f"密码重置失败: {e}"), 500

    return jsonify(success=True, message="密码已重置，请使用新密码登录"), 200

# 退出登录
@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return jsonify({'success': True, 'message': '已退出登录'}), 200

# 获取当前用户信息
@app.route('/api/me', methods=['GET'])
def get_user():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '未登录'}), 401

    conn = get_db()
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute(
                'SELECT id, username, email FROM users WHERE id = %s',
                (session['user_id'],)
            )
            user = cursor.fetchone()
            return jsonify({
                'success': True,
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'email': user['email']
                }
            }), 200
    except Exception as e:
        print(e)
        return jsonify({'success': False, 'message': '获取用户信息失败'}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'message': 'API服务正常运行中'}), 200

if __name__ == '__main__':
    # create_db_if_not_exists()  # 如果你已用 Navicat 建好表，可注释掉
    app.run(debug=True)