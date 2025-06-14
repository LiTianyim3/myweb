import os
import random
import time
from typing import Final
from flask import Flask, request, jsonify, session, g, url_for
import pymysql
import pymysql.cursors
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
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

# 上传目录
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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

@app.route('/api/orders/<int:order_id>', methods=['GET'])
def get_order(order_id):
    user = session.get('user_id')
    if not user:
        return jsonify(success=False, message='未登录'), 401
    conn = get_db()
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        cur.execute("""
            SELECT o.id, o.status, o.product_id, p.file_url 
            FROM orders o 
            JOIN products p ON o.product_id=p.id 
            WHERE o.id=%s AND o.buyer_id=%s
        """, (order_id, user))
        order = cur.fetchone()
    if not order:
        return jsonify(success=False, message='订单不存在'), 404
    return jsonify(success=True, data=order), 200
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

# 退出登录
@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify(success=True, message='已退出登录'), 200

# 获取当前用户
@app.route('/api/me', methods=['GET'])
def get_user():
    if 'user_id' not in session:
        return jsonify(success=False, message='未登录'), 401
    conn = get_db()
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        cur.execute("SELECT id, username, email FROM users WHERE id=%s", (session['user_id'],))
        user = cur.fetchone()
    return jsonify(success=True, user=user), 200

# 发布商品（支持文件上传）
@app.post("/api/products")
def create_product():
    user = session.get('user_id')
    if not user:
        return jsonify(success=False, message="未登录"), 401

    title = request.form.get('title')
    price = request.form.get('price')
    desc  = request.form.get('description')
    if not all([title, price]):
        return jsonify(success=False, message="参数不全"), 400

    img = request.files.get('image')
    f   = request.files.get('file')
    if not img or not f or img.filename == '' or f.filename == '':
        return jsonify(success=False, message="文件缺失"), 400

    img_name  = secure_filename(img.filename)
    file_name = secure_filename(f.filename)
    img.save(os.path.join(app.config['UPLOAD_FOLDER'], img_name))
    f.save(os.path.join(app.config['UPLOAD_FOLDER'], file_name))

    img_url  = url_for('static', filename=f'uploads/{img_name}', _external=True)
    file_url = url_for('static', filename=f'uploads/{file_name}', _external=True)

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO products(owner_id,title,description,price,file_url,image_url)
            VALUES(%s,%s,%s,%s,%s,%s)
        """, (user, title, desc, price, file_url, img_url))
    conn.commit()
    return jsonify(success=True), 201

# 列出所有商品
@app.get("/api/products")
def list_products():
    conn = get_db()
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        cur.execute("SELECT p.*,u.username FROM products p JOIN users u ON p.owner_id=u.id ORDER BY p.created_at DESC")
        items = cur.fetchall()
    return jsonify(success=True, data=items), 200

# 我的商品
@app.get("/api/products/mine")
def my_products():
    user = session.get('user_id')
    if not user:
        return jsonify(success=False, message="未登录"), 401
    conn = get_db()
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        cur.execute("SELECT * FROM products WHERE owner_id=%s", (user,))
        items = cur.fetchall()
    return jsonify(success=True, data=items), 200

# 删除商品
@app.route('/api/products/<int:product_id>', methods=['DELETE'])
def delete_product(product_id):
    user = session.get('user_id')
    if not user:
        return jsonify(success=False, message="未登录"), 401

    conn = get_db()
    try:
        with conn.cursor() as cur:
            # 验证商品存在且属于当前用户
            cur.execute("SELECT owner_id FROM products WHERE id=%s", (product_id,))
            row = cur.fetchone()
            if not row:
                return jsonify(success=False, message="商品不存在"), 404
            if row[0] != user:
                return jsonify(success=False, message="无权限删除"), 403
            # 执行删除
            cur.execute("DELETE FROM products WHERE id=%s", (product_id,))
        conn.commit()
        return jsonify(success=True, message="删除成功"), 200

    except pymysql_err.IntegrityError:
        conn.rollback()
        # 关联订单未删除，外键约束阻止删除
        return jsonify(success=False,
                       message="该商品已有订单记录，无法删除，请先处理相关订单"), 400

# 创建订单（模拟微信支付）
@app.post("/api/orders")
def create_order():
    data = request.get_json() or {}
    user = session.get('user_id')
    pid  = data.get('product_id')
    if not user or not pid:
        return jsonify(success=False, message="参数不全"), 400

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT price FROM products WHERE id=%s", (pid,))
        row = cur.fetchone()
        if not row:
            return jsonify(success=False, message="商品不存在"), 404
        amount = row[0]
        cur.execute("INSERT INTO orders(buyer_id,product_id,amount) VALUES(%s,%s,%s)", (user, pid, amount))
        oid = cur.lastrowid
    conn.commit()

    pay_url = f"https://api.mockwechatpay.cn/qrcode/{oid}"
    return jsonify(success=True, order_id=oid, pay_url=pay_url), 201

# 订单列表
@app.get("/api/orders")
def list_orders():
    user = session.get('user_id')
    if not user:
        return jsonify(success=False, message="未登录"), 401

    conn = get_db()
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        cur.execute("""
            SELECT o.*, p.title, p.file_url
            FROM orders o
            JOIN products p ON o.product_id=p.id
            WHERE o.buyer_id=%s
        """, (user,))
        orders = cur.fetchall()
    return jsonify(success=True, data=orders), 200

# 健康检查
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify(status='healthy', message='API服务正常运行中'), 200

if __name__ == '__main__':
    app.run(debug=True)