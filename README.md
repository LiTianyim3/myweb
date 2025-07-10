# logupin 用户认证系统

本项目是一个基于 Flask + MySQL 的用户注册、登录、密码重置（含邮箱验证码）全流程示例，前后端分离，适合学习和二次开发。

## 目录结构

```
myweb/
  test-backend/      # Flask 后端
    app.py           # 主后端代码
    requirements.txt # 后端依赖
  test-frontend/     # 前端静态页面
    index.html       # 登录页
    register.html    # 注册页
    reset_password.html # 重置密码页
    dashboard.html   # 用户中心
    static/          # 静态资源
```

## 快速开始

### 1. 安装依赖

后端依赖：
```bash
cd test-backend
pip install -r requirements.txt
pip install pymysql flask-mailman
```

### 2. 配置数据库

- 确保本地 MySQL 已创建数据库 `myweb`，并有 `users` 表：

```sql
CREATE TABLE users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(50) UNIQUE NOT NULL,
  email VARCHAR(100) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL
);
```

### 3. 启动后端

```bash
python app.py
```

### 4. 启动前端本地服务器

```bash
cd ../test-frontend
python -m http.server 8080
```

### 5. 访问系统

浏览器访问：http://localhost:8080/index.html

- 支持注册、登录、邮箱验证码找回密码、登录态校验、60秒验证码倒计时。

## 邮箱配置

- 邮箱服务使用 QQ 邮箱 SMTP，需在 app.py 中配置 `MAIL_USERNAME` 和 `MAIL_PASSWORD`（授权码）。

## 主要依赖
- Flask
- Flask-Cors
- flask-mailman
- pymysql

## 说明
- 仅供学习和演示，生产环境请加强安全性（如密码加密、验证码防刷等）。

---
如有问题欢迎提 issue。
