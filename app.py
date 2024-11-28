from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
import mysql.connector

app = Flask(__name__)
app.secret_key = 'your_secret_key'
bcrypt = Bcrypt(app)

# Quản lý phiên đăng nhập
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Kết nối MySQL
try:
    db = mysql.connector.connect(
        host="127.0.0.1",
        user="root",
        password="0394383782",
        database="user_management"
    )
    print("Kết nối cơ sở dữ liệu thành công!")
except mysql.connector.Error as err:
    print(f"Lỗi kết nối cơ sở dữ liệu: {err}")

cursor = db.cursor(dictionary=True)

# Định nghĩa model User
class User(UserMixin):
    def __init__(self, id, username, email, role):
        self.id = id
        self.username = username
        self.email = email
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    cursor.execute("SELECT * FROM user WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    if user:
        return User(user['id'], user['username'], user['email'], user['role'])
    return None

# Trang chủ
@app.route('/')
def home():
    return redirect(url_for('login'))

# Đăng ký
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        try:
            cursor.execute(
                "INSERT INTO user (username, email, password_hash, role) VALUES (%s, %s, %s, %s)",
                (username, email, hashed_password, 'user')
            )
            db.commit()
            flash("Đăng ký thành công!", "success")
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            flash(f"Lỗi: {err}", "danger")
    return render_template('register.html')

# Đăng nhập
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cursor.execute("SELECT * FROM user WHERE username = %s", (username,))
        user = cursor.fetchone()
        if user and bcrypt.check_password_hash(user['password_hash'], password):
            user_obj = User(user['id'], user['username'], user['email'], user['role'])
            login_user(user_obj)

            if user['role'] == 'admin':
                flash("Đăng nhập thành công với quyền Admin!", "success")
                return redirect(url_for('admin_dashboard'))
            else:
                flash("Đăng nhập thành công!", "success")
                return redirect(url_for('user_dashboard'))
        else:
            flash("Sai thông tin đăng nhập!", "danger")
    return render_template('login.html')

# Dashboard Admin
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash("Bạn không có quyền truy cập trang này!", "danger")
        return redirect(url_for('user_dashboard'))

    cursor.execute("SELECT id, username, email, role FROM user")
    users = cursor.fetchall()
    return render_template('admin_dashboard.html', username=current_user.username, users=users)

# Xóa người dùng
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash("Bạn không có quyền thực hiện hành động này!", "danger")
        return redirect(url_for('admin_dashboard'))

    try:
        cursor.execute("DELETE FROM user WHERE id = %s", (user_id,))
        db.commit()
        flash("Người dùng đã được xóa thành công!", "success")
    except mysql.connector.Error as err:
        flash(f"Lỗi khi xóa người dùng: {err}", "danger")
    return redirect(url_for('admin_dashboard'))

# Thêm người dùng
@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        flash("Bạn không có quyền thực hiện hành động này!", "danger")
        return redirect(url_for('admin_dashboard'))

    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    role = request.form['role']
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    try:
        cursor.execute(
            "INSERT INTO user (username, email, password_hash, role) VALUES (%s, %s, %s, %s)",
            (username, email, hashed_password, role)
        )
        db.commit()
        flash("Thêm người dùng thành công!", "success")
    except mysql.connector.Error as err:
        flash(f"Lỗi: {err}", "danger")
    return redirect(url_for('admin_dashboard'))

# Dashboard User
@app.route('/user_dashboard')
@login_required
def user_dashboard():
    return render_template('user_dashboard.html', username=current_user.username)

# Cập nhật thông tin cá nhân
@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Cập nhật thông tin cá nhân
        try:
            cursor.execute(
                "UPDATE user SET username = %s, email = %s WHERE id = %s",
                (username, email, current_user.id)
            )
            db.commit()

            # Cập nhật mật khẩu
            if current_password and new_password and confirm_password:
                cursor.execute("SELECT password_hash FROM user WHERE id = %s", (current_user.id,))
                user = cursor.fetchone()
                if user and bcrypt.check_password_hash(user['password_hash'], current_password):
                    if new_password == confirm_password:
                        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                        cursor.execute(
                            "UPDATE user SET password_hash = %s WHERE id = %s",
                            (hashed_password, current_user.id)
                        )
                        db.commit()
                        flash("Mật khẩu đã được cập nhật!", "success")
                    else:
                        flash("Mật khẩu mới và xác nhận mật khẩu không khớp!", "danger")
                else:
                    flash("Mật khẩu hiện tại không đúng!", "danger")

            flash("Cập nhật thông tin cá nhân thành công!", "success")
        except mysql.connector.Error as err:
            flash(f"Lỗi: {err}", "danger")

        return redirect(url_for('user_dashboard'))

    # Lấy thông tin người dùng 
    cursor.execute("SELECT username, email FROM user WHERE id = %s", (current_user.id,))
    user = cursor.fetchone()
    return render_template('edit_profile.html', user=user)

# Đăng xuất
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Đã đăng xuất!", "info")
    return redirect(url_for('login'))

# Chạy ứng dụng
if __name__ == '__main__':
    app.run(debug=True)
