from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
import mysql.connector

app = Flask(__name__)
app.secret_key = 'your_secret_key'
bcrypt = Bcrypt(app)

# Thiết lập Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

try:
    db = mysql.connector.connect(
        host="127.0.0.1",
        user="root",
        password="0394383782",
        database="user_management"
    )
    print("Kết nối thành công!")
except mysql.connector.Error as err:
    print(f"Lỗi kết nối: {err}")

cursor = db.cursor(dictionary=True)

# User model cho Flask-Login
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

# Route cho trang chủ
@app.route('/')
def home():
    return redirect(url_for('login'))  

# Trang Đăng ký
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form.get('role', 'user')  
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        try:
            cursor.execute(
                "INSERT INTO user (username, email, password_hash, role) VALUES (%s, %s, %s, %s)",
                (username, email, hashed_password, role)
            )
            db.commit()
            flash("Đăng ký thành công!", "success")
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            flash(f"Lỗi: {err}", "danger")

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        cursor.execute("SELECT * FROM user WHERE username = %s", (username,))
        user = cursor.fetchone()
        if user and bcrypt.check_password_hash(user['password_hash'], password):
            # Đăng nhập thành công
            user_obj = User(user['id'], user['username'], user['email'], user['role'])
            login_user(user_obj)
            
            # Kiểm tra role để chuyển hướng
            if user['role'] == 'admin':
                flash("Đăng nhập thành công với quyền Admin!", "success")
                return redirect(url_for('admin_dashboard'))  
            else:
                flash("Đăng nhập thành công!", "success")
                return redirect(url_for('user_dashboard'))  
        else:
            flash("Sai thông tin đăng nhập!", "danger")

    return render_template('login.html')


@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash("Bạn không có quyền truy cập trang này!", "danger")
        return redirect(url_for('user_dashboard'))  # Chuyển về trang của user

    cursor.execute("SELECT id, username, email, role FROM user")
    users = cursor.fetchall()
    return render_template('admin_dashboard.html', username=current_user.username, users=users)


# Xóa người dùng
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash("Bạn không có quyền thực hiện hành động này!", "danger")
        return redirect(url_for('admin_dashboard'))  # Chuyển về trang admin_dashboard

    try:
        cursor.execute("DELETE FROM user WHERE id = %s", (user_id,))
        db.commit()
        flash("Người dùng đã được xóa thành công!", "success")
    except mysql.connector.Error as err:
        flash(f"Lỗi khi xóa người dùng: {err}", "danger")

    return redirect(url_for('admin_dashboard'))  # Chuyển về trang admin_dashboard


# Thêm tài khoản
@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        flash('Bạn không có quyền thực hiện thao tác này!', 'danger')
        return redirect(url_for('admin_dashboard'))  
    
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    role = request.form['role']

    # Băm mật khẩu
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    
    try:
        cursor.execute(
            "INSERT INTO user (username, email, password_hash, role) VALUES (%s, %s, %s, %s)",
            (username, email, hashed_password, role)
        )
        db.commit()
        flash('Tài khoản mới đã được thêm!', 'success')
    except mysql.connector.Error as err:
        flash(f'Lỗi: {err}', 'danger')
    
    return redirect(url_for('admin_dashboard')) 

# Trang Dashboard của User
@app.route('/user_dashboard')
@login_required
def user_dashboard():
    return render_template('user_dashboard.html', username=current_user.username)

# Đăng xuất
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Đã đăng xuất!", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
