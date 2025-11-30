from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User

user_bp = Blueprint('user', __name__)

@user_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm = request.form['confirm']
        email = request.form.get('email')
        if not username or not password or password != confirm:
            flash('Invalid registration details.')
            return render_template('register.html')
        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return render_template('register.html')
        password_hash = generate_password_hash(password)
        user = User(username=username, password_hash=password_hash, email=email)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please log in.')
        return redirect(url_for('user.login'))
    return render_template('register.html')

@user_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash('Logged in successfully.')
            return redirect(url_for('index'))
        flash('Invalid username or password.')
    return render_template('login.html')

@user_bp.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.')
    return redirect(url_for('user.login'))
