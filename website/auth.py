from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, current_user, logout_user, login_required
import random 

auth = Blueprint('auth', __name__)

@auth.route("/loginregister", methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if current_user.is_authenticated:
            return redirect(url_for('views.home'))
        else :
            return render_template('login.html', user=current_user)         
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password or email, try again!', category='error')
        else:
            flash('Incorrect password or email, try again!', category='error')

    return render_template('login.html', user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        phone = request.form.get('phone')
        fullname = request.form.get('fullname')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(fullname) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            
            session['EMAIL'] = email
            session['PHONE'] = phone
            session['FULLNAME'] = fullname
            session['PASSWORD'] = password1

            flash('Check your email and enter OTP code bellow!', category='success')
            otp = generateOTP()
            session["OTPKEY"] = str(otp)
            print(session["OTPKEY"])
            session['EMAIL'] = email
            return redirect(url_for('views.validationOTP'))

    return render_template('register.html', user=current_user)      

@auth.route('/validationOTP', methods=['POST'])
def validationOTP():
    if request.method == 'POST':
        otp = request.form.get('otp')
        if 'OTPKEY' in session:
            s = session['OTPKEY']
            if s == otp:
                email = session['EMAIL']
                phone = session['PHONE']
                fullname = session['FULLNAME']
                password = session['PASSWORD']

                #add new user
                new_user = User(email=email, phone=phone, fullname=fullname, password=generate_password_hash(
                password, method='sha256'))
                db.session.add(new_user)
                db.session.commit()

                login_user(new_user, remember=True)

                #Delete session
                session.pop('EMAIL',None)
                session.pop('PHONE',None)
                session.pop('FULLNAME',None)
                session.pop('PASSWORD',None)
                session.pop('OTPKEY',None)
                flash('Authorized!', category='success')
                return redirect(url_for('views.home'))
            else:
                flash('Wrong OTP!', category='error')  
                
    return render_template('validationOTP.html')

@auth.route('/forgotPassword', methods=['POST'])
def forgotPassword():
    if request.method == 'POST':
        email = request.form.get('email')  
        user = User.query.filter_by(email=email).first()
        if user:
            session['EMAIL'] = email
            otp = generateOTP()
            session["OTPKEY"] = str(otp)
            print(session["OTPKEY"])
            return redirect(url_for('views.validationForgotPassword'))
        else :
            flash('Wrong email, please enter email correctly!', category='error')

    return render_template("forgot-password.html")  

@auth.route('/validationForgotPassword', methods=['POST'])
def validationForgotPassword():
    if request.method == 'POST':
        otp = request.form.get('otp')
        if 'OTPKEY' in session:
            s = session['OTPKEY']
            if s == otp:
                flash('Authorized!, please reset your password!', category='success')
                session.pop('OTPKEY',None)
                return redirect(url_for('views.resetPassword'))
            else:
                flash('Wrong OTP!', category='error')    
    return render_template("validationOTP.html")    

@auth.route('/resetPassword', methods=['POST'])
def resetPassword():
    if request.method == 'POST':
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        email = session['EMAIL']
        
        if password1 == password2:
            user = User.query.filter_by(email=email).first()
            if user:
                user.password = generate_password_hash(
                password1, method='sha256')
                db.session.commit()
                session.pop('EMAIL',None)
                flash('Reset password success!', category='success')
                return redirect(url_for('views.loginregister'))
        else:
            flash('Passwords don\'t match.', category='error')

    return render_template("reset-password.html")       

#Function 
def generateOTP():
    return random.randrange(100000,999999)   