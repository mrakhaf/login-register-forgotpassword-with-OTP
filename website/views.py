from flask import Blueprint, render_template

views = Blueprint('views', __name__)


@views.route('/')
def home():
    return render_template("home.html")

@views.route('/loginregister')
def loginregister():
    return render_template("login.html")    

@views.route('/validationOTP')
def validationOTP():
    return render_template("validationOTP.html") 

@views.route('/forgotPassword')
def forgotPassword():
    return render_template("forgot-password.html")  

@views.route('/validationForgotPassword')
def validationForgotPassword():
    return render_template("validationOTP.html")       

@views.route('/resetPassword')
def resetPassword():
    return render_template("reset-password.html")        
    
       
       

