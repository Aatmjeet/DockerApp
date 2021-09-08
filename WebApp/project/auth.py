import re
from flask import Blueprint, render_template, redirect, url_for,request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User
from . import db
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime
import pyotp
import base64
import hashlib


auth = Blueprint('auth', __name__)

@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect(url_for('auth.login'))

    login_user(user, remember=remember)
    return redirect(url_for('main.profile'))

@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/signup', methods=['POST'])
def signup_post():
    username = request.form.get('username')
    firstname = request.form.get('firstname')
    lastname = request.form.get('lastname')
    dob = request.form.get('dob')
    password = request.form.get('password')
    error = None
    if not username or not username.strip():
        error = 'Invalid User Name'    
    if not firstname or not firstname.strip():
        error = 'Invalid First Name'   
    if not lastname or not lastname.strip():
        error = 'Invalid Last Name'
          
    if not password or not password.strip():
        error = 'Invalid Password'
    if not dob or not dob.strip():
        error = "Invalid Date of Birth"
    if error:
        return  render_template('signup.html', error = error, username = username, firstname = firstname, dob=dob, lastname = lastname, password = password)
    
    dob_new = dob[2:]
    bday = datetime.strptime(dob_new, '%y-%m-%d').date()

    user = User.query.filter_by(username=username).first()
    if user:
        flash('Username already exists')
        return redirect(url_for(('auth.signup')))
    userhash = hashlib.sha256(("webapp"+username+ "salt").encode()).hexdigest()
    hstring = base64.b32encode(username.encode()).decode('utf-8').replace("=","")
    new_user = User(username=username,ustring=hstring, firstname=firstname,lastname=lastname,dob=bday,userhash=userhash, password=generate_password_hash(password, method='sha256'))

    db.session.add(new_user)
    db.session.commit()

    flash('Account created, Login and Don\'t forget to add Authenticator!')
    return redirect(url_for('auth.login'))


@auth.route('/passwordreset')
def passwordreset():
    return render_template('passwordreset.html')

@auth.route('/passwordreset', methods=['POST'])
def passwordreset_post():
    username = request.form.get('username')
    error = None
    if not username or not username.strip():
        error = 'Invalid User Name'
    
    if error:
        return render_template('passwordreset.html', error = error, username = username)
    
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('Username not found! try again.')
        return redirect(url_for('auth.passwordreset'))
    return redirect(url_for('auth.checkauth', userhash=user.userhash))

@auth.route('/checkauth')
def checkauth():
    userhash = request.args['userhash']
    return render_template('checkauth.html', userhash=userhash)

@auth.route('/checkauth', methods=['POST'])
def checkauth_post():
    userhash = request.form.get('userhash')
    user = User.query.filter_by(userhash=userhash).first()
    totp = request.form.get('totp')
    strl = pyotp.TOTP(user.ustring)
    error = None
    if not totp or not totp.strip():
        error = 'Invalid TOTP'
    if error:
        flash(error)
        return redirect(url_for('auth.checkauth', userhash=userhash))
    if strl.verify(totp):
        return redirect(url_for('auth.newpass', userhash=userhash))
    else:
        flash("You have supplied an invalid 2FA token!")
        return redirect(url_for('auth.checkauth', userhash=userhash))

@auth.route('/newpass')
def newpass():
    userhash = request.args['userhash']
    return render_template('newpass.html', userhash=userhash)

@auth.route('/newpass', methods=['POST'])
def newpass_post():
    userhash = request.form.get('userhash')
    newpass = request.form.get('newpass')
    retype = request.form.get('retype-new')
    error = None
    if not newpass or not newpass.strip():
        error = 'Invalid Password'
    if not retype or not retype.strip():
        error = 'Invalid Password'
    if retype != newpass:
        error = 'Passwords Don\'t match'
    
    if error:
        flash(error)
        return redirect(url_for('auth.newpass', userhash=userhash))
    
    user = User.query.filter_by(userhash=userhash).first()
    if user.password == generate_password_hash(newpass, method='sha256'):
        flash("You can not use last passsword!")
        return redirect(url_for('auth.newpass', userhash=userhash))
    user.password = generate_password_hash(newpass, method='sha256')
    db.session.commit()
    flash("Password has beed updated! Login now!")
    return redirect(url_for('auth.login'))

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))
