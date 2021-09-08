from flask import Blueprint, render_template
from datetime import datetime
from . import db
from flask_login import login_required, current_user
import qrcode
import pyotp
import io
import base64

main  = Blueprint('main',__name__)


@main.route('/')
def index():
    return render_template('index.html')

@main.route('/profile')
@login_required
def profile():
    t = current_user.dob
    doblol = t.strftime('%d/%m/%y')
    return render_template('profile.html', username=current_user.username, dob=doblol)

@main.route('/authqr')
@login_required
def authqr():
    output = io.BytesIO()
    t = current_user.ustring
    gg = qrcode.QRCode(version=1,
                       error_correction=qrcode.constants.ERROR_CORRECT_L,
                       box_size=20,
                       border=1)
    gg.add_data("otpauth://totp/WebApp:"+ current_user.username +"?secret="+ t +"&issuer=WebApp")
    gg.make()
    img = gg.make_image()
    img.convert('RGB').save(output, format = 'png')
    output.seek(0,0)
    lol = base64.standard_b64encode(output.read()) 
    output_s = lol.decode('utf-8')
    return render_template('auth.html', img=output_s)
