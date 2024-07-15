from flask import Flask, render_template, url_for, redirect, request, send_file, session, Blueprint
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO, send, join_room ,leave_room
import os
import qrcode
import random
import pyotp
from string import ascii_uppercase
from io import BytesIO
from werkzeug.utils import secure_filename
#import threading
#import logging


#init db
db = SQLAlchemy()
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'th1s1sasecretkey'
db.init_app(app)
#socketio for chat func
socketio = SocketIO(app)

"""
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
AUTH, ONE TIME PASSWORD AND SALT FUNCTION
"""
auth = Blueprint("auth", __name__)

key = "0n3t1m3p4ssw0rdk3yl3tsm4k3th1ss3cur3"
totp = pyotp.TOTP(key)

def make_salt() -> str:
    return 


"""
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
LOGIN
"""

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    #change to session.get()
    return User.query.get(int(user_id))
"""
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
CLASSES
"""

class Admin(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, nullable=False, unique=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(150), nullable=False, unique=True)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, nullable=False, unique=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(150), nullable=False, unique=True)
    
class Files(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(50), nullable=False)
    data = db.Column(db.LargeBinary, nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[ InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    email = StringField(validators=[ InputRequired(), Length(min=4, max=40)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[ InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')
        
    def validate_email(self, email):
        existing_user_email = User.query.filter_by(
            email=email.data).first()
        if existing_user_email:
            raise ValidationError(
                'That Email already exists. Please choose a different one')
            
class LoginForm(FlaskForm):
    username = StringField(validators=[ InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[ InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

class AuthForm(FlaskForm):
    inputCode = IntegerField(validators=[ InputRequired()], render_kw={"placeholder": "One Time Password"})
    submit = SubmitField('Authenticate')
"""
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ROOM CODES
"""
rooms = {}


def generate_code(length):
    while True: 
        code = ""
        for _ in range(length):
            code += random.choice(ascii_uppercase)

        if code not in rooms:
            break
    return code
"""
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ROUTES
"""
@app.route('/')
def home():
    session.clear()
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    
    if request.method == 'POST':
        session.pop('username', None)
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                user.authenticated = True
                session["username"] = form.username.data
                #session["email"] = form.email.data
                #name = session.get("username")
                session['user_id']=user.id
                #login_user(user)
                
                return redirect(url_for('authenticate'))
    return render_template('login.html', form=form)

@app.route('/authenticate', methods=['GET', 'POST'])
def authenticate():
    form = AuthForm()
    user = session.get('username')
    #create a QR code to authenticate
    url = pyotp.totp.TOTP(key).provisioning_uri(name=user, issuer_name="Security App")
    qr = qrcode.make(url)
    qr.save('static/image.jpg')

    if form.validate_on_submit():
        inputCode = form.inputCode.data
        verification = totp.verify(inputCode)
        if verification == True:
            login_user(user)
            qr.delete('static/image.jpg')
            return redirect(url_for('dashboard'))
    return render_template('authenticate.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    
    if request.method == "POST":
        code = request.form.get("code")
        join = request.form.get("join", False)
        #create = request.form.get("create", False)

        if join != False and not code:
            return render_template("dashboard.html", error="Please enter a valid room code")
        
        room = code

        if code not in rooms:
            return render_template("dashboard.html", error="Room does not exist", code=code)

        #store room in session
        session["room"] = room
        return redirect(url_for("chat"))

    return render_template('dashboard.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    salt = make_salt()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data + salt)
        new_user = User(id = random.randint(1000000, 9999999), username=form.username.data, password=hashed_password, email=form.email.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/admin/', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        session.pop('username', None)
    form = LoginForm()

    if form.validate_on_submit():
        admin = Admin.query.filter_by(username=form.username.data).first()
        if admin:
            if bcrypt.check_password_hash(admin.password, form.password.data):
                session['admin_id']=admin.id
                session["username"] = form.username.data
                #name = session.get("username")
                print('reached login')
                login_user(admin)
                return redirect(url_for('adminDashboard'))
    return render_template('login.html', form=form)

@app.route('/admin/dashboard', methods=['GET','POST'])

def adminDashboard():
    
    if not session.get('admin_id'):
        
        return redirect(url_for('admin'))
    
    if request.method == "POST":
        
        code = request.form.get("code")
        join = request.form.get("join", False)
        create = request.form.get("create", False)

        if join != False and not code:
            return render_template("adminDashboard.html", error="Please enter a valid room code")
        
        room = code
        
        if create != False:
            room = generate_code(4)
            rooms[room] = {"members": 0, "messages": []}

        elif code not in rooms:
            return render_template("adminDashboard.html", error="Room does not exist", code=code)

        #store room in session
        session["room"] = room
        return redirect(url_for("chat"))
    
    return render_template('adminDashboard.html')

#this section is to be removed once admin account created
@app.route('/adminregister', methods=['GET', 'POST'])
def adminregister():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = Admin(id = random.randint(1000000, 9999999), username=form.username.data, password=hashed_password, email=form.email.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('admin'))

    return render_template('register.html', form=form)
"""
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
CHAT FUNCTIONALITY
"""
@app.route('/chat', methods=['GET', 'POST'])
def chat():
    #this is stopping a user from just entering /chat in url to get to room
    username = session.get("username")
    room = session.get("room")
    
    if room is None or username is None or room not in rooms:
        return redirect(url_for("home"))
    return render_template("chat.html", code=room, messages=rooms[room]["messages"])

"""
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
FILE HOSTING FUNCTIONALITY
"""
#allow only admin to upload
@app.route('/upload', methods=['GET', 'POST'])

def upload():
    if not session.get('admin_id'):
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        file = request.files['file']
        filename = secure_filename(file.filename)
        upload = Files(filename=filename, data=file.read())
        db.session.add(upload)
        db.session.commit()
        return f'Uploaded: {file.filename}'
    return render_template('upload.html')

@app.route('/download', methods=['GET'])
@login_required
def download():
    files = db.session.execute(db.select(upload))
    return render_template('download.html', files=files)

@app.route('/download/<upload_id>')
@login_required
def downloadFile(upload_id):
    upload = Files.query.filter_by(id=upload_id).first()
    return send_file(BytesIO(upload.data), download_name=upload.filename, as_attachment=True)

"""
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SOCKETIO
"""
@socketio.on('connect')
def connect(auth):
    room = session.get("room")
    username = session.get("username")
    
    if not room or not username:
        return
    if room not in rooms:
        leave_room(room)
        return
    
    join_room(room)
    send({"name": username, "message": "has entered"}, to=room)
    rooms[room]["members"]+=1
    print(f"{username} joined room {room}")

@socketio.on('disconnect')
def disconnect():
    room = session.get("room")
    username = session.get("username")
    leave_room(room)
    send({"name": username, "message": "has left"}, to=room)
    rooms[room]["members"]-=1

@socketio.on("message")
def message(data):
    room = session.get("room")
    
    if room not in rooms:
        return
    
    #add date and time here
    content = {
        "name": session.get("username"),
        "message": data["data"]
    }
    send(content, to=room)
    rooms[room]["messages"].append(content)
    print(f"{session.get('name')} said: {data['data']}")

    
"""
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
RUN APP
"""

if __name__ == "__main__":
    
    socketio.run(app, debug=True)
