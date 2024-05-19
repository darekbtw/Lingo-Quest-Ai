from flask import Flask, render_template, url_for, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm, CSRFProtect
from flask_bcrypt import Bcrypt
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'main.db')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

csrf = CSRFProtect(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(254), unique=True, nullable=False)
    password_hash = db.Column(db.String(254), nullable=False)
    join_date = db.Column(db.DateTime, default=datetime.utcnow)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=1, max=15)], render_kw={"placeholder": "Username"})

    email = StringField(validators=[InputRequired(), Length(
        min=12, max=40)], render_kw={"placeholder": "Email"})

    password = StringField(validators=[InputRequired(), Length(
        min=6, max=25)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()

        if existing_user_username:
            raise ValidationError("Username already exists. Please choose a different one.")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=1, max=15)], render_kw={"placeholder": "Username"})

    password = StringField(validators=[InputRequired(), Length(
        min=6, max=25)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")

def __repr__(self):
    return '<task %r>' % self.id

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    return render_template('home.html')

@app.route('/learn', methods=['GET', 'POST'])
@login_required
def learn():
    return render_template('learn.html')

@app.route('/practice', methods=['GET', 'POST'])
@login_required
def practice():
    return render_template('practice.html')

@app.route('/about', methods=['GET', 'POST'])
@login_required
def about():
    return render_template('about.html')

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    return render_template('settings.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    return render_template('profile.html')

# Route for handling the login page logic
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                return redirect(url_for('home'))
    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        # Generate the hashed password
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')  # assuming you need to decode it

        # Create a new user with the correct field name for the password
        new_user = User(username=form.username.data, 
                        email=form.email.data, 
                        password_hash=hashed_password)  # Use 'password_hash' instead of 'password'

        # Add the new user to the database session and commit
        db.session.add(new_user)
        db.session.commit()

        # Redirect to the login page after successful registration
        return redirect(url_for('login'))

    # Render the registration form
    return render_template('register.html', form=form)

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)