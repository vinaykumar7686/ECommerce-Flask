import os
from flask import Flask, url_for, redirect, request, flash, session
from flask.templating import render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_manager, login_user, login_required, LoginManager, current_user, logout_user, mixins
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import InputRequired, Length, ValidationError, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt
from datetime import datetime
import base64

SECRET_KEY = os.urandom(32)
app = Flask(__name__)
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = SECRET_KEY

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ----------------------------------------------------------------------------------
# --------------------------------> Table to store products


class ProductsInfo(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Integer)
    link = db.Column(db.String(200), nullable=False)
    dateaddes = db.Column(db.DateTime, default=datetime.utcnow)
    thumbnailLink = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f'<Task : {self.id}>'


# -----------------------------> Table to store the details of all the products brought
class ProductBrought(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    userid = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    productid = db.Column(db.Integer, db.ForeignKey(
        'products_info.id'), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)


# ---------------------------------------------------------------------------------
# -----------------------> Table containing details of users
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(20), nullable=False, unique=True)
    mobile = db.Column(db.String(20), nullable=False, unique=True)

# -------------------------> User Form


class RegsiterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    email = StringField(validators=[InputRequired(), Length(
        min=4, max=40)], render_kw={"placeholder": "Email"})
    mobile = StringField(validators=[InputRequired(), Length(
        min=4, max=40)], render_kw={"placeholder": "Mobile no."})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    password2 = PasswordField(validators=[InputRequired(), EqualTo(
        'password')], render_kw={"placeholder": "Confirm Password"})
    submit = SubmitField("Register")

    def validate_user(self, username, email, mobile):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'User already exists. Please choose a different username.')

        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError(
                'User already exists. Please choose a different username.')

        existing_user_mobile = User.query.filter_by(mobile=mobile.data).first()
        if existing_user_mobile:
            raise ValidationError(
                'User already exists. Please choose a different username.')


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

# ------------------------------> For admin to view the products and delete them


@app.route('/admin', methods=['GET', 'POST'])
def adminHome():
    # --------------> For admin to add new product
    if request.method == 'POST':
        newItem = ProductsInfo(
            name=request.form['productName'],
            author=request.form['productAuthor'],
            description=request.form['productDescription'],
            price=request.form['productPrice'],
            link=request.form['productLink'],
            thumbnailLink=request.form['thumbnailLink']
        )
        try:
            session['productName'] = request.form['productName']
            db.session.add(newItem)
            db.session.commit()
            return redirect('/admin')
        except:
            return "There was an issue pushing to database"

    # --------------------> For admin to display all the stored products
    else:
        products = ProductsInfo.query.order_by(ProductsInfo.name).all()
        return render_template('Admin/adminPanel.html', products=products)


# -----------------------> For admin to delete a product
@app.route('/delete/<int:id>')
def deleteProduct(id):
    print(id)
    toDelete = ProductsInfo.query.get_or_404(id)
    try:
        db.session.delete(toDelete)
        db.session.commit()
        return redirect('/admin')
    except:
        return "Some error occured while deleting the file"

# -------------------------> For Homepage


@app.route('/')
def home():
    allProducts = []
    try:
        allProducts = ProductsInfo.query.all()
        print("======-=-=-=-==-=======>", allProducts)
    except:
        pass
    return render_template('home.html', allProducts=allProducts)


# -----------------------------> For logging in admin and normal users
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    # For admin
    if form.username.data and form.username.data == 'admin':
        if form.password.data == 'admin':
            session['username'] = request.form['username']
            session['logged_in'] = True
            return redirect('/admin')
        else:
            flash(f'Your credentials did not match. Please try again', 'danger')
            return redirect('/login')

    # For normal user
    else:
        if form.validate_on_submit():
            username = User.query.filter_by(
                username=form.username.data).first()
            if username:
                if bcrypt.check_password_hash(username.password, form.password.data):
                    session['username'] = request.form['username']
                    session['logged_in'] = True
                    login_user(username)
                    return redirect('/')
                else:
                    flash(f'Your credentials did not match. Please try again', 'danger')
                    return redirect(url_for('login'))
            else:
                flash(f'Your credentials did not match. Please try again', 'danger')
                return redirect(url_for('login'))
        return render_template('login.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    session['logged_in'] = False
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegsiterForm()
    if form.validate_on_submit():
        if (form.username.data).lower() == 'admin':
            flash(f'Username not allowed. Please any other username.', 'danger')
            return redirect(url_for('signup'))
        else:
            hashed_password = bcrypt.generate_password_hash(
                form.password.data, 12)
            new_user = User(username=form.username.data, password=hashed_password,
                            email=form.email.data, mobile=form.mobile.data)
            db.session.add(new_user)
            db.session.commit()
            flash(f'You have signed up successfully. Please login now.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/order/<int:productid>')
def order(productid):
    try:
        productDetails = ProductsInfo.query.get_or_404(productid)
        return render_template('order.html', productDetails=productDetails)
    except:
        #!!! Product not found Warning must show up
        return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)
