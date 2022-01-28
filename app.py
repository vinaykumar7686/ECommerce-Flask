import os
from flask import Flask, url_for, redirect, request, flash, session
from flask.templating import render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_manager, login_user, login_required, LoginManager, current_user, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import InputRequired, Length, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt
from datetime import datetime
from werkzeug.utils import secure_filename


UPLOAD_FOLDER = 'static/images/'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
SECRET_KEY = os.urandom(32)
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
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
    imageName = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f'<Task : {self.id}>'


# -----------------------> Table containing details of users
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(20), nullable=False, unique=True)
    mobile = db.Column(db.String(20), nullable=False, unique=True)



# -------------------------> User Registration Form
class RegsiterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    email = EmailField(validators=[InputRequired(), Length(
        min=4, max=40)], render_kw={"placeholder": "Email"})
    mobile = StringField(validators=[InputRequired(), Length(
        min=10, max=15)], render_kw={"placeholder": "Mobile no."})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    password2 = PasswordField(validators=[InputRequired(), ],
                              render_kw={"placeholder": "Confirm Password"})
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
                'User already exists. Please choose a different email.')

        existing_user_mobile = User.query.filter_by(mobile=mobile.data).first()
        if existing_user_mobile:
            raise ValidationError(
                'User already exists. Please choose a different mobile number.')


# -------------------------------> User Login Form
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")


# ------------------------------> For admin to view the products and delete them
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# --------------------------------> Admin Homepage
@app.route('/admin', methods=['GET', 'POST'])
def adminHome():
    if 'username' in session and session['username'] == 'admin':
        # --------------> For admin to add new product
        if request.method == 'POST':
            image = request.files['productImage']
            if image and allowed_file(image.filename):
                filename = secure_filename(image.filename)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            newItem = ProductsInfo(
                name=request.form['productName'],
                author=request.form['productAuthor'],
                description=request.form['productDescription'],
                price=request.form['productPrice'],
                link=request.form['productLink'],
                imageName=image.filename
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
    else:
        return render_template('Error.html', title='Access Denied', msg="Unable to access admin Homepage, Please signin to continue.")



# -----------------------> For admin to delete a product
@app.route('/delete/<int:id>')
def deleteProduct(id):
    if 'username' in session and session['username'] == 'admin':
        print(id)
        toDelete = ProductsInfo.query.get_or_404(id)
        try:
            db.session.delete(toDelete)
            db.session.commit()
            return redirect('/admin')
        except:
            return "Some error occured while deleting the file"
    else:
        return render_template('Error.html', title="Access Denied!", msg="You need admin priviledges to perform this action!")


# ---------------------------> Function to autofill the details into the update form
@app.route('/update/<int:id>', methods=['GET'])
def updateProduct(id):
    if request.method == 'GET':
        if 'username' in session and session['username'] == 'admin':
            print(id)
            toUpdate = ProductsInfo.query.get_or_404(id)
            print(toUpdate.description)
            return render_template('Admin/update.html', toUpdate=toUpdate, product_id=id)
        else:
            return render_template('Error.html', title="Access Denied!", msg="You need admin priviledges to perform this action!")



# --------------------------> For admin to update the product details
@app.route('/updateproduct', methods=['POST'])
def UpdateProducts():
    if 'username' in session and session['username'] == 'admin':

        name = request.form['productName']
        author = request.form['productAuthor']
        description = request.form['productDescription']
        price = request.form['productPrice']
        link = request.form['productLink']
        image = request.files['productImage']
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            image = image.filename
            db.session.query(ProductsInfo).filter(ProductsInfo.id == request.form['product_id']).update(
                {'name': name, 'author': author, 'description': description, 'price': price, 'link': link, 'imageName': image})
            db.session.commit()

        else:
            db.session.query(ProductsInfo).filter(ProductsInfo.id == request.form['product_id']).update(
                {'name': name, 'author': author, 'description': description, 'price': price, 'link': link})
            db.session.commit()
        return redirect('/admin')
    else:
        return render_template('Error.html', title="Access Denied!", msg="You need admin priviledges to perform this action!")


# -------------------------> User Homepage
@app.route('/')
def home():
    allProducts = []
    # Adding a username in session with value if doesn't exists any.
    if 'username' not in session:
        session['username'] = 'None'
        session['logged_in'] = False

    try:
        allProducts = ProductsInfo.query.all()
    except:
        pass
    return render_template('home.html', allProducts=allProducts)


# -----------------------------> For logging in admin and normal users
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Adding a username in session with value if doesn't exists any.
    if 'username' not in session:
        session['username'] = 'None'
        session['logged_in'] = False

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


# ---------------------------------> For Logging Out Users
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    session['username'] = 'None'
    session['logged_in'] = False
    return redirect(url_for('login'))

# -----------------------------------> For signing up a user
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegsiterForm()
    if form.validate_on_submit():
        if (form.username.data).lower() == 'admin' or (form.username.data).lower() == 'none':
            flash(f'Username not allowed. Please any other username.', 'danger')
            return redirect(url_for('signup'))
        elif (form.password.data != form.password2.data):
            flash(f'Password mismatch.', 'danger')

        else:
            try:
                hashed_password = bcrypt.generate_password_hash(
                    form.password.data, 12)
                new_user = User(username=form.username.data, password=hashed_password,
                                email=form.email.data, mobile=form.mobile.data)
                db.session.add(new_user)
                db.session.commit()
                flash(f'You have signed up successfully. Please login now.', 'success')
                return redirect(url_for('login'))
            except:
                # return render_template('Error.html', title="Integrity Voilation")
                flash(f'User with same details already exists.', 'danger')
                return redirect(url_for('signup'))

    return render_template('register.html', form=form)


# ----------------------------------------> Buying a book
@app.route('/order/<int:productid>')
def order(productid):
    if 'username' in session and session['username'] != 'None':
        try:
            productDetails = ProductsInfo.query.get_or_404(productid)
            print(productDetails.imageName)
            return render_template('order.html', productDetails=productDetails)
        except:
            #!!! Product not found Warning must show up
            return redirect('/')
    else:
        flash(f'To buy, you need to be signed up!', 'danger')
        return redirect('/login')


if __name__ == '__main__':
    app.run(debug=True)