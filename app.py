from flask import Flask, render_template, url_for, request, redirect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import base64

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db = SQLAlchemy(app)

# def render_picture(data):
#     '''
#     Function to render a picture!
#     '''
#     render_pic = base64.b64encode(data).decode('ascii') 
#     return render_pic


#--------------------------------> Table to store products
class ProductsInfo(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(200), nullable = False)
    description = db.Column(db.String(200), nullable = False)
    price = db.Column(db.Integer)
    link = db.Column(db.String(200), nullable = False)
    dateaddes = db.Column(db.DateTime, default = datetime.utcnow)
    thumbnailLink = db.Column(db.Text, nullable = True)

    def __repr__(self):
        return f'<Task : {self.id}>'


# ------------------------------> For user to view homepage
@app.route('/')
def homepage():
    return render_template('index.html')


# ------------------------------> For admin to view the products and delete them
@app.route('/admin', methods = ['GET', 'POST'])
def adminHome():
    
    # --------------> For admin to add new product
    if request.method == 'POST':

        # thumbnail = request.files['myfile']
        # data = thumbnail.read()
        # render_file = render_picture(data)
        
        newItem = ProductsInfo(
            name = request.form['productName'],
            description = request.form['productDescription'],
            price = request.form['productPrice'],
            link = request.form['productLink'],
            thumbnailLink = request.form['thumbnailLink']
            # thumbnail = render_file
        )
        try:
            db.session.add(newItem)
            db.session.commit()
            return redirect('/admin')
        except:
            return "There was an issue pushing to database"
    
    #--------------------> For admin to display all the stored products
    else:
        products = ProductsInfo.query.order_by(ProductsInfo.name).all()
        return render_template('Admin/adminPanel.html', products = products)


#-----------------------> For admin to delete a product
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
    

if __name__ == "__main__":
    app.run(debug = True)