from flask import Flask, render_template, request, redirect, url_for, flash, Response, session
from flask.templating import render_template_string
from flask_bootstrap import Bootstrap
from werkzeug.wrappers import response
from filters import datetimeformat, file_type # imported from the parallel file filter.py
from resource import get_bucket, get_bucket_list
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError 
from flask_bcrypt import Bcrypt # imported to encrypt the password in hash to store in database


app = Flask(__name__)
Bootstrap(app)
app.secret_key = 'secret' # its the secret key for the Flash messages for successfully uploaded File, It's not related with aws S3.
app.jinja_env.filters['datetimeformat'] = datetimeformat
app.jinja_env.filters['file_type'] = file_type
# -----------------------Database code ----------------------------------

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisissecretkey'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(20), nullable= False)
    password = db.Column(db.String(80), nullable= False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    password = StringField(validators=[InputRequired(), Length(
        min=4, max=50)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

def validate_username(self, username):      # it will check the database and then it will validate the user is exist or not 
    existing_user_username = User.query.filter_by(
    username=username.data).first()
    if existing_user_username:
        raise ValidationError ("The user name already exist, try another username")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    password = StringField(validators=[InputRequired(), Length(
        min=4, max=50)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

#----------------------------------------------- Database code ends here-----------------------------------------


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first() # Take the input from the user and store it in user
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data): # match the hash password stored in database
                login_user(user)    # If password matches then user gets login 
                return redirect( url_for('home'))  # Logged in Successfully to Dashboard.
    return render_template('login.html', form=form)                  # otherwise user will get redirected to login page again

# -----------------------user registration------------------------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data) # bcrypt generate the password in hash type
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect( url_for('login'))
    return render_template('register.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
#@login_required
def logout():
    logout_user()
    return redirect('login')


@app.route("/", methods=['GET', 'POST'])
#@login_required
def home():
    if request.method == 'POST':
        bucket = request.form['bucket']
        session['bucket'] = bucket
        return redirect(url_for('files'))
    else:
        buckets = get_bucket_list()
        return render_template("buckets.html", buckets=buckets)


@app.route('/files')
#@login_required
def files():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first() # Take the input from the user and store it in user
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data): # match the hash password stored in database
                login_user(user)    # If password matches then user gets login 
                return redirect( url_for('/'))  # Logged in Successfully to Dashboard.
    my_bucket = get_bucket()
    summaries = my_bucket.objects.all()
    return render_template('files.html', my_bucket=my_bucket, files=summaries)


@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']

    my_bucket = get_bucket()
    my_bucket.Object(file.filename).put(Body=file)
    
    flash('File Uploaded Successfully!')
    return redirect(url_for('files'))

@app.route('/delete', methods=['POST'])
def delete():
    key = request.form['key']
                                    #   s3_resource = boto3.resource('s3')
    my_bucket = get_bucket()        #s3_resource.Bucket(s3_bucket)
    my_bucket.Object(key).delete()

    flash('File deleted successfully!')
    return redirect(url_for('files'))

@app.route('/download', methods=['POST'])
def download():
    key = request.form['key']
                                    #   s3_resource = boto3.resource('s3')
    my_bucket = get_bucket()        # s3_resource.Bucket(s3_bucket)
    file_obj = my_bucket.Object(key).get()
  
    return Response(
        file_obj['Body'].read(),
        mimetype='text.plan',
        headers={"Content-Disposition": "attachment;filename={}".format(key)}
    )




#---------Error 404------------
@app.errorhandler(404)
def not_found(e):               # inbuilt function which takes error as parameter
  
  return redirect( url_for("404"))

if __name__ =="__main__":
  app.run(debug=True)