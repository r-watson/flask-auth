import flask
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'c915edbc90083ba213c6e2dfeebd3303dddec8af423f3e3e049756105ab8344d'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    # since the user_id is just the primary key of our user table, use it in the query for the user
    return User.query.get(int(user_id))

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

#Line below only required once, when creating DB. 
# db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        new_user = User(
            email=request.form.get("email"),
            password=generate_password_hash(
                request.form.get("password"),
                method="pbkdf2:sha256",
                salt_length=8
            ),
            name=request.form.get("name"),
        )
        if new_user.email:
            flash("You've already signed up with the email. Log in instead.")
            return redirect(url_for("login"))
        else:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for("secrets", name=new_user.name))
    return render_template("register.html")


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user_email = request.form.get('email')
        user_password = request.form.get('password')
        user_entered = User.query.filter_by(email=user_email).first()
        if user_entered:
            if check_password_hash(pwhash=user_entered.password, password=user_password):
                login_user(user_entered)
                return redirect(url_for('secrets', name=user_entered.name))
            else:
                flash("Password incorrect, please try again.")
                return redirect(url_for("login"))
        else:
            flash("That email does not exist, please try again.")
            return redirect(url_for("login"))
    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route('/download/<path:filename>')
@login_required
def download(filename):
    return send_from_directory("static", "files/" + filename, as_attachment=True)




if __name__ == "__main__":
    app.run(debug=True)
