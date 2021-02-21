# Our Flask application by EnQuire!
# Feel free to look through out Flask app,
# it is organized by sections (routes,etc).
# Also, it has notes labeled "Important"
# which give insight into the key ideas and 
# implementations of our project.
# Thanks for reading and hope you enjoy!

from flask import *
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_, and_, func, extract
from flask_session import Session
from datetime import datetime, date, time
from time import time
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
# Things to note: We spent time reading articles and watching videos on Flask back-end, 
# and learned much of what we know about Flask from EdX CS50W and online Flask blogs.

# SECTION: SETTING UP FLASK APP
app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)

Session(app)
app.secret_key = 'secret' # Changed for upload of code

login_manager = LoginManager()
login_manager.init_app(app)

# These are login handler functions
@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# This function runs when a session times out or a user is not logged in 
# and tries to access an login locked page.
@login_manager.unauthorized_handler
def unauthorized():
    # Tell the user that they are logged out.
    flash("Please log in to access the application or if your session timed out.")
    return redirect(url_for('login'))

# SECTION: DATABASE CLASSES
class Question(db.Model):
    # Our project currently utilizes, id, question and answer.
    # The other options are for improvements to the application.
    # Ex. Asker profiles and dates,etc
    id = db.Column(db.Integer, primary_key=True)
    date_time = db.Column(db.DateTime, nullable=False)
    question = db.Column(db.String, nullable=False)
    answer = db.Column(db.String)
    
    # backref to User
    asker = db.Column(db.String, db.ForeignKey(
        'user.username'), nullable=False)

    status = db.Column(db.Integer)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    # Note about role, the role of 1 is a student while the role of 2 is the ta.
    role = db.Column(db.Integer)
    questions_asked = db.relationship('Question', backref='user', lazy=True)

    # I want to make it a two way street, so the question will be able to "access" the User
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# SECTION: ROUTES
@app.route('/', methods=['GET'])
# This allows me to make sure the current user is logged in before accessing the page.
@login_required
def index():
    # Getting questions
    # Important: 
    # We wanted the student to only be able to see their own questions,
    # however, we did not want a student to see another student's question
    # or possibly even implementation of a question.
    # So, we have it so the query for students is only by username and the
    # ta can query all the questions by all students.
    questions = Question.query.filter_by(asker=current_user.username)
    ta = Question.query.all() 

    if current_user.role == 1:
        return render_template('index1.html', questions=questions)

    if current_user.role == 2:
        return render_template('index2.html', questions=ta)

# This route is updated so that depending on your role (only TAs can answer questions)
@app.route('/question/<int:question_id>', methods=['GET', 'POST'])
@login_required
def question(question_id):
    if request.method == 'POST':
        if 'ta_submit' in request.form:
            ans = request.form.get("notes") # Grab the answer
            update_question = Question.query.filter_by(id=question_id).first() # Grab the question
            update_question.answer = ans
            update_question.status = 1 # Question is done, information for further use in the future
            db.session.merge(update_question)
            db.session.commit()

    question_result = Question.query.filter_by(id=question_id).first()

    # In case the user tries to access random questions, they will get an error
    if question_result is None:
        return render_template("error.html")

    q = question_result.question
    a = question_result.answer

    if current_user.role == 1:
        return render_template("question1.html", question=q, answer=a)
    if current_user.role == 2:
        return render_template("question2.html", question=q, answer=a)

@app.route('/handle', methods=['POST'])
def handle():
    # I am going to collect the information from the forms
    if request.method == "POST":
        # This handles data collection from the search form
        if 'question_submit' in request.form:
            question_text = str(request.form.get("question_text"))
            now = datetime.now()
            q = Question(status=0,asker=current_user.username, question=question_text,answer="",date_time=now)
            db.session.add(q)
            db.session.commit()
            # Now that I have a list of all of the objects, return render template based on role type
            # student or ta
            return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        check_acc = request.form.get("username")
        check_pass = request.form.get("password")
        checker = User.query.filter_by(username=check_acc).first()
        
        if checker and checker.check_password(check_pass):
            login_user(checker)
            return redirect(url_for('home'))
        else:
            flash("Username or password are incorrect.")

    return render_template('login.html')

# Important: Once the user enters, we want them to enter a Test ID
# That way, we can make sure the student is a legitimate student.
# This route and demonstration of this part of the web application is
# a proof of concept and could be fully integrated later on.
@app.route('/home', methods=['GET','POST'])
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == "POST":
        reg_username = request.form.get("username")
        reg_password = request.form.get("password")
        reg_password2 = request.form.get("password2")

        if reg_password == reg_password2:
            x = User(username=reg_username,role=1)
            x.set_password(reg_password)
            db.session.add(x)
            db.session.commit()
            return redirect(url_for('login'))
        else:
            flash("Check that your passwords match")
            return render_template('register.html')
    return render_template('register.html')

# Want to let the user know that they have been logged out.
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out")
    return redirect(url_for('login'))
