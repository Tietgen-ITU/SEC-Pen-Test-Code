import sqlite3, functools, os, time, random, sys
from flask import Flask, session, redirect, render_template, url_for, request
from password import hash_password, verify_password



### DATABASE FUNCTIONS ###

def connect_db():
    return sqlite3.connect(app.database)

def init_db():
    """Initializes the database with our great SQL schema"""
    conn = connect_db()
    db = conn.cursor()
    db.executescript("""
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS notes;

        CREATE TABLE notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assocUser INTEGER NOT NULL,
            dateWritten DATETIME NOT NULL,
            note TEXT NOT NULL,
            publicID INTEGER NOT NULL
        );

        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
        );
    """)

### APPLICATION SETUP ###
app = Flask(__name__)
app.database = "db.sqlite3"
app.secret_key = os.urandom(32)

### ADMINISTRATOR'S PANEL ###
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

@app.route("/")
def index():
    if not session.get('logged_in'):
        return render_template('index.html')
    else:
        return redirect(url_for('notes'))


@app.route("/notes/", methods=('GET', 'POST'))
@login_required
def notes():
    importerror=""
    #Posting a new note:
    if request.method == 'POST':
        if request.form['submit_button'] == 'add note':
            note = request.form['noteinput']
            db = connect_db()
            c = db.cursor()
            statement = """INSERT INTO notes(id,assocUser,dateWritten,note,publicID) VALUES(null, ?, ?, ?, ?);""" 
            print(statement)
            c.execute(statement,(session['userid'] , time.strftime('%Y-%m-%d %H:%M:%S') , note , random.randrange(1000000000, 9999999999)))
            db.commit()
            db.close()
        elif request.form['submit_button'] == 'import note':
            noteid = request.form['noteid']
            db = connect_db()
            c = db.cursor()
            statement = """SELECT * from NOTES where publicID = ?"""
            c.execute(statement, noteid)
            result = c.fetchall()
            if(len(result)>0):
                row = result[0]
                statement = """INSERT INTO notes(id,assocUser,dateWritten,note,publicID) VALUES(null, ?, ?, ?, ?);"""
                c.execute(statement,(session['userid'], row[2], row[3], row[4]))
            else:
                importerror="No such note with that ID!"
            db.commit()
            db.close()
    
    db = connect_db()
    c = db.cursor()
    statement = "SELECT * FROM notes WHERE assocUser = ?;"
    print(statement)
    c.execute(statement,(session['userid']))
    notes = c.fetchall()
    print(notes)
    
    return render_template('notes.html',notes=notes,importerror=importerror)


@app.route("/login/", methods=('GET', 'POST'))
def login():
    error = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = connect_db()
        c = db.cursor()
        statement = "SELECT * FROM users WHERE username = ?;"
        c.execute(statement, username)
        result = c.fetchall()

        #TODO: maybe do something here? write better logic 
        if len(result) > 0:
            user = result[0]

            if not verify_password(password, derived_key = user[2], salt = user[3]):
                render_template('login.html', error = "Wrong password!")

            session.clear()
            session['logged_in'] = True
            session['userid'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('index'))
        else:
            error = "Wrong username or password!"
    return render_template('login.html',error=error)


@app.route("/register/", methods=('GET', 'POST'))
def register():
    errored = False
    usererror = ""
    passworderror = ""
    if request.method == 'POST':
        username = request.form['username']
        derived_key, salt = hash_password(request.form['password'])

        db = connect_db()
        c = db.cursor()
        user_statement = """SELECT * FROM users WHERE username = ?;"""

        c.execute(user_statement, username)
        if(len(c.fetchall())>0):
            errored = True
            usererror = "That username is already in use by someone else!"

        if (not errored):
            statement = """
                INSERT INTO users(id, username, password_hash, salt)
                VALUES(null, ?, ?, ?);
            """
            c.execute(statement, (username, derived_key, salt))
            db.commit()
            db.close()
            return f"""<html>
                        <head>
                            <meta http-equiv="refresh" content="2;url=/" />
                        </head>
                        <body>
                            <h1>SUCCESS!!! Redirecting in 2 seconds...</h1>
                        </body>
                        </html>
                        """
        
        db.commit()
        db.close()
    return render_template('register.html',usererror=usererror,passworderror=passworderror)


@app.route("/logout/")
@login_required
def logout():
    """Logout: clears the session"""
    session.clear()
    return redirect(url_for('index'))

if __name__ == "__main__":
    #create database if it doesn't exist yet
    if not os.path.exists(app.database):
        init_db()
    runport = 443
    if(len(sys.argv)==2):
        runport = sys.argv[1]
    try:
        app.run(host='0.0.0.0', port=runport, ssl_context=('certs/cert.pem', 'certs/key.pem')) # runs on machine ip address to make it visible on netowrk
    except:
        print("Something went wrong. the usage of the server is either")
        print("'python3 app.py' (to start on port 80)")
        print("or")
        print("'sudo python3 app.py 80' (to run on any other port)")
