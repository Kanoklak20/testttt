import json
from flask import (jsonify, render_template,
                  request, url_for, flash, redirect, session,url_for)
import requests
from sqlalchemy.sql import text
from app import app
from app import db
from werkzeug.security import generate_password_hash,check_password_hash
from werkzeug.urls import url_parse
from sqlalchemy.sql import text
from flask_login import login_user,login_required,logout_user
from app import login_manager
from app.models.authuser import UserInfo
from app.models.authuser import Reservations
from app.models.authuser import Tables
from flask_login import login_user, login_required, logout_user, current_user
import secrets
import string
from app import oauth
from flask import request
import os
from dotenv import load_dotenv
load_dotenv('.env.dev')
from sqlalchemy import and_
from datetime import datetime, timedelta
app.secret_key = os.urandom(24)

CLIENT_ID = '26GxenhhK15m5n2prKgjQYF33tT0uMjnwkC0Y2Z7'
CLIENT_SECRET = 'z3CTyqGN2sBj4wbeBPEYEu08TU0VVcAyXkWXwYFP'
REDIRECT_URI = 'http://localhost:5000/callback'
AUTHORIZATION_URL = 'https://auth.cmu.ac.th/oauth/authorize'
TOKEN_URL = 'https://mis-api.auth.cmu.ac.th/oauth/token'
RESOURCE_URL = 'https://mis-api.auth.cmu.ac.th/api/userinfo'

@app.route('/')
def home():
    return render_template('home.html')

def read_file(filename, mode="rt"):
    with open(filename, mode, encoding='utf-8') as fin:
        return fin.read()
    
def write_file(filename, contents, mode="wt"):
    with open(filename, mode, encoding="utf-8") as fout:
        fout.write(contents)

@app.route('/ticket')
@login_required
def ticket():
    reservation_id = session.get('reservation')
    reservation = Reservations.query.filter_by(id=reservation_id).first()
    if reservation:
        content = {
            'id': reservation.id,
            'date': reservation.date,
            'table_id': reservation.table.no,
            'owner_id': reservation.owner_id,
            'firstname': current_user.firstname,
            'lastname': current_user.lastname
        }
        return render_template('ticket.html',contents=[content])
    



@app.route('/db')
def db_connection():
    try:
        with db.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return '<h1>db works.</h1>'
    except Exception as e:
        return '<h1>db is broken.</h1>' + str(e)

@login_manager.user_loader
def load_user(user_id):
    return UserInfo.query.get(int(user_id))


@app.route('/login', methods=('GET', 'POST'))
def login():
    # Step 1: Redirect user to OAuth provider for authorization
    authorization_url = f'{AUTHORIZATION_URL}?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope=openid profile'
    return redirect(authorization_url)


@app.route('/callback')
def callback():
    # Step 3: Receive the authorization code from OAuth provider
    code = request.args.get('code')

    # Step 4: Exchange the authorization code for an access token
    token_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    token_response = requests.post(TOKEN_URL, data=token_data)
    token_json = token_response.json()
    access_token = token_json.get('access_token')

    # Step 5: Use access token to get protected resource (user info)
    headers = {'Authorization': f'Bearer {access_token}'}
    userinfo_response = requests.get(RESOURCE_URL, headers=headers)
    userinfo = userinfo_response.json()

    # Display the user info
    return f'User info: {userinfo}'

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/signup', methods=('GET', 'POST'))
def signup():
    if request.method == 'POST':
        result = request.form.to_dict()
        app.logger.debug(str(result))
 
        validated = True
        validated_dict = {}
        valid_keys = ['name', 'surname', 'email', 'user', 'phone', 'date', 'password', 'cfpassword']

        # validate the input
        for key in result:
            app.logger.debug(str(key)+": " + str(result[key]))
            # screen of unrelated inputs
            if key not in valid_keys:
                continue

            value = result[key].strip()
            if not value or value == 'undefined':
                validated = False
                break
            validated_dict[key] = value
            # code to validate and add user to database goes here
        app.logger.debug("validation done")
        if validated:
            app.logger.debug('validated dict: ' + str(validated_dict))
            name = validated_dict['name']
            surname = validated_dict['surname']
            email = validated_dict['email']
            user = validated_dict['user']
            phone = validated_dict['phone']
            date = validated_dict['date']
            password = validated_dict['password']
            cfpassword = validated_dict['cfpassword']

            # if this returns a user, then the email, username and phone number already exists in database
            same_email = UserInfo.query.filter_by(email=email).first()
            same_user = UserInfo.query.filter_by(username=user).first()
            same_phone = UserInfo.query.filter_by(phone_no=phone).first()

            if password != cfpassword:
                flash('Password not match')
                return redirect(url_for('signup'))

            # if same_email:
            #     # if a user is found, we want to redirect back to signup
            #     # page so user can try again
            #     flash('Email address already exists')
            #     return redirect(url_for('signup'))
            
            # if same_user:
            #     flash('Username already exists')
            #     return redirect(url_for('signup'))
            
            # if same_phone:
            #     flash('Phone number already exists')
            #     return redirect(url_for('signup'))
            
            # # # Additional validation for date (must be greater than 20 years ago)
            # if 'date' in validated_dict:
            #     birth_date = datetime.strptime(validated_dict['date'], '%Y-%m-%d')
            #     min_age_date = datetime.now() - timedelta(days=365 * 20)  # Calculate date 20 years ago
            #     if birth_date > min_age_date:
            #         validated = False
            #         flash('You must be at least 20 years old to sign up.')
            #         return redirect(url_for('signup'))

            # create a new user with the form data. Hash the password so
            # the plaintext version isn't saved.
            app.logger.debug("preparing to add")
            new_user = UserInfo(firstname=name, lastname=surname, email=email, phone_no=phone, birth=date,
                                password=generate_password_hash(password, method='sha256'), username=user,role='customer')
            # add the new user to the database
            db.session.add(new_user)
            db.session.commit()

        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/booking',methods=('GET','POST'))
@login_required
def booking():
    if request.method == 'POST':
        email=current_user.email
        firstname=current_user.firstname
        lastname=current_user.lastname
        phone=current_user.phone_no
        date = request.form['date']
        table = request.form.get('tickets')
        if not date:
            flash('Date is required!')
        elif not ticket :
            flash('Ticket is required!')
        else:
            exist = Reservations.query.filter_by(date = date).first()
            # print(exist)
            if exist and exist.table.no == table:
                flash('This reservation already exists!')
            else:
                seat = Tables(no=table,date=date,status=False)
                db.session.add(seat)
                db.session.commit()
                entry = Reservations(date=date,table_id=seat.id,owner_id=current_user.id)
                app.logger.debug(str(entry))
                db.session.add(entry)
                db.session.commit()
                session['reservation'] = entry.id
                return redirect(url_for('ticket'))

    return render_template('booking.html')


@app.route('/booked')
@login_required
def booked():
    return render_template('bookedtable.html')

@app.route("/booked-f1d")
@login_required
def booked_stored_contacts():
    raw_json = read_file('app/data/stored_contacts.json')
    contacts = json.loads(raw_json)

    return jsonify(contacts)


@app.route("/user", methods=('GET', 'POST'))
def user_settings():
    if request.method == 'POST':
        firstname = request.form.get('firstname')
        lastname = request.form.get('lastname')
        birth = request.form.get('birth')
        phone_no = request.form.get('phone_no')
        email = request.form.get('email')
        username = request.form.get('username')
        user = UserInfo.query.get(current_user.id)
        user.update(firstname=firstname,lastname=lastname,birth=birth,phone_no=phone_no,email=email,username=username)        
        
        db.session.commit()
        flash('User information updated successfully.')
        # Redirect to a profile page or display a success message
        return redirect(url_for("user_settings"))
    return render_template('user.html')



@app.route("/data")
def data():
    contacts = []
    db_contacts = Reservations.query.all()
    contacts = list(map(lambda x: x.to_dict(), db_contacts))
    app.logger.debug("DB Contacts: " + str(contacts))
    return jsonify(contacts)

@app.route('/booked/remove_contact', methods=('GET', 'POST'))
def lab10_remove_contacts():
    app.logger.debug("BOOKED - REMOVE")
    if request.method == 'POST':
        result = request.form.to_dict()
        id_ = result.get('id', '')
        try:
            contact = Reservations.query.get(id_)
            db.session.delete(contact)
            db.session.commit()
        except Exception as ex:
           app.logger.error(f"Error removing contact with id {id_}: {ex}")
           raise
    return data()