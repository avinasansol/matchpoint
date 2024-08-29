import re
from flask import Flask, render_template, request, redirect, session, url_for, flash
import mysql.connector
from flask_bcrypt import Bcrypt, check_password_hash
from MySQLdb import IntegrityError  # Import IntegrityError
from datetime import timedelta

app = Flask(__name__)
app.secret_key = 'ydururhhduwojdkdjfjey'
app.config['SESSION_COOKIE_DURATION'] = timedelta(days=30)  # Set the duration as per your requirement
app.config['SESSION_TYPE'] = 'filesystem'  # or 'redis', 'memcached', etc. depending on your needs
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

bcrypt = Bcrypt(app)

# Database configuration
db_config = {
    'host': ${HOST},
    'user': ${USER},
    'password': ${password},
    'database': ${DB}
}

@app.route('/logout')
def logout():
    # Remove all session variables
    session.clear()
    # Redirect to the login page
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
def login():
    if 'loggedin' in session:
        return redirect('/user-dashboard')

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=False)

        # Check if the provided password matches the Initial_Pass
        cursor.execute('SELECT `User_Id`, `Name`, `User_Type` FROM `user` WHERE `Phone` = %s AND `Initial_Pass` = %s', (email, password))
        user_initial_pass = cursor.fetchone()

        # Check if the provided password matches the regular Password
        cursor.execute('SELECT `User_Id`, `Name`, `User_Type`, `Password` FROM `user` WHERE `Phone` = %s', (email,))
        user_regular_pass = cursor.fetchone()

        if user_initial_pass:
            session['loggedin'] = True
            session['user_id'] = user_initial_pass[0]
            session['user_name'] = user_initial_pass[1].split()[0]
            session['user_type'] = user_initial_pass[2]
            return render_template('account_settings.html', temppass="temppass")  # Redirect to account settings

        elif user_regular_pass and check_password_hash(user_regular_pass[3], password):
            session['loggedin'] = True
            session['user_id'] = user_regular_pass[0]
            session['user_name'] = user_regular_pass[1].split()[0]
            session['user_type'] = user_regular_pass[2]
            redirectLink = request.form.getlist('rlink')
            if redirectLink:
                return redirect('/'+str(redirectLink[0]))
            else:
                return redirect('/user-dashboard')   # Redirect to user dashboard

        else:
            message = 'Incorrect phone no/password!'
            return render_template('login.html', message=message)

    return render_template('login.html')

@app.route('/account-settings', methods=['GET', 'POST'])
def account_settings():
    if 'loggedin' in session:
        if request.method == 'POST':
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']

            # Validate password complexity
            password_regex = r"^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$"
            if not re.match(password_regex, new_password):
                return render_template('account_settings.html', message='Password does not meet complexity requirements.')

            if new_password != confirm_password:
                return render_template('account_settings.html', message='Passwords do not match.')

            # Hash the password
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

            # Update hashed password in the database
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor(dictionary=False)
            user_id = session['user_id']
            cursor.execute('UPDATE `user` SET `Initial_Pass` = NULL, `Password` = %s WHERE `User_Id` = %s', (hashed_password, user_id))
            conn.commit()
            return redirect('/')
        else:
            return render_template('account_settings.html')

    return redirect('/')

@app.route('/admin-dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    # Check if user is logged in and is an admin
    if 'loggedin' in session and session['user_type'] == 'A':

        # Render the admin dashboard template
        return render_template('admin_dashboard.html')
    else:
        # If user is not logged in or is not an admin, redirect to login page
        return redirect(url_for('login'))

@app.route('/add-user', methods=['GET', 'POST'])
def add_user():
    # Redirect to login page if user is not logged in or is not an admin
    if 'loggedin' not in session or session['user_type'] != 'A':
        return redirect(url_for('login'))

    if request.method == 'POST':

        email = request.form['email']
        initial_pass = request.form['initial_pass']
        name = request.form['name']
        user_type = request.form['user_type']
        updated_by = session.get('user_id')  # Assuming the current user ID is stored in session

        if not email or not initial_pass or not name or not user_type:
            flash('Please fill out all the fields.', 'error')
            return render_template('add_user.html', email=email, initial_pass=initial_pass, name=name, user_type=user_type)

        # Perform email format validation using regular expression
        if not email.isdigit():
            flash('Invalid phone no format.', 'error')
            return render_template('add_user.html', email=email, initial_pass=initial_pass, name=name, user_type=user_type)

        if user_type not in ('A', 'U'):
            flash('Invalid user type. User type must be either "A" for admin or "U" for normal user.', 'error')
            return render_template('add_user.html', email=email, initial_pass=initial_pass, name=name, user_type=user_type)

        if len(email) > 10:
            flash('Phone No is too long. Maximum 10 characters allowed.', 'error')
            return render_template('add_user.html', email=email, initial_pass=initial_pass, name=name, user_type=user_type)

        if len(initial_pass) > 15:
            flash('Initial password is too long. Maximum 15 characters allowed.', 'error')
            return render_template('add_user.html', email=email, initial_pass=initial_pass, name=name, user_type=user_type)

        if len(name) > 58:
            flash('Name is too long. Maximum 58 characters allowed.', 'error')
            return render_template('add_user.html', email=email, initial_pass=initial_pass, name=name, user_type=user_type)

        # Insert data into the user table
        try:
            # Insert data into the user table
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor(dictionary=False)
            cursor.execute('INSERT INTO `user` (`User_Type`, `Phone`, `Initial_Pass`, `Name`, `Updated_By`) VALUES (%s, %s, %s, %s, %s)',
                           (user_type, email, initial_pass, name, updated_by))
            conn.commit()
            cursor.close()

            flash('User added successfully.', 'success')
            return render_template('add_user.html')
        except IntegrityError:
            flash('Failed to add user. Email already exists.', 'error')
            if 'cursor' in locals():  # Close cursor in case of error
                cursor.close()
            return render_template('add_user.html', email=email, initial_pass=initial_pass, name=name, user_type=user_type)
        except Exception as e:  # Catch other exceptions
            flash(f'Failed to add user: {str(e)}', 'error')  # Display a general error message
            if 'cursor' in locals():  # Close cursor in case of error
                cursor.close()
            return render_template('add_user.html', email=email, initial_pass=initial_pass, name=name, user_type=user_type)

    else:
        # Handle GET request method
        return render_template('add_user.html')

@app.route('/add-series', methods=['GET', 'POST'])
def add_series():
    # Redirect to login page if user is not logged in or is not an admin
    if 'loggedin' not in session or session['user_type'] != 'A':
        return redirect(url_for('login'))

    if request.method == 'POST':

        series_name = request.form['series_name']
        updated_by = session.get('user_id')  # Assuming the current user ID is stored in session

        if not series_name:
            flash('Please provide a series name.', 'error')
            return render_template('add_series.html', series_name=series_name)

        if len(series_name) > 58:
            flash('Series name is too long. Maximum 58 characters allowed.', 'error')
            return render_template('add_series.html', series_name=series_name)

        # Insert data into the series table
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=False)
        try:
            cursor.execute('INSERT INTO `series` (`Series_Name`, `Updated_By`) VALUES (%s, %s)',
                           (series_name, updated_by))
            conn.commit()
            flash('Series added successfully.', 'success')
            return render_template('add_series.html')
        except Exception as e:
            flash('An error occurred while adding the series.', 'error')
            return render_template('add_series.html', series_name=series_name)

    else:
        # Handle GET request method
        return render_template('add_series.html')

@app.route('/add-team', methods=['GET', 'POST'])
def add_team():
    # Redirect to login page if user is not logged in or is not an admin
    if 'loggedin' not in session or session['user_type'] != 'A':
        return redirect(url_for('login'))

    if request.method == 'POST':

        team_name = request.form['team_name']
        team_short_name = request.form['team_short_name']
        updated_by = session.get('user_id')  # Assuming the current user ID is stored in session

        if not team_name or not team_short_name:
            flash('Please provide both team name and short name.', 'error')
            return render_template('add_team.html', team_name=team_name, team_short_name=team_short_name)

        if len(team_name) > 50:
            flash('Team name is too long. Maximum 50 characters allowed.', 'error')
            return render_template('add_team.html', team_name=team_name, team_short_name=team_short_name)

        if len(team_short_name) > 3:
            flash('Team short name is too long. Maximum 3 characters allowed.', 'error')
            return render_template('add_team.html', team_name=team_name, team_short_name=team_short_name)

        # Insert data into the team table
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=False)
        try:
            cursor.execute('INSERT INTO `team` (`Team_Name`, `Team_Short_Name`, `Updated_By`) VALUES (%s, %s, %s)',
                           (team_name, team_short_name, updated_by))
            conn.commit()
            flash('Team added successfully.', 'success')
            return render_template('add_team.html')
        except Exception as e:
            flash('An error occurred while adding the team.', 'error')
            return render_template('add_team.html', team_name=team_name, team_short_name=team_short_name)

    else:
        # Handle GET request method
        return render_template('add_team.html')

from datetime import datetime, timedelta

@app.route('/add-match', methods=['GET', 'POST'])
def add_match():
    # Redirect to login page if user is not logged in or is not an admin
    if 'loggedin' not in session or session['user_type'] != 'A':
        return redirect(url_for('login'))

    # Fetch series list from the database
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=False)
    cursor.execute('SELECT Series_Id, Series_Name FROM series ORDER BY Updated_TS DESC')
    series_list = cursor.fetchall()

    # Fetch team list from the database
    cursor.execute('SELECT Team_Id, Team_Name FROM team')
    team_list = cursor.fetchall()
    cursor.close()

    if request.method == 'POST':

        # Retrieve form data
        series_id = request.form['series_id']
        date_time = request.form['date_time']
        place = request.form['place']
        team_1 = request.form['team_1']
        team_2 = request.form['team_2']
        updated_by = session.get('user_id')  # Assuming the current user ID is stored in session

        # Store form data to return in case of error
        form_data = {
            'date_time': date_time,
            'place': place
        }

        # Check if series_id exists in series_list
        series_found = False
        for series in series_list:
            if str(series[0]) == series_id:
                form_data['series_id'] = series[0]
                form_data['series_name'] = series[1]
                series_found = True
                break

        # Check if teams exists in team_list
        team_1_found = False
        team_2_found = False
        for team in team_list:
            if str(team[0]) == team_1:
                form_data['team_1'] = team[0]
                form_data['team_1_name'] = team[1]
                team_1_found = True
            if str(team[0]) == team_2:
                form_data['team_2'] = team[0]
                form_data['team_2_name'] = team[1]
                team_2_found = True

        # Check if team_1 and team_2 are different
        if team_1 == team_2:
            flash('Team 1 and Team 2 must be different.', 'error')
            return render_template('add_match.html', series_list=series_list, team_list=team_list, **form_data)

        # Check if place is longer than 15 characters
        if len(place) > 15:
            flash('Place must not be longer than 15 characters.', 'error')
            return render_template('add_match.html', series_list=series_list, team_list=team_list, **form_data)

        # Validate date_time
        try:
            date_time = datetime.strptime(date_time, '%Y-%m-%dT%H:%M')
            if date_time < datetime.now() or date_time > datetime.now() + timedelta(days=365):
                raise ValueError
        except ValueError:
            flash('Invalid date-time. Please provide a valid date-time in the future within the next year.', 'error')
            return render_template('add_match.html', series_list=series_list, team_list=team_list, **form_data)

        # Check if a match between the same two teams already exists on the same date
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=False)
        cursor.execute('SELECT COUNT(*) FROM `match` WHERE (Team_1 = %s AND Team_2 = %s OR Team_1 = %s AND Team_2 = %s) AND DATE(Date_Time) = %s',
                       (team_1, team_2, team_2, team_1, date_time.date()))
        existing_matches_count = cursor.fetchone()[0]
        cursor.close()

        if existing_matches_count > 0:
            flash('A match between the same two teams already exists on the same date.', 'error')
            return render_template('add_match.html', series_list=series_list, team_list=team_list, **form_data)

        if team_1_found and team_2_found:  # Both teams exist
            if series_found:
                # Insert data into the match table
                conn = mysql.connector.connect(**db_config)
                cursor = conn.cursor(dictionary=False)
                try:
                    cursor.execute('INSERT INTO `match` (`Series_Id`, `Date_Time`, `Place`, `Team_1`, `Team_2`, `Updated_By`) VALUES (%s, %s, %s, %s, %s, %s)',
                                   (series_id, date_time, place, team_1, team_2, updated_by))
                    conn.commit()
                    flash('Match added successfully.', 'success')
                    return render_template('add_match.html', series_list=series_list, team_list=team_list)
                except Exception as e:
                    flash('An error occurred while adding the match.', 'error')
                    return render_template('add_match.html', series_list=series_list, team_list=team_list, **form_data)
                finally:
                    cursor.close()
            else:
                flash('Invalid Series.', 'error')
                return render_template('add_match.html', series_list=series_list, team_list=team_list, **form_data)
        else:
            flash('One or both teams are invalid.', 'error')
            return render_template('add_match.html', series_list=series_list, team_list=team_list, **form_data)

        return render_template('add_match.html', series_list=series_list, team_list=team_list)
    else:
        # Handle GET request method
        return render_template('add_match.html', series_list=series_list, team_list=team_list)

@app.route('/add-user-to-series', methods=['GET', 'POST'])
def add_user_to_series():
    # Redirect to login page if user is not logged in or is not an admin
    if 'loggedin' not in session or session['user_type'] != 'A':
        return redirect(url_for('login'))

    # Fetch series list from the database
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=False)
    cursor.execute('SELECT Series_Id, Series_Name FROM series ORDER BY Updated_TS DESC')
    series_list = cursor.fetchall()
    cursor.close()

    if request.method == 'POST':

        useries_id = request.form['useries_id']
        # Check if useries_id exists in series_list
        useries_found = False
        for series in series_list:
            if str(series[0]) == useries_id:
                useries_id = series[0]
                useries_name = series[1]
                useries_found = True
                break
        if not useries_found:
            flash('Invalid Series.', 'error')
            return render_template('add_user_to_series.html', series_list=series_list)
        else:
            selected_users = request.form.getlist('users')
            updated_by = session.get('user_id')
            update = request.form.get('update')

            # Fetch user list from the database
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor(dictionary=False)
            query = """
            SELECT u.User_Id, u.Name, su.Series_Id
            FROM user u
            LEFT OUTER JOIN series_user su ON u.User_Id = su.User_Id AND su.Series_Id = %s;
            """

            if update == 'yes':
                cursor.execute(query, (useries_id,))
                user_list = cursor.fetchall()
                for userid in user_list:
                    if userid[2]:
                        to_be_deleted = True
                        if selected_users:
                            for user in selected_users:
                                if str(user) == str(userid[0]):
                                    to_be_deleted = False
                        if to_be_deleted:
                            # Delete data into the series_user table
                            try:
                                cursor.execute('DELETE FROM `series_user` WHERE `Series_Id` = %s AND `User_Id` = %s',
                                               (useries_id, userid[0]))
                                conn.commit()
                                flash('User deleted successfully from the series.', 'success')
                            except Exception as e:
                                flash('An error occurred while deleting a user.', 'error')
                                return render_template('add_user_to_series.html', series_list=series_list)
                    else:
                        if selected_users:
                            for user in selected_users:
                                if str(user) == str(userid[0]):
                                    # Insert data into the series_user table
                                    try:
                                        cursor.execute('INSERT INTO `series_user` (`Series_Id`, `User_Id`, `Updated_By`) VALUES (%s, %s, %s)',
                                                       (useries_id, user, updated_by))
                                        conn.commit()
                                        flash('User added successfully to the series.', 'success')
                                    except Exception as e:
                                        flash('An error occurred while adding a user.', 'error')
                                        return render_template('add_user_to_series.html', series_list=series_list)

            cursor.execute(query, (useries_id,))
            user_list = cursor.fetchall()
            cursor.close()
            return render_template('add_user_to_series.html', useries_id=useries_id, useries_name=useries_name, user_list=user_list, series_list=series_list)

    else:
        # Handle GET request method
        return render_template('add_user_to_series.html', series_list=series_list)

@app.route('/select-match-winner', methods=['GET', 'POST'])
def select_match_winner():
    # Redirect to login page if user is not logged in or is not an admin
    if 'loggedin' not in session or session['user_type'] != 'A':
        return redirect(url_for('login'))

    current_time = get_current_ist_time()
    # Fetch match list from the database
    match_fetch_query = "SELECT m.Series_Id, s.Series_Name, m.Match_Id, t1.Team_Id AS Team_1_Id, t1.Team_Name AS Team_1_Name,  t1.Team_Short_Name AS Team_1_SN, t2.Team_Id AS Team_2_Id, t2.Team_Name AS Team_2_Name, t2.Team_Short_Name AS Team_2_SN, DATE_FORMAT(m.Date_Time, '%d-%b-%y') AS Match_Date, m.Place FROM `match` m JOIN `series` s ON m.Series_Id = s.Series_Id JOIN `team` t1 ON m.Team_1 = t1.Team_Id JOIN `team` t2 ON m.Team_2 = t2.Team_Id WHERE m.Winner IS NULL AND m.Date_Time < '"+str(current_time)+"' ORDER BY m.Date_Time ASC"
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=False)
    cursor.execute(match_fetch_query)
    match_list = cursor.fetchall()
    cursor.close()

    if request.method == 'POST':

        match_id = request.form['match_id']
        # Check if match_id exists in match_list
        match_found = False
        for match in match_list:
            if str(match[2]) == match_id:
                match_id = match[2]
                match_series_id = str(match[0])
                match_series = str(match[1])
                match_date = str(match[9])
                match_place = str(match[10])
                match_teamvsteam = str(match[5])+" Vs "+str(match[8])
                match_team1_id = str(match[3])
                match_team2_id = str(match[6])
                match_team1_nm = str(match[4])
                match_team2_nm = str(match[7])
                match_found = True
                break
        if not match_found:
            flash('Invalid Match.', 'error')
            return render_template('select_match_winner.html', match_list=match_list)
        else:
            updated_by = session.get('user_id')
            update = request.form.get('update')
            if update == 'yes':
                winner_id = request.form.get('winner_id')
                winner_found = False
                for match in match_list:
                    if str(match[3]) == winner_id:
                        winner_found = True
                    elif str(match[6]) == winner_id:
                        winner_found = True

                if not winner_found:
                    if winner_id == "0":
                        winner_found = True
                    else:
                        flash('Invalid Winner.', 'error')

                if winner_found:
                    winner = 0
                    if winner_id == match_team1_id:
                        winner = 1
                    if winner_id == match_team2_id:
                        winner = 2
                    conn = mysql.connector.connect(**db_config)
                    cursor = conn.cursor(dictionary=False)

                    cursor.execute("UPDATE `match` SET `Winner` = %s, `Updated_By` = %s, `Updated_TS` = current_timestamp()  WHERE `Match_Id` = %s", (str(winner), updated_by, match_id))

                    if winner == 0:

                        default_points = 0
                        positive_points = 0
                        negative_points = 0

                        # Fetch user and poll for the match
                        cursor.execute("SELECT su.User_Id, su.Points, p.Poll_Team FROM series_user su LEFT OUTER JOIN poll p ON su.User_Id = p.User_Id AND p.Match_Id = %s WHERE su.Series_Id = %s", (match_id,match_series_id))
                        result = cursor.fetchall()
                        for row in result:

                            row_user_id = row[0]
                            row_user_points = row[1]
                            row_poll_team = row[2]
                            updated_points = 0
                            if row_user_points:
                                updated_points = int(row_user_points)

                            if str(row_poll_team) == str(winner_id):
                                updated_points = updated_points + positive_points
                            else:
                                updated_points = updated_points + negative_points

                            cursor.execute("SELECT p.Poll_Team FROM poll p WHERE p.User_Id = %s AND p.Match_Id = %s", (row_user_id,match_id))
                            poll_exists = cursor.fetchone()
                            if poll_exists:
                                if str(row_poll_team) == str(winner_id):
                                    cursor.execute("UPDATE poll SET Points = %s WHERE User_Id = %s AND Match_Id = %s", (positive_points,row_user_id,match_id))
                                else:
                                    cursor.execute("UPDATE poll SET Points = %s WHERE User_Id = %s AND Match_Id = %s", (negative_points,row_user_id,match_id))
                            else:
                                cursor.execute("INSERT INTO poll (Match_Id, User_Id, Points, Updated_By) VALUES (%s,%s,%s,%s)", (match_id,row_user_id,negative_points,updated_by))

                    else:

                        # Fetch user count for the series
                        series_user_count = 0
                        cursor.execute("SELECT COUNT(User_Id) AS User_Count FROM `series_user` WHERE Series_Id = %s", (match_series_id,))
                        qresult = cursor.fetchone()
                        series_user_count = qresult[0]

                        # Fetch correct poll count for the match
                        correct_poll_count = 0
                        cursor.execute("SELECT COUNT(Poll_Team) FROM `poll` WHERE Match_Id = %s AND Poll_Team = %s", (match_id,winner_id))
                        qresult = cursor.fetchone()
                        correct_poll_count = qresult[0]

                        default_points = 500
                        positive_points = 0
                        if correct_poll_count > 0:
                            positive_points = round((series_user_count-correct_poll_count)* default_points /correct_poll_count)
                        negative_points = -1 * default_points

                        # Fetch user and poll for the match
                        cursor.execute("SELECT su.User_Id, su.Points, p.Poll_Team FROM series_user su LEFT OUTER JOIN poll p ON su.User_Id = p.User_Id AND p.Match_Id = %s WHERE su.Series_Id = %s", (match_id,match_series_id))
                        result = cursor.fetchall()
                        for row in result:
                            row_user_id = row[0]
                            row_user_points = row[1]
                            row_poll_team = row[2]
                            updated_points = 0
                            if row_user_points:
                                updated_points = int(row_user_points)
                            if str(row_poll_team) == str(winner_id):
                                updated_points = updated_points + positive_points
                            else:
                                updated_points = updated_points + negative_points
                            cursor.execute('UPDATE `series_user` SET `Points` = %s  WHERE Series_Id = %s AND User_Id = %s', (updated_points, match_series_id, row_user_id))

                            cursor.execute("SELECT p.Poll_Team FROM poll p WHERE p.User_Id = %s AND p.Match_Id = %s", (row_user_id,match_id))
                            poll_exists = cursor.fetchone()
                            if poll_exists:
                                if str(row_poll_team) == str(winner_id):
                                    cursor.execute("UPDATE poll SET Points = %s WHERE User_Id = %s AND Match_Id = %s", (positive_points,row_user_id,match_id))
                                else:
                                    cursor.execute("UPDATE poll SET Points = %s WHERE User_Id = %s AND Match_Id = %s", (negative_points,row_user_id,match_id))
                            else:
                                cursor.execute("INSERT INTO poll (Match_Id, User_Id, Points, Updated_By) VALUES (%s,%s,%s,%s)", (match_id,row_user_id,negative_points,updated_by))

                    conn.commit()
                    flash('Winner Updated for the match.', 'success')
                    cursor.execute(match_fetch_query)
                    match_list = cursor.fetchall()
                    cursor.close()
                    return render_template('select_match_winner.html', match_list=match_list)

            return render_template('select_match_winner.html', match_id=match_id, match_series=match_series, match_date=match_date, match_teamvsteam=match_teamvsteam, match_team1_id=match_team1_id, match_team2_id=match_team2_id, match_team1_nm=match_team1_nm, match_team2_nm=match_team2_nm, match_place=match_place, match_list=match_list)

    else:
        # Handle GET request method
        return render_template('select_match_winner.html', match_list=match_list)

@app.route('/user-dashboard', methods=['GET', 'POST'])
def user_dashboard():
    # Redirect to login page if user is not logged in
    if 'loggedin' not in session:
        return redirect('/')
    match_status_dict = None
    # Fetch series data from the database
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor(dictionary=False)
    cur.execute("SELECT Series_Id, Series_Name FROM series ORDER BY Updated_TS DESC")
    series_data = cur.fetchall()
    cur.close()
    poll_match_id = None
    series_found = False
    if request.method == 'POST':
        series_id = request.form['series_id']
        for series in series_data:
            if str(series[0]) == series_id:
                series_found = True
                series_id = series[0]
                series_name = series[1]
    if not series_found:
        # Fetch one series data from the database
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor(dictionary=False)
        cur.execute("SELECT Series_Id, Series_Name FROM series ORDER BY Updated_TS DESC LIMIT 0,1")
        one_series_data = cur.fetchone()
        cur.close()
        if one_series_data:
            series_found = True
            series_id = one_series_data[0]
            series_name = one_series_data[1]
        else:
            series_id = None
            series_name = None
    else:
        match_id = request.form.get('match_id')
        poll = request.form.get('poll')
        correct_poll = None
        if match_id and poll:
            # Check if the poll provided matches with team_1 or team_2
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor(dictionary=False)
            current_time = get_current_ist_time()
            cursor.execute('SELECT Match_Id FROM `match` WHERE Date_Time > %s AND Match_Id = %s AND (Team_1 = %s OR Team_2 = %s)', (current_time, match_id, poll, poll))
            correct_poll = cursor.fetchone()
            cursor.close()
            if not correct_poll:
                # Display "invalid match id" message
                return render_template('invalid_request.html')
        if correct_poll:
            user_id = session.get('user_id')
            poll_match_id = match_id
            poll_present = None
            # Check if the poll is already present
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor(dictionary=False)
            cursor.execute('SELECT Poll_Team FROM `poll` WHERE Match_Id = %s AND User_Id = %s', (match_id, user_id))
            poll_present = cursor.fetchone()
            cursor.close()
            if poll_present:
                # Update the data in the poll table
                conn = mysql.connector.connect(**db_config)
                cursor = conn.cursor(dictionary=False)
                try:
                    cursor.execute('UPDATE `poll` SET `Poll_Team` = %s, `Updated_By`= %s WHERE `Match_Id` = %s AND `User_Id` = %s',(poll, user_id, match_id, user_id))
                    conn.commit()
                    flash('Poll updated successfully.', 'success')
                except Exception as e:
                    flash('An error occurred while updating the poll.', 'error')
                finally:
                    cursor.close()
            else:
                # Insert data into the poll table
                conn = mysql.connector.connect(**db_config)
                cursor = conn.cursor(dictionary=False)
                try:
                    cursor.execute('INSERT INTO `poll` (`Match_Id`, `Poll_Team`, `User_Id`, `Updated_By`) VALUES (%s, %s, %s, %s)',(match_id, poll, user_id, user_id))
                    conn.commit()
                    flash('Poll updated successfully.', 'success')
                except Exception as e:
                    flash('An error occurred while updating the poll.', 'error')
                finally:
                    cursor.close()
    if series_found:
        user_id = session.get('user_id')
        # Fetch match data from the database
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=False)
        # Execute the SQL query
        query = """
            SELECT
                m.Match_Id,
                DATE_FORMAT(m.Date_Time, '%d-%b-%y') AS Match_Date,
                TIME_FORMAT(m.Date_Time, '%h:%i %p') AS Match_Time,
                m.Place,
                t1.Team_Id AS Team_1_Id,
                t1.Team_Name AS Team_1_Name,
                t1.Team_Short_Name AS Team_1_SN,
                t2.Team_Id AS Team_2_Id,
                t2.Team_Name AS Team_2_Name,
                t2.Team_Short_Name AS Team_2_SN,
                m.Winner,
                p.Poll_Team,
                m.Date_Time
            FROM
                `match` m
            INNER JOIN
                `series` s ON m.Series_Id = s.Series_Id
            INNER JOIN
                `team` t1 ON m.Team_1 = t1.Team_Id
            INNER JOIN
                `team` t2 ON m.Team_2 = t2.Team_Id
            LEFT OUTER JOIN
                `poll` p ON m.Match_Id = p.Match_Id AND p.User_Id = %s
            WHERE
                m.Series_Id = %s
            AND
                m.Date_Time < %s
            ORDER BY
                CASE
                    WHEN m.Winner IS NULL THEN 0
                    ELSE 1
                END ASC,
                CASE
                    WHEN m.Winner IS NULL THEN m.Date_Time
                    ELSE NULL
                END ASC,
                CASE
                    WHEN m.Winner IS NOT NULL THEN m.Date_Time
                    ELSE NULL
                END DESC
        """

        current_time_plus_1_days = get_current_ist_time(30)
        cursor.execute(query, (user_id, series_id,current_time_plus_1_days))
        matches = cursor.fetchall()
        cursor.close()
        current_time = get_current_ist_time()

        match_status_dict = {}
        for match in matches:
            match_dict = {
                'Match_Id': match[0],
                'Match_Date': match[1],
                'Match_Time': match[2],
                'Place': match[3],
                'Team_1_Id': match[4],
                'Team_1_Name': match[5],
                'Team_1_SN': match[6],
                'Team_2_Id': match[7],
                'Team_2_Name': match[8],
                'Team_2_SN': match[9],
                'Winner': match[10],
                'Poll_Team': match[11],
                'Date_Time': match[12]
            }

            if current_time < match[12]:
                match_dict['Status'] = 'NS'  # Not Started
            else:
                match_dict['Status'] = 'AS'  # Already Started

            match_status_dict[match[0]] = match_dict

    user_id = session.get('user_id')
    series_access = "No"
    user_score = None
    user_rank = None
    series_access_present = None
    # Check if the user has access to the series
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=False)
    cursor.execute('SELECT Points FROM `series_user` WHERE Series_Id = %s AND User_Id = %s', (series_id, user_id))
    series_access_present = cursor.fetchone()
    cursor.close()
    if series_access_present:
        series_access = "Yes"
        # Get the user score and rank
        user_score = series_access_present[0]
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=False)
        cursor.execute('SELECT (SELECT COUNT(*) + 1 FROM series_user AS su2 WHERE su2.Points > su1.Points AND su2.Series_Id = su1.Series_Id) AS `Rank` FROM series_user AS su1 WHERE Series_Id = %s AND User_Id = %s', (series_id, user_id))
        rank_result = cursor.fetchone()
        cursor.close()
        if rank_result:
            user_rank = rank_result[0]

    user_score_rank_list = None
    if series_found:
        # Get the score and rank for all
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=False)
        cursor.execute('SELECT u.Name, (SELECT COUNT(*) + 1 FROM series_user AS su2 WHERE COALESCE(su2.Points, 0) > COALESCE(su1.Points, 0) AND su2.Series_Id = su1.Series_Id) AS `Rank`, COALESCE(su1.Points, 0) AS Points FROM series_user AS su1 JOIN user AS u ON su1.User_Id = u.User_Id WHERE su1.Series_Id = %s ORDER BY `Rank` ASC', (series_id,))
        user_score_rank_list = cursor.fetchall()
        cursor.close()

    if match_status_dict:
        return render_template('user-dashboard.html', series_data=series_data, series_id=series_id, series_name=series_name, series_access=series_access, matches=match_status_dict, user_score=user_score, user_rank=user_rank, user_score_rank_list=user_score_rank_list, poll_match_id=poll_match_id)
    else:
        return render_template('user-dashboard.html', series_data=series_data, series_id=series_id, series_name=series_name, series_access=series_access, user_score=user_score, user_rank=user_rank, user_score_rank_list=user_score_rank_list, poll_match_id=poll_match_id)

# Function to get current IST time with optional days offset
def get_current_ist_time(days_offset=0):
    current_utc_time = datetime.utcnow()
    ist_offset = timedelta(hours=5, minutes=30)  # UTC+5:30 for IST
    current_ist_time = current_utc_time + ist_offset + timedelta(days=days_offset)
    return current_ist_time

@app.route('/match', methods=['GET', 'POST', 'REQUEST'])
def match():
    # Redirect to login page if user is not logged in
    #if 'loggedin' not in session:
    #    return redirect('/')
    valid_poll_user_id = None
    user_type = None
    if 'user_type' in session:
        user_type = session['user_type']
    matchid = request.args.get('matchid')
    if matchid:
        # Fetch match data from the database
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=False)
        # Execute the SQL query
        query = """
            SELECT
                m.Match_Id,
                DATE_FORMAT(m.Date_Time, '%d-%b-%y') AS Match_Date,
                TIME_FORMAT(m.Date_Time, '%h:%i %p') AS Match_Time,
                m.Place,
                t1.Team_Id AS Team_1_Id,
                t1.Team_Name AS Team_1_Name,
                t1.Team_Short_Name AS Team_1_SN,
                t2.Team_Id AS Team_2_Id,
                t2.Team_Name AS Team_2_Name,
                t2.Team_Short_Name AS Team_2_SN,
                m.Winner,
                m.Date_Time,
                s.Series_Name,
                s.Series_Id
            FROM
                `match` m
            INNER JOIN
                `series` s ON m.Series_Id = s.Series_Id
            INNER JOIN
                `team` t1 ON m.Team_1 = t1.Team_Id
            INNER JOIN
                `team` t2 ON m.Team_2 = t2.Team_Id
            WHERE
                m.Match_Id = %s
        """
        cursor.execute(query, (matchid,))
        match = cursor.fetchone()
        cursor.close()
        if not match:
            return render_template('invalid_request.html')
        else:
            match_id = matchid
            user_id = session.get('user_id')
            poll_user_id = request.form.get('userid')
            poll = request.form.get('poll')
            correct_poll = None
            correct_userid = None
            correct_access = None
            if match_id and poll and poll_user_id:
                # Check if the poll provided matches with team_1 or team_2
                conn = mysql.connector.connect(**db_config)
                cursor = conn.cursor(dictionary=False)
                current_time = get_current_ist_time()
                cursor.execute('SELECT Match_Id FROM `match` WHERE Date_Time > %s AND Match_Id = %s AND (Team_1 = %s OR Team_2 = %s)', (current_time, match_id, poll, poll))
                correct_poll = cursor.fetchone()
                cursor.execute('SELECT User_Id FROM `user` WHERE User_Id = %s', (poll_user_id,))
                correct_userid = cursor.fetchone()
                cursor.close()
                if user_type:
                    if user_type == 'A' or (user_type!='A' and str(user_id) == str(poll_user_id)):
                        correct_access = True
            if correct_poll and correct_userid and correct_access:
                valid_poll_user_id = poll_user_id
                poll_present = None
                # Check if the poll is already present
                conn = mysql.connector.connect(**db_config)
                cursor = conn.cursor(dictionary=False)
                cursor.execute('SELECT Poll_Team FROM `poll` WHERE Match_Id = %s AND User_Id = %s', (match_id, poll_user_id))
                poll_present = cursor.fetchone()
                cursor.close()
                if poll_present:
                    # Update the data in the poll table
                    conn = mysql.connector.connect(**db_config)
                    cursor = conn.cursor(dictionary=False)
                    try:
                        cursor.execute('UPDATE `poll` SET `Poll_Team` = %s, `Updated_By`= %s WHERE `Match_Id` = %s AND `User_Id` = %s',(poll, user_id, match_id, poll_user_id))
                        conn.commit()
                        flash('Poll updated successfully.', 'success')
                    except Exception as e:
                        flash('An error occurred while updating the poll.', 'error')
                    finally:
                        cursor.close()
                else:
                    # Insert data into the poll table
                    conn = mysql.connector.connect(**db_config)
                    cursor = conn.cursor(dictionary=False)
                    try:
                        cursor.execute('INSERT INTO `poll` (`Match_Id`, `Poll_Team`, `User_Id`, `Updated_By`) VALUES (%s, %s, %s, %s)',(match_id, poll, poll_user_id, user_id))
                        conn.commit()
                        flash('Poll updated successfully.', 'success')
                    except Exception as e:
                        flash('An error occurred while updating the poll.', 'error')
                    finally:
                        cursor.close()
            else:
                if match_id and poll and poll_user_id:
                    # Display "invalid match id" message
                    return render_template('invalid_request.html')
        current_time = get_current_ist_time()

        match_status_dict = {}
        match_dict = {
            'Match_Id': match[0],
            'Match_Date': match[1],
            'Match_Time': match[2],
            'Place': match[3],
            'Team_1_Id': match[4],
            'Team_1_Name': match[5],
            'Team_1_SN': match[6],
            'Team_2_Id': match[7],
            'Team_2_Name': match[8],
            'Team_2_SN': match[9],
            'Winner': match[10],
            'Date_Time': match[11],
            'Series_Name': match[12],
        }
        if current_time < match[11]:
            match_dict['Status'] = 'NS'  # Not Started
        else:
            match_dict['Status'] = 'AS'  # Already Started
        match_status_dict[match[0]] = match_dict

        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=False)
        # Fetch poll data from the database
        poll = None
        # Execute the SQL query
        query = """
            SELECT u.Name, p.Poll_Team, u.User_Id, p.Points FROM series_user su INNER JOIN user u ON su.User_Id = u.User_Id LEFT OUTER JOIN poll p ON su.User_Id = p.User_Id AND p.Match_Id = %s WHERE su.Series_Id = %s
        """
        cursor.execute(query, (matchid,match[13]))
        poll = cursor.fetchall()
        cursor.close()
        user_id = None
        if 'user_id' in session:
            user_id = session['user_id']

        team_1_poll_count = 0
        team_2_poll_count = 0
        na_poll_count = 0
        for row in poll:
            if row[1] == match_dict['Team_1_Id']:
                team_1_poll_count = team_1_poll_count + 1
            elif row[1] == match_dict['Team_2_Id']:
                team_2_poll_count = team_2_poll_count + 1
            else:
                na_poll_count = na_poll_count + 1

        poll_counts = [team_1_poll_count, team_2_poll_count, na_poll_count]
        return render_template('match.html', poll_counts=poll_counts, match=match_dict, poll=poll, user_type=user_type, user_id=user_id, valid_poll_user_id=valid_poll_user_id)
    else:
        # Display "invalid match id" message
        return render_template('invalid_request.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
