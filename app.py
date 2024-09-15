from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from werkzeug.exceptions import RequestEntityTooLarge
import os
from werkzeug.utils import secure_filename
import sqlite3
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Configuration for file uploads
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'avi', 'mov', 'pdf', 'docx', 'xlsx'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5000 * 1024 * 1024  # Max 500MB upload

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Database setup
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, password TEXT, pin TEXT)''')
    # Uploads table
    c.execute('''CREATE TABLE IF NOT EXISTS uploads
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  filename TEXT,
                  filepath TEXT,
                  username TEXT,
                  FOREIGN KEY(username) REFERENCES users(username))''')
    conn.commit()
    conn.close()

init_db()

# Helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    if 'username' in session:
        return render_template('home.html', username=session['username'])
    else:
        return redirect(url_for('login'))

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        pin = request.form['pin']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ? AND password = ? AND pin = ?', (username, password, pin))
        user = c.fetchone()
        conn.close()

        if user:
            session['username'] = username
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid login credentials', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        pin = request.form['pin']
        confirm_pin = request.form['confirm_pin']

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('signup'))

        if pin != confirm_pin:
            flash('PINs do not match!', 'danger')
            return redirect(url_for('signup'))

        if not re.match(r'^\d{4,6}$', pin):
            flash('PIN must be 4 to 6 digits!', 'danger')
            return redirect(url_for('signup'))

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password, pin) VALUES (?, ?, ?)', (username, password, pin))
            conn.commit()
            flash('Signup successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists!', 'danger')
            return redirect(url_for('signup'))
        finally:
            conn.close()

    return render_template('signup.html')

@app.route('/account', methods=['GET', 'POST'])
def account():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    if request.method == 'POST':
        new_username = request.form['username']
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']
        new_pin = request.form['pin']
        confirm_pin = request.form['confirm_pin']

        # Validate inputs
        if new_password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('account'))

        if new_pin != confirm_pin:
            flash('PINs do not match!', 'danger')
            return redirect(url_for('account'))

        if not re.match(r'^\d{4,6}$', new_pin):
            flash('PIN must be 4 to 6 digits!', 'danger')
            return redirect(url_for('account'))

        try:
            c.execute('UPDATE users SET username = ?, password = ?, pin = ? WHERE username = ?', 
                      (new_username, new_password, new_pin, username))
            conn.commit()
            session['username'] = new_username  # Update session
            flash('Account details updated successfully!', 'success')
            return redirect(url_for('account'))
        except sqlite3.IntegrityError:
            flash('Username already exists!', 'danger')
            return redirect(url_for('account'))
        finally:
            conn.close()

    else:
        # Fetch the current user's details
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()

        return render_template('account.html', user=user)

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.errorhandler(RequestEntityTooLarge)
def handle_request_entity_too_large(error):
    flash('The uploaded file is too large. Please upload a smaller file.', 'danger')
    return redirect(url_for('upload'))


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'username' not in session:
        flash('Please log in to upload files.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part!', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file!', 'danger')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            user_folder = os.path.join(app.config['UPLOAD_FOLDER'], session['username'])
            if not os.path.exists(user_folder):
                os.makedirs(user_folder)
            filepath = os.path.join(user_folder, filename)
            file.save(filepath)

            # Save file info to the database
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute('INSERT INTO uploads (filename, filepath, username) VALUES (?, ?, ?)', 
                      (filename, filepath, session['username']))
            conn.commit()
            conn.close()

            flash('File uploaded successfully!', 'success')
            return redirect(url_for('access'))
        else:
            flash('File type not allowed!', 'danger')
            return redirect(request.url)

    return render_template('upload.html')

@app.route('/access', methods=['GET', 'POST'])
def access():
    if 'username' not in session:
        flash('Please log in to view your files.', 'warning')
        return redirect(url_for('login'))

    username = session['username']
    
    if request.method == 'POST':
        pin = request.form.get('pin')
        if not pin:
            flash('Please enter your PIN.', 'warning')
            return render_template('access.html', pin_required=True)

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT pin FROM users WHERE username = ?', (username,))
        correct_pin = c.fetchone()
        conn.close()

        if correct_pin and pin == correct_pin[0]:
            # PIN is correct, show the files
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute('SELECT id, filename FROM uploads WHERE username = ?', (username,))
            files = c.fetchall()
            conn.close()
            return render_template('access.html', files=files, pin_required=False)
        else:
            flash('Incorrect PIN. Please try again.', 'danger')
            return render_template('access.html', pin_required=True)

    elif request.method == 'GET':
        # GET request - show the PIN entry form or the files list
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT id, filename FROM uploads WHERE username = ?', (username,))
        files = c.fetchall()
        conn.close()
        return render_template('access.html', files=files, pin_required=True)

@app.route('/delete_file/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    if 'username' not in session:
        flash('Please log in to delete files.', 'warning')
        return redirect(url_for('login'))

    username = session['username']
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT filename, filepath FROM uploads WHERE id = ? AND username = ?', (file_id, username))
    file_data = c.fetchone()
    conn.close()

    if file_data:
        filename, filepath = file_data
        os.remove(filepath)  # Delete the file from the filesystem

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('DELETE FROM uploads WHERE id = ?', (file_id,))
        conn.commit()
        conn.close()

        flash('File deleted successfully!', 'success')
    else:
        flash('File not found or you do not have permission to delete this file.', 'danger')

    return redirect(url_for('access'))

    # GET request - show the PIN entry form
    return render_template('access.html', pin_required=True)

@app.route('/view/<username>/<filename>')
def view_file(username, filename):
    if 'username' not in session:
        flash('Please log in to view files.', 'warning')
        return redirect(url_for('login'))
    if username != session['username']:
        flash('You do not have permission to view this file.', 'danger')
        return redirect(url_for('access'))
    return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'], username), filename)


@app.route('/uploads/<username>/<filename>')
def uploaded_file(username, filename):
    if 'username' not in session:
        flash('Please log in to access files.', 'warning')
        return redirect(url_for('login'))
    if username != session['username']:
        flash('You do not have permission to access this file.', 'danger')
        return redirect(url_for('access'))
    return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'], username), filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
