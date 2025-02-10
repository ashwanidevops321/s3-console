from flask import Flask, render_template, request, redirect, url_for, flash, session
from functools import wraps
import boto3
import os
from botocore.exceptions import ClientError
from werkzeug.security import generate_password_hash, check_password_hash
import string
import random
import logging
from dotenv import load_dotenv
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Ensure environment variables are set
AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
AWS_REGION = os.environ.get('AWS_REGION', 'eu-west-2')
S3_BUCKET = os.environ.get('S3_BUCKET')
FLASK_SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'supersecretkey')

if not all([AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, S3_BUCKET]):
    logging.error("One or more required environment variables are missing.")
    raise EnvironmentError("One or more required environment variables are missing.")

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

s3 = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=AWS_REGION
)

users = {
    "admin": {"password": generate_password_hash("adminpass"), "role": "admin", "id": 1},
    "user": {"password": generate_password_hash("userpass"), "role": "user", "id": 2}
}

def generate_random_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('Admin access required')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = users.get(username)
        if user and check_password_hash(user['password'], password):
            session['user'] = username
            session['role'] = user['role']
            session['user_id'] = user['id']
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    token = request.args.get('token')
    prefix = request.args.get('prefix', '')
    logging.debug(f"Token: {token}, Prefix: {prefix}")
    try:
        if token:
            response = s3.list_objects_v2(Bucket=S3_BUCKET, ContinuationToken=token, Prefix=prefix, Delimiter='/', MaxKeys=32)
        else:
            response = s3.list_objects_v2(Bucket=S3_BUCKET, Prefix=prefix, Delimiter='/', MaxKeys=32)
        
        objects = response.get('Contents', [])
        prefixes = [p['Prefix'].rstrip('/') for p in response.get('CommonPrefixes', [])]
        next_token = response.get('NextContinuationToken')
        prev_token = response.get('StartAfter')
        
        folder_names = [p['Prefix'].rstrip('/') for p in response.get('CommonPrefixes', [])]
        
        return render_template('index.html', objects=objects, prefixes=prefixes, bucket=S3_BUCKET, next_token=next_token, prev_token=prev_token, prefix=prefix, folder_names=folder_names)
    except ClientError as e:
        logging.error(f"Error accessing bucket: {e}")
        flash(f'Error accessing bucket: {e}')
        return render_template('index.html', objects=[], prefixes=[], bucket=S3_BUCKET, folder_names=[])

@app.route('/search', methods=['POST'])
@login_required
def search():
    search_key = request.form.get('search_key')
    if search_key:
        return redirect(url_for('index', prefix=search_key))
    else:
        flash('Search key is required')
        return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    current_prefix = request.args.get('prefix', '')
    if request.method == 'POST':
        folder = request.form.get('folder')
        files = request.files.getlist('files')
        user_id = session.get('user_id')

        if not files:
            flash('Files are required')
            return redirect(url_for('upload', prefix=current_prefix))

        if folder:
            folder_prefix = f"{folder}/"
            try:
                response = s3.list_objects_v2(Bucket=S3_BUCKET, Prefix=folder_prefix, Delimiter='/')
                if 'Contents' not in response and 'CommonPrefixes' not in response:
                    flash(f'Folder "{folder}" does not exist in the bucket')
                    return redirect(url_for('upload', prefix=current_prefix))
            except ClientError as e:
                flash(f'Error checking folder: {e}')
                return redirect(url_for('upload', prefix=current_prefix))

        for file in files:
            key = file.filename
            if folder:
                key = f"{folder}/{key}"
            else:
                key = f"{current_prefix}{key}"

            try:
                s3.upload_fileobj(file, S3_BUCKET, key, ExtraArgs={"Metadata": {"user_id": str(user_id)}})
            except ClientError as e:
                flash(f'Upload error: {e}')
                return redirect(url_for('upload', prefix=current_prefix))

        flash('Files uploaded successfully')
        return redirect(url_for('index', prefix=current_prefix))

    return render_template('upload.html', prefix=current_prefix)

@app.route('/delete/<path:key>')
@login_required
@admin_required
def delete(key):
    try:
        s3.delete_object(Bucket=S3_BUCKET, Key=key)
        flash('Object deleted successfully')
    except ClientError as e:
        flash(f'Delete error: {e}')
    return redirect(url_for('index'))

@app.route('/download/<path:key>')
@login_required
def download(key):
    try:
        url = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': S3_BUCKET, 'Key': key},
            ExpiresIn=3600
        )
        return redirect(url)
    except ClientError as e:
        flash(f'Download error: {e}')
        return redirect(url_for('index'))

@app.route('/edit/<path:key>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit(key):
    if request.method == 'POST':
        new_key = request.form.get('key')
        new_file = request.files.get('file')

        if not new_key:
            flash('Key is required')
            return redirect(url_for('edit', key=key))

        try:
            if new_key != key:
                if new_file:
                    s3.upload_fileobj(new_file, S3_BUCKET, new_key)
                else:
                    s3.copy_object(
                        Bucket=S3_BUCKET,
                        CopySource={'Bucket': S3_BUCKET, 'Key': key},
                        Key=new_key
                    )
                s3.delete_object(Bucket=S3_BUCKET, Key=key)
            else:
                if new_file:
                    s3.upload_fileobj(new_file, S3_BUCKET, key)
                else:
                    flash('No changes made')
                    return redirect(url_for('edit', key=key))

            flash('Object updated successfully')
            return redirect(url_for('index'))
        except ClientError as e:
            flash(f'Update error: {e}')
            return redirect(url_for('edit', key=key))

    return render_template('edit.html', key=key)

@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_users():
    if request.method == 'POST':
        username = request.form.get('username')
        if 'delete' in request.form:
            if username in users:
                del users[username]
                flash(f'User {username} deleted successfully')
            else:
                flash('User not found')
        elif 'check' in request.form:
            if username in users:
                user = users[username]
                flash(f'User {username} found with role {user["role"]}')
            else:
                flash('User not found')
        else:
            role = request.form.get('role')
            if username and role:
                if username in users:
                    flash('User already exists')
                else:
                    user_id = max(user['id'] for user in users.values()) + 1
                    random_password = generate_random_password()
                    hashed_password = generate_password_hash(random_password)
                    users[username] = {"password": hashed_password, "role": role, "id": user_id}
                    flash(f'User created successfully. Password is: {random_password}')
            else:
                flash('Username and role are required')
    return render_template('users.html', users=users)

if __name__ == '__main__':
    app.run(host="0.0.0.0",debug=True)
