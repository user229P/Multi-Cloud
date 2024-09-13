import base64
from flask import Flask, json, render_template, request, redirect, url_for, flash
import stripe
import boto3
import requests
import os
import time
from werkzeug.utils import secure_filename
from compare import compare_cloud_services
from config import Config
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from PIL import Image, ImageFilter

app = Flask(__name__)
app.config.from_object(Config)

stripe.api_key = Config.STRIPE_SECRET_KEY

# Create a session for Boto3
session = boto3.Session(
    aws_access_key_id=Config.AWS_ACCESS_KEY,
    aws_secret_access_key=Config.AWS_SECRET_KEY,
    region_name=Config.AWS_REGION
)

# AWS S3 and Lambda Clients
s3 = session.client('s3')
lambda_client = session.client('lambda')

# Initialize the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cloud_db.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Define the User model


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'


# Create the database tables
with app.app_context():
    db.create_all()

# User loader callback for Flask-Login


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes for user registration and login


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'warning')
            return redirect(url_for('register'))

        # Check if email already exists
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Email already exists. Please choose a different one.', 'warning')
            return redirect(url_for('register'))

        # Check if password and confirm_password match
        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return redirect(url_for('register'))

        # Create new user
        hashed_password = generate_password_hash(
            password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email,
                        password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('User registered successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!')
            return redirect(url_for('index'))
        else:
            flash('Login failed. Check your email and password.')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!')
    return redirect(url_for('index'))


# Ensure the upload folder exists
if not os.path.exists(Config.UPLOAD_FOLDER):
    os.makedirs(Config.UPLOAD_FOLDER)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS


@app.route('/')
@login_required
def index():
    return render_template('index.html')


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            return redirect(url_for('payment', filename=filename))
    return render_template('upload.html')


@app.route('/free_upload', methods=['GET', 'POST'])
@login_required
def free_upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            return redirect(url_for('free_process_image', filename=filename))
    return render_template('upload.html')


@app.route('/payment/<filename>', methods=['GET', 'POST'])
@login_required
def payment(filename):
    if request.method == 'POST':
        token = request.form['stripeToken']
        try:
            charge = stripe.Charge.create(
                amount=500,  # in cents
                currency='usd',
                description='Image Conversion Fee',
                source=token,
            )
            return redirect(url_for('process_image', filename=filename))
        except stripe.error.StripeError:
            flash('Payment failed')
            return redirect(url_for('upload_file'))
    return render_template('payment.html', key=app.config['STRIPE_PUBLIC_KEY'])


def process_image_locally(file_path, filename, width=None, height=None, img_format='original', grayscale=False, rotate=False):
    try:
        # Open an image file
        with Image.open(file_path) as img:
            # Resize the image if width and height are provided
            if width and height:
                width = int(width)
                height = int(height)
                img = img.resize((width, height))

            # Convert the image to grayscale if selected
            if grayscale:
                img = img.convert('L')

            # Rotate the image 90 degrees if selected
            if rotate:
                img = img.rotate(90, expand=True)

            # Determine the file format
            if img_format == 'original' or not img_format:
                img_format = img.format  # Use the original format of the image
                processed_filename = f"processed_{filename}"
            else:
                img_format = img_format.upper()  # Ensure img_format is uppercase for PIL
                processed_filename = f"processed_{os.path.splitext(filename)[0]}.{img_format.lower()}"

            # Define the path for the processed image
            processed_file_path = os.path.join(
                'static', 'uploads', processed_filename)

            # Save the processed image in the desired format
            img.save(processed_file_path, format=img_format)

            return processed_filename
    except Exception as e:
        print(f"Error processing image locally: {e}")
        return "error_placeholder.png"  # Return a placeholder image in case of an error

def process_file_with_lambda(file_path, filename):
    try:
        s3.upload_file(file_path, 'mybestbucket123', filename)
        with open(file_path, 'rb') as file_data:
            encoded_file_data = base64.b64encode(file_data.read()).decode('utf-8')
            response = lambda_client.invoke(
                FunctionName='my_image_processor',
                InvocationType='RequestResponse',
                Payload=json.dumps(
                    {"body": encoded_file_data, "isBase64Encoded": True})
            )
        if response['StatusCode'] == 200:
            return True
    except Exception as e:
        pass
    return True


def process_file_with_azure(file_path):
    try:
        with open(file_path, 'rb') as file_data:
            files = {'file': file_data}
            response = requests.post(Config.AZURE_FUNCTION_URL, files=files)
            if response.status_code == 200:
                return True
    except Exception as e:
        print(f"Error processing file with Azure Functions: {e}")
    return False

import threading
import requests
import random

@app.route('/process/<filename>', methods=['GET', 'POST'])
@login_required
def process_image(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    processed_image_filename = process_image_locally(file_path, filename, 
                                                     width=request.form.get('width'),
                                                     height=request.form.get('height'),
                                                     img_format=request.form.get('img_format'),
                                                     grayscale=request.form.get('grayscale'),
                                                     rotate=request.form.get('rotate'))

    aws_execution_time = None
    azure_execution_time = None
    aws_cost = None
    azure_cost = None
    aws_scalability_tests = None
    azure_scalability_tests = None
    aws_setup_time = None
    azure_setup_time = None

    if request.method == 'POST':
        service = request.form['service']
        start_time = time.time()

        def run_scalability_test(service_function, num_requests=100):
            threads = []
            results = []

            def process_request():
                try:
                    start = time.time()
                    service_function(file_path, filename)
                    results.append(time.time() - start)
                except:
                    results.append(None)

            for _ in range(num_requests):
                thread = threading.Thread(target=process_request)
                thread.start()
                threads.append(thread)

            for thread in threads:
                thread.join()

            return results

        if service == 'aws':
            if process_file_with_lambda(file_path, filename):
                aws_execution_time = time.time() - start_time
                aws_cost = 0.05  # Placeholder cost; replace with actual logic
                aws_setup_time = 10  # Placeholder setup time; replace with actual logic
                
                # Scalability test for AWS
                aws_scalability_results = run_scalability_test(process_file_with_lambda, num_requests=100)
                aws_scalability_tests = sum(filter(None, aws_scalability_results)) / len(aws_scalability_results)  # Average execution time
                
                flash('File processed using AWS Lambda')
                return redirect(url_for('success',
                                        service='aws',
                                        aws_execution_time=aws_execution_time,
                                        aws_cost=aws_cost,
                                        aws_scalability_tests=aws_scalability_tests,
                                        aws_setup_time=aws_setup_time,
                                        processed_image=processed_image_filename))
            else:
                flash('Error processing file with AWS Lambda, proceeding with Azure')
                if process_file_with_azure(file_path):
                    azure_execution_time = time.time() - start_time
                    azure_cost = 0.07  # Placeholder cost; replace with actual logic
                    azure_setup_time = 12  # Placeholder setup time; replace with actual logic
                    
                    # Scalability test for Azure
                    azure_scalability_results = run_scalability_test(process_file_with_azure, num_requests=100)
                    azure_scalability_tests = sum(filter(None, azure_scalability_results)) / len(azure_scalability_results)  # Average execution time
                    
                    flash('File processed using Azure Functions')
                    return redirect(url_for('success',
                                            service='azure',
                                            azure_execution_time=azure_execution_time,
                                            azure_cost=azure_cost,
                                            azure_scalability_tests=azure_scalability_tests,
                                            azure_setup_time=azure_setup_time,
                                            processed_image=processed_image_filename))
                else:
                    flash('Error processing file with Azure Functions')
        elif service == 'azure':
            if process_file_with_azure(file_path):
                azure_execution_time = time.time() - start_time
                azure_cost = 0.07  # Placeholder cost; replace with actual logic
                azure_setup_time = 12  # Placeholder setup time; replace with actual logic
                
                # Scalability test for Azure
                azure_scalability_results = run_scalability_test(process_file_with_azure, num_requests=100)
                azure_scalability_tests = sum(filter(None, azure_scalability_results)) / len(azure_scalability_results)  # Average execution time
                
                flash('File processed using Azure Functions')
                return redirect(url_for('success',
                                        service='azure',
                                        azure_execution_time=azure_execution_time,
                                        azure_cost=azure_cost,
                                        azure_scalability_tests=azure_scalability_tests,
                                        azure_setup_time=azure_setup_time,
                                        processed_image=processed_image_filename))
            else:
                flash('Error processing file with Azure Functions, proceeding with AWS Lambda')
                if process_file_with_lambda(file_path, filename):
                    aws_execution_time = time.time() - start_time
                    aws_cost = 0.05  # Placeholder cost; replace with actual logic
                    aws_setup_time = 10  # Placeholder setup time; replace with actual logic
                    
                    # Scalability test for AWS
                    aws_scalability_results = run_scalability_test(process_file_with_lambda, num_requests=100)
                    aws_scalability_tests = sum(filter(None, aws_scalability_results)) / len(aws_scalability_results)  # Average execution time
                    
                    flash('File processed using AWS Lambda')
                    return redirect(url_for('success',
                                            service='aws',
                                            aws_execution_time=aws_execution_time,
                                            aws_cost=aws_cost,
                                            aws_scalability_tests=aws_scalability_tests,
                                            aws_setup_time=aws_setup_time,
                                            processed_image=processed_image_filename))
                else:
                    flash('Error processing file with both AWS Lambda and Azure Functions')
    return render_template('process.html', filename=filename)

import threading
import requests
import random

@app.route('/free_process/<filename>', methods=['GET', 'POST'])
@login_required
def free_process_image(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    processed_image_filename = process_image_locally(file_path, filename, 
                                                     width=request.form.get('width'),
                                                     height=request.form.get('height'),
                                                     img_format=request.form.get('img_format'),
                                                     grayscale=request.form.get('grayscale'),
                                                     rotate=request.form.get('rotate'))

    aws_execution_time = None
    azure_execution_time = None
    aws_cost = None
    azure_cost = None
    aws_scalability_tests = None
    azure_scalability_tests = None
    aws_setup_time = None
    azure_setup_time = None

    if request.method == 'POST':
        service = request.form['service']
        start_time = time.time()

        def run_scalability_test(service_function, num_requests=100):
            threads = []
            results = []

            def process_request():
                try:
                    start = time.time()
                    service_function(file_path, filename)
                    results.append(time.time() - start)
                except:
                    results.append(None)

            for _ in range(num_requests):
                thread = threading.Thread(target=process_request)
                thread.start()
                threads.append(thread)

            for thread in threads:
                thread.join()

            return results

        if service == 'aws':
            if process_file_with_lambda(file_path, filename):
                aws_execution_time = time.time() - start_time
                aws_cost = 0.05  # Placeholder cost; replace with actual logic
                aws_setup_time = 10  # Placeholder setup time; replace with actual logic
                
                # Scalability test for AWS
                aws_scalability_results = run_scalability_test(process_file_with_lambda, num_requests=100)
                aws_scalability_tests = sum(filter(None, aws_scalability_results)) / len(aws_scalability_results)  # Average execution time
                
                flash('File processed using AWS Lambda')
                return redirect(url_for('success',
                                        service='aws',
                                        aws_execution_time=aws_execution_time,
                                        aws_cost=aws_cost,
                                        aws_scalability_tests=aws_scalability_tests,
                                        aws_setup_time=aws_setup_time,
                                        processed_image=processed_image_filename))
            else:
                flash('Error processing file with AWS Lambda, proceeding with Azure')
                if process_file_with_azure(file_path):
                    azure_execution_time = time.time() - start_time
                    azure_cost = 0.07  # Placeholder cost; replace with actual logic
                    azure_setup_time = 12  # Placeholder setup time; replace with actual logic
                    
                    # Scalability test for Azure
                    azure_scalability_results = run_scalability_test(process_file_with_azure, num_requests=100)
                    azure_scalability_tests = sum(filter(None, azure_scalability_results)) / len(azure_scalability_results)  # Average execution time
                    
                    flash('File processed using Azure Functions')
                    return redirect(url_for('success',
                                            service='azure',
                                            azure_execution_time=azure_execution_time,
                                            azure_cost=azure_cost,
                                            azure_scalability_tests=azure_scalability_tests,
                                            azure_setup_time=azure_setup_time,
                                            processed_image=processed_image_filename))
                else:
                    flash('Error processing file with Azure Functions')
        elif service == 'azure':
            if process_file_with_azure(file_path):
                azure_execution_time = time.time() - start_time
                azure_cost = 0.07  # Placeholder cost; replace with actual logic
                azure_setup_time = 12  # Placeholder setup time; replace with actual logic
                
                # Scalability test for Azure
                azure_scalability_results = run_scalability_test(process_file_with_azure, num_requests=100)
                azure_scalability_tests = sum(filter(None, azure_scalability_results)) / len(azure_scalability_results)  # Average execution time
                
                flash('File processed using Azure Functions')
                return redirect(url_for('success',
                                        service='azure',
                                        azure_execution_time=azure_execution_time,
                                        azure_cost=azure_cost,
                                        azure_scalability_tests=azure_scalability_tests,
                                        azure_setup_time=azure_setup_time,
                                        processed_image=processed_image_filename))
            else:
                flash('Error processing file with Azure Functions, proceeding with AWS Lambda')
                if process_file_with_lambda(file_path, filename):
                    aws_execution_time = time.time() - start_time
                    aws_cost = 0.05  # Placeholder cost; replace with actual logic
                    aws_setup_time = 10  # Placeholder setup time; replace with actual logic
                    
                    # Scalability test for AWS
                    aws_scalability_results = run_scalability_test(process_file_with_lambda, num_requests=100)
                    aws_scalability_tests = sum(filter(None, aws_scalability_results)) / len(aws_scalability_results)  # Average execution time
                    
                    flash('File processed using AWS Lambda')
                    return redirect(url_for('success',
                                            service='aws',
                                            aws_execution_time=aws_execution_time,
                                            aws_cost=aws_cost,
                                            aws_scalability_tests=aws_scalability_tests,
                                            aws_setup_time=aws_setup_time,
                                            processed_image=processed_image_filename))
                else:
                    flash('Error processing file with both AWS Lambda and Azure Functions')
    return render_template('process.html', filename=filename)


@app.route('/success')
@login_required
def success():
    service = request.args.get('service')
    processed_image = request.args.get('processed_image')

    aws_execution_time = request.args.get('aws_execution_time')
    aws_cost = request.args.get('aws_cost')
    aws_scalability_tests = request.args.get('aws_scalability_tests')
    aws_setup_time = request.args.get('aws_setup_time')

    azure_execution_time = request.args.get('azure_execution_time')
    azure_cost = request.args.get('azure_cost')
    azure_scalability_tests = request.args.get('azure_scalability_tests')
    azure_setup_time = request.args.get('azure_setup_time')

    return render_template('success.html',
                           service=service,
                           aws_execution_time=aws_execution_time,
                           aws_cost=aws_cost,
                           aws_scalability_tests=aws_scalability_tests,
                           aws_setup_time=aws_setup_time,
                           azure_execution_time=azure_execution_time,
                           azure_cost=azure_cost,
                           azure_scalability_tests=azure_scalability_tests,
                           azure_setup_time=azure_setup_time,
                           processed_image=processed_image)


if __name__ == '__main__':
    app.run(debug=True)
