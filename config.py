import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'xxxx')
    STRIPE_PUBLIC_KEY = os.environ.get('STRIPE_PUBLIC_KEY', 'xxxx')
    STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY', 'xxxx')

    AWS_ACCESS_KEY = os.environ.get('AWS_ACCESS_KEY', 'xxxx')
    AWS_SECRET_KEY = os.environ.get('AWS_SECRET_KEY', 'xxxx')
    AWS_REGION = 'us-east-1'  

    AZURE_FUNCTION_URL = os.environ.get('AZURE_FUNCTION_URL', 'https://imageconversions.azurewebsites.net')

    UPLOAD_FOLDER = 'static/uploads'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
