import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from config import Config

try:
    s3 = boto3.client('s3', 
                      aws_access_key_id=Config.AWS_ACCESS_KEY, 
                      aws_secret_access_key=Config.AWS_SECRET_KEY, 
                      region_name=Config.AWS_REGION)
    print(Config.AWS_SECRET_KEY)
except NoCredentialsError:
    print("Credentials not available")
except PartialCredentialsError:
    print("Incomplete credentials provided")
