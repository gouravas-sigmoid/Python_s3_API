import os
import boto3

s3_bucket = os.environ.get("s3_bucket")
s3_access_key = os.environ.get("s3_access_key")
s3_secret_key = os.environ.get("s3_secret_key")

