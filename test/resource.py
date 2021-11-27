import boto3
from boto3 import client, resource
from botocore.exceptions import ClientError
import os.path
from config import s3_bucket, s3_access_key, s3_secret_key # imported from the paralled file config.py
from flask import Flask, render_template, request, redirect, url_for, flash, Response, session

s3_client = client('s3')
s3_resource = resource('s3')

def _get_s3_resource():
    if s3_access_key and s3_secret_key:
        return boto3.resource(
            's3',
            aws_access_key_id=s3_access_key,
            aws_secret_access_key=s3_secret_key
        )
    else:
        return boto3.resource('s3')

def get_bucket():
    s3_resource = _get_s3_resource()
    if 'bucket' in session:
        bucket = session['bucket']
    else:
        bucket = s3_bucket
    return s3_resource.Bucket(bucket)

def get_bucket_list():
    client = boto3.client('s3')
    return client.list_buckets().get('Buckets')

