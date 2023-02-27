import boto3
import logging
from botocore.exceptions import ClientError


sts_client = boto3.client('sts')


class S3Client(object):

    sts_client = boto3.client('sts')
    s3 = None
    work_dir = '/tmp'

    def __init__(self, role_arn, work_dir=None):
        # Assume a role
        assumed_role_object=sts_client.assume_role(RoleArn=role_arn, RoleSessionName="AssumeS3Role")
        credentials=assumed_role_object['Credentials']
        self.s3 = boto3.client(
            's3',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        self.work_dir = work_dir if work_dir else self.work_dir

    def set_work_dir(self, workdir):
        self.work_dir = workdir

    def get_work_dir(self):
        return self.work_dir
    
    def download_s3_file(self, bucket, file_key):
        """
        Download a S3 object.
        :param bucket The bucket to download from
        :param file_key The file path to the object
        """
        object_name = file_key.split('/')[-1]
        local_file_name = '%s/%s' % (self.work_dir, object_name)
        logging.info('%s/%s will be downloaded as %s...', bucket, file_key, local_file_name)
        self.s3.download_file(bucket, file_key, local_file_name )
        logging.info('%s/%s is downloaded successfully.', bucket, file_key)
        return local_file_name
    
    def upload_s3_file(self, file, bucket, file_key):
        """
        Upload a file to the S3.
        :param file The file to upload. Path can be included
        :param bucket The bucket to upload the object.
        :param file_key The place to put the file
        """
        logging.info('%s will be uploaded to %s/%s...', file, bucket, file_key)
        self.s3.upload_file(file, bucket, file_key, ExtraArgs={'ACL': 'bucket-owner-full-control'})
        logging.info('%s is uploaded successfully.', file)
        return '%s/%s' % (bucket, file_key)

    def delete_s3_file(self, bucket, file_key):
        """
        Delete a S3 object.
        :param bucket The bucket to download from
        :param file_key The file path to the object
        """
        logging.info('%s/%s will be removed...', bucket, file_key)
        self.s3.delete_object(Bucket=bucket, Key=file_key )
        logging.info('%s/%s is removed successfully.', bucket, file_key)

    def has_s3_file(self, bucket, file_key):
        """
        Dose the S3 file exist?
        :param bucket The bucket to download from
        :param file_key The file path to the object
        """
        try:
            self.s3.head_object(Bucket=bucket, Key=file_key)
        except ClientError as e:
            if e.response['Error']['Code'] == "404":
                # The object does not exist.
                return False
            else:
                # Something else has gone wrong.
                raise e
        else:
            # The object does exist.
            return True
