import json
import boto3
import os
import sys
import logging
import math
import re
from logging.handlers import RotatingFileHandler
from botocore.exceptions import ClientError
from urllib import parse
import pgp_utility as pgp
from s3_client import S3Client
from ec2_client import EC2Client
from cw_client import CWClient
from ec2_metadata import ec2_metadata


LOG_LEVEL = os.environ['log_level'] if 'log_level' in os.environ else 'INFO'
LOG_FILE= os.environ['log_file'] if 'log_file' in os.environ else '/var/log/sftp-pgp/pgp.log'
QUEUE_NAME = os.environ['queue_name'] if 'queue_name' in os.environ else 'pgp_transform'
SFTP_LOG_GROUP = os.environ['sftp_log_group'] if 'sftp_log_group' in os.environ else ''
GTS_ENVIRONMENT = os.environ['gts_environment'] if 'gts_environment' in os.environ else None 
store_prefix = os.environ['store_prefix'] if 'store_prefix' in os.environ else '/sftp/customers'
general_store_prefix = '/sftp/customers/shared'
public_key_name = 'customer_pgp_pub_key'
private_key_name = 'fico_pgp_priv_key'
recipients_name = 'recipients'
passphrase_name = 'passphrase'
assume_role_name = "iam_role_arn"
inbound_file_extension = 'preferences/file_extension/inbound_file_extension'
outbound_file_extension = 'preferences/file_extension/outbound_file_extension'
sqs_default_timeout = 2 * 60
max_process_retries = 5

s3 = boto3.client('s3')
ssm = boto3.client('ssm', region_name = ec2_metadata.region)
sqs = boto3.resource('sqs', region_name = ec2_metadata.region)
queue = sqs.get_queue_by_name(QueueName='%s'%QUEUE_NAME)

log_format = '%(asctime)s - [%(levelname)s] - %(message)s'
logging.basicConfig(level=LOG_LEVEL, format=log_format)
rotatingHandler = RotatingFileHandler(LOG_FILE, maxBytes=1000000, backupCount=10)
rotatingHandler.setFormatter(logging.Formatter(log_format))
logging.getLogger().addHandler(rotatingHandler)


def get_environment(file_key):
    """
    Get the environment based on the s3 file structure
    :param file_key The S3 file path
    """
    items = file_key.split('/')
    for index, item in enumerate(items):
        if item == 'client_access' or item == 'output' or item == 'input':
            return items[index -1] if index-1 > -1 else None
    return None


def can_do_encrypt(file_key):
    """
    Decide the encrypt/decrypt or do nothing
    Encrypt if True, Decrypt if False, None to do nothing
    :param file_key The S3 file path
    """
    if '/client_access/inbound/' in file_key:
        return False
    elif '/output/' in file_key:
        return True
    else:
        return None

def get_upload_file_key(file_key, do_encrypt, file_extension):
    """
    Generate the file path for uploading the file
    :param file_key The S3 file path
    :param do_encrypt Encrypt or decrypt
    :param file_extestion The file extestion to be appended or removed
    """
    new_file_key = ''
    if do_encrypt:
        new_file_key = file_key.replace('/output/', '/client_access/outbound/')
        if file_extension:
            new_file_key = new_file_key + file_extension
    elif do_encrypt == False:
        new_file_key = file_key.replace('/client_access/inbound/', '/input/')
        if file_extension:
            file_key_before = new_file_key
            new_file_key = re.sub(file_extension+'$', '', new_file_key, flags=re.IGNORECASE)
            if file_key_before == new_file_key:
                logging.warning('The inbound file "%s" does not have the expected file extension %s' % (file_key_before, file_extension))
    return new_file_key
    
def get_ssm_value(prefix, bucket_name=None, env_str=None, name=None, can_skip=True):
    """
    Read the parameter store value by name
    :param prefix The prefix of the value name to compose parameter store
    :param bucket_name S3 bucket name
    :param env_str The client's environment
    :param name The value name
    :param can_skip Ignore the non-exist error if true
    """
    store_name = ''
    try:
        store_name = '/'.join(filter(None, [prefix, bucket_name, env_str, name]))     
        parameter = ssm.get_parameter(Name='%s' % store_name, WithDecryption=True)
        logging.info ('Access the parameter store:%s' % store_name)
        return parameter['Parameter']['Value']
    except Exception as e:
        if can_skip:
            logging.info('parameter store does not exist: %s', store_name)
            return None
        err_mesg = 'Fail to retrieve parameter store: %s' % store_name
        logging.debug('%s, error_detail: %s' % (err_mesg, str(e)))
        raise ValueError(err_mesg)

def filter_messages(file_key):
    """
    Filter the invalid messages
    :param file_key The S3 file path
    """
    if not '/client_access/inbound/' in file_key and not '/output/' in file_key:
        logging.warning('Skip: Invalid S3 file path: %s' % file_key)
        return True

    filename = file_key.split('/')[-1]
    if not filename:
        logging.warning('Skip: No filename is provided. A folder might be created.')
        return True
    if '.filepart' in filename:
        logging.warning('Skip: File is not completely uploaded.')
        return True

    return False

def set_message_timeout_by_file_size(message, file_size):
    """
    Set the SQS message visibility timeout
    :param message SQS.Message
    :param file_size The file size (GB)
    """
    if file_size < 1:
        return
    # Assume 3 mins to process 1G file (download, encryption/decryption, upload) 
    time_secs = 3 * 60 * math.ceil(file_size)
    time_secs = time_secs if time_secs < 12 * 3600 else 12 * 3600
    logging.info('SQS - Extend the message "%s" to %s seconds' % (message.message_id, time_secs))
    response = message.change_visibility(VisibilityTimeout=time_secs)
    if (response and response.get('ResponseMetadata') and isinstance(response.get('ResponseMetadata'),dict)
            and str(response.get('ResponseMetadata').get('HTTPStatusCode')) == '200'):
        logging.debug('Message ID: %s - Visibility was set, response: %s', message.message_id, response)
    else:
        logging.error('Message ID: %s - Visibility was not set due to: %s', message.message_id, response)
        raise Exception('Error in extending the message %s visibility timeout' % (message.message_id))
    return 


def transform(message):
    ec2_client = None
    try:
        try:
            event = json.loads(message.body)
            logging.info('Event: %s', event)
        except ValueError as e:
            logging.warning('Skip: Message is not valid JSON. Remove it from queue: %s', message.body)
            return True

        receive_cout = int(message.attributes["ApproximateReceiveCount"])
        bucket_name = ''
        file_key = ''
        file_size = 0
        file_extension = ''
        try:
            # Retrive the uploaded file info
            bucket_name = event['Records'][0]['s3']['bucket']['name']
            file_key = parse.unquote_plus(str(event['Records'][0]['s3']['object']['key']))
            file_size = float(event['Records'][0]['s3']['object']['size']) / 1024 / 1024 / 1024
            logging.info('bucket_name: %s, filekey: %s, file_size: %s', bucket_name, file_key, file_size)
            # Filter the messages
            if filter_messages(file_key):
                return True
        except Exception as err:
            logging.warning(str(err))
            logging.warning('Skip: Not valid message. Remove it from queue...')
            return True

        # Fetch the environment values
        env_str = get_environment(file_key)
        role_arn = get_ssm_value(store_prefix, bucket_name, env_str, assume_role_name, False)

        do_encrypt = can_do_encrypt(file_key)
        if do_encrypt == True:
            key_data = get_ssm_value(store_prefix, bucket_name, env_str, public_key_name, False)
            recipients_data = get_ssm_value(store_prefix, bucket_name, env_str, recipients_name, False)
            file_extension = get_ssm_value(store_prefix, bucket_name, env_str, outbound_file_extension)
        elif do_encrypt == False:
            pass_str = get_ssm_value(store_prefix, bucket_name, env_str, passphrase_name)
            key_data = get_ssm_value(store_prefix, bucket_name, env_str, private_key_name)
            if pass_str is None or key_data is None:
                logging.info('No customized key or passphrase is found. Use the general FICO keys...')
                pass_str = get_ssm_value(general_store_prefix, None, GTS_ENVIRONMENT, passphrase_name, False)
                key_data = get_ssm_value(general_store_prefix, None, GTS_ENVIRONMENT, private_key_name, False)
            file_extension = get_ssm_value(store_prefix, bucket_name, env_str, inbound_file_extension)
        else:
            raise ValueError('Can not verify if encryption/decryption is required. Do nothing...')

        # Skip the message if file is PARTIAL_CLOSE
        if SFTP_LOG_GROUP:
            s3_event_time = event['Records'][0]['eventTime']
            file_full_path = '/%s/%s' % (bucket_name, file_key)
            cw_client = CWClient(SFTP_LOG_GROUP)
            logging.info('Checking the SFTP log for the status of the uploaded file: %s' % file_full_path)
            is_partial = cw_client.has_partial_close(s3_event_time, file_full_path)
            if is_partial:
                # Skip
                logging.warning('Skip: File is partial closed - %s' % file_full_path)
                return True
            elif is_partial is None:
                logging.info('SFTP log is not available for the specified file: %s' % file_full_path)
                if receive_cout >= max_process_retries:
                    logging.info('Maximum SFTP log checks have been executed. Process the file without checking logs: %s' % file_full_path)
                else:
                    return False
            else:
                logging.info('Checking the SFTP log: %s is not partial closed.' % file_full_path)
        else:
            logging.info('Log group is not defined. Skip checking the SFTP log')

        # Skip the message if remote file does not exist     
        s3_client = S3Client(role_arn)
        has_file = s3_client.has_s3_file(bucket_name, file_key)
        if not has_file:
            logging.warning('Skip: Remote file does not exist: %s/%s', bucket_name, file_key)
            return True

        # Extend the SQS timeout if 
        set_message_timeout_by_file_size(message, file_size)

        # Mount the disk
        ec2_client = EC2Client()

        # Set calculated volume size at 10 times file size (minimum 1GB)
        # Note - This may not be large enough for all files as the compression ratio of a compressed and encrypted file might be more than 10 to 1
        #        Recommend that clients that use PGP encryption set their local configs to not enable compression to avoid problems (e.g. "-z0" argument to gpg) 
        vol_size = math.ceil(file_size * 10)
        vol_info = ec2_client.install_volume(vol_size, bucket_name)
        logging.info('Volume info: %s', vol_info)

        # Fetch the file
        s3_client.set_work_dir(vol_info['mount_path'])
        logging.info('Download %s from %s', file_key, bucket_name)
        local_file_name = s3_client.download_s3_file(bucket_name, file_key)
        
        output_file_name = ''        
        if do_encrypt == True:
            logging.info('Encrypt the file...')
            # Encrypt the file
            pgp.import_pgp_key_data(key_data)
            output_file_name = pgp.encrypt_file(local_file_name, recipients_data)
        elif do_encrypt == False and file_size == 0:
            logging.info ('Zero Byte File Uploaded, Decryption will not be attempted')
            output_file_name = local_file_name
        elif do_encrypt == False:
            logging.info ('Decrypt the file...')
            # Decrypt the file
            pgp.import_pgp_key_data(key_data)
            output_file_name = pgp.decrypt_file(local_file_name, pass_str)

        # Upload the processed file to bucket
        if output_file_name:
            upload_file_key = get_upload_file_key(file_key, do_encrypt, file_extension)
            s3_client.upload_s3_file(output_file_name, bucket_name, upload_file_key)
            s3_client.delete_s3_file(bucket_name, file_key)
            os.remove(local_file_name)
            if local_file_name != output_file_name:
                os.remove(output_file_name)

        return True
    except ClientError as err:
        logging.error('AWS client error: %s', err)
        return False
    except ValueError as val_err:
        logging.error(str(val_err))
        return False
    except Exception as e:
        logging.exception('Error: %s', e)
        return False
    finally:
        # Remove the volume
        if ec2_client and EC2Client.volume_id:
            ec2_client.uninstall_volume(EC2Client.volume_id)


def process_messages():
    for message in queue.receive_messages(AttributeNames=['ApproximateReceiveCount'], MessageAttributeNames=['All'], MaxNumberOfMessages=1, WaitTimeSeconds=20, VisibilityTimeout=sqs_default_timeout):
        logging.info('Receive the message: %s', message.message_id)
        if not message.body:
            logging.warning('No message body: The message %s is removed.', message.message_id)

        logging.info('Start process message: %s', message.message_id)
        result = transform(message)
        # The message is processed
        if result:
            message.delete()
            logging.info('Message is processed: %s', message.message_id)
        else:
            logging.info('Message is NOT processed and will be processed again later...')
