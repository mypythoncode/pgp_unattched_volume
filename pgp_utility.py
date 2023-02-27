import gnupg
import os
import logging
from datetime import datetime

DEFAULT_KEY_FILE_NAME = '.pgp'
DEFAULT_PASSPHRASE = 'T3zWYZA394tQ'
DEFAULT_EMAIL='ml_core_services_engineering@fico.com'
EXPIRE_YEAR = 2


GNUPG_HOME = '%s/pgp' % os.path.dirname(os.path.abspath(__file__))
gpg = None
if os.path.exists(GNUPG_HOME):
    gpg = gnupg.GPG(gnupghome=GNUPG_HOME)
else:
    gpg = gnupg.GPG()


def generate_pgp_key(passphrase_str=None, email=None, expire_year=None):
    """
    Generate PGP key.
    :param passphrase is required for key generation with GunPG
    """
    passphrase_str = passphrase_str if passphrase_str else DEFAULT_PASSPHRASE
    email = email if email else DEFAULT_EMAIL
    expire_year = expire_year if expire_year else EXPIRE_YEAR
    input_data = gpg.gen_key_input(key_length=2048, name_email=email, passphrase=passphrase_str, expire_date='%sy' % expire_year )
    key = gpg.gen_key(str(input_data))
    logging.info('key:%s' % key)
    return key


def export_pgp_key(key, export_private_key=False, passphrase_str=None):
    """
    Export the public/private key. 
    The public key name is .pgp_public.
    The private key name is .pgp_private.
    :param key The key's figure print
    :param export_private_key Export the private key or not
    :param passphrase It's required when exporting the private key
    """ 
    # Generate public key
    passphrase_str = passphrase_str if passphrase_str else DEFAULT_PASSPHRASE
    with open('%s_public' % DEFAULT_KEY_FILE_NAME, 'w') as f:
        ascii_armored_public_keys = gpg.export_keys(str(key))
        f.write(ascii_armored_public_keys)
        logging.info('Public key is exported.')
    if export_pgp_key:
        with open('%s_private' % DEFAULT_KEY_FILE_NAME, 'w') as f:
            ascii_armored_private_keys = gpg.export_keys(str(key), True, passphrase=passphrase_str)
            f.write(ascii_armored_private_keys)
            logging.info('Private key is exported.')
    return


def import_pgp_key(pgp_file_name):
    """
    Import the key file.
    :param pgp_file_name The file name to import.
    """
    key_data = open(pgp_file_name).read()
    import_pgp_key_data(key_data)
    return


def import_pgp_key_data(key_data):
    """
    Import the key data
    :param key_data The key data to import.
    """
    import_result = gpg.import_keys(key_data)
    logging.info('Key is imported: %s', import_result.results)
    return


def encrypt_file(file, recipients=None, output_file_name=None):
    """
    Encrypt the file.
    :param file The file to encrypt. The path and file name can be included
    :param recipients The recipients can be none if 
    :param output_file_name The file name for the encrypted file. The path and file name can be included
    """
    recipients_list = recipients if recipients else DEFAULT_EMAIL
    output_file_name = output_file_name if output_file_name else "%s._enc" % file 
    with open(file, 'rb') as f:
        result = gpg.encrypt_file(f, recipients=recipients_list, output=output_file_name, always_trust=True)
        if not result.ok:
            err_msg = '--Encryption error:  status: %s; \n; stderr: %s\n' % (result.status, result.stderr)
            raise Exception(err_msg)
        else:
            logging.info('Encryption status: %s', result.status)
    return output_file_name


def decrypt_file(file, passphrase=None, output_file_name=None):
    """
    Decrypt the file.
    :param file The file to decrypt. The path and file name can be included
    :param passphrase The passphrase for decryption
    :param output_file_name The file name for the decrypted file. The path and file name can be included
    """
    passphrase_str = passphrase if passphrase else DEFAULT_PASSPHRASE
    output_file_name = output_file_name if output_file_name else "%s._dec" % file 
    with open(file, 'rb') as f:
        result = gpg.decrypt_file(f, passphrase=passphrase_str, output=output_file_name, always_trust=True)
        if not result.ok:
            if 'no valid OpenPGP data found' in str(result.stderr):
                logging.warning('Unencrypted file is detected and will be moved to target folder directly: %s ' % file)
                return file
            err_msg = '--Decryption error:   status: %s; \n; stderr: %s\n' % (result.status, result.stderr)
            raise Exception(err_msg)
        else:
            logging.info('Decryption status: %s', result.status)
    return output_file_name


def get_key_info(hash_key, has_private=True):
    """
    Fetch the key information form keyrings
    """
    keys = gpg.list_keys() 
    if has_private:
        keys += gpg.list_keys(True)
    output = [] 
    for item in keys:
        if item['fingerprint'] == hash_key:
            item['date'] = datetime.fromtimestamp(int(item['date'])).strftime('%m/%d/%Y %H:%M:%S') if item['date'] else ''
            item['expires'] = datetime.fromtimestamp(int(item['expires'])).strftime('%m/%d/%Y %H:%M:%S') if item['expires'] else ''
            output.append(item)
    
    return output
