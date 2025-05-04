# Python script to PGP encrypt file


# Import required packages
import json
import urllib.parse
import boto3
import gnupg
import botocore
import os
from botocore.exceptions import ClientError

# Declare global clients
s3_client = boto3.client('s3')
secretsmanager_client = boto3.client('secretsmanager')

# Function to retrieve specified secret_value from secrets manager
def get_secret_details(secretArn, pgpKeyType):
    try:
        response = secretsmanager_client.get_secret_value(
           SecretId=secretArn
           )
        # Create dictionary
        secret = response['SecretString']
        if secret != None:
            secret_dict = json.loads(secret)
        else:
            print("Secrets Manager exception thrown")
            statusCode = 500
            body = {
                    "errorMessage": "Secrets Manager exception thrown"
                }
        if pgpKeyType in secret_dict:
            PGPKey = secret_dict[pgpKeyType]
            statusCode = 200
        else:
            print(f"{pgpKeyType} not found in secret")
            statusCode = 500
            body = {
                "errorMessage": f"{pgpKeyType} not found in secret"
            }
        return {
            "PGPKey": PGPKey
            }
    except ClientError as e:
        print(json.dumps(e.response))
        statusCode = e.response['ResponseMetadata']['HTTPStatusCode']
        errorCode = e.response['Error']['Code']
        errorMessage = e.response['Error']['Message']
        body = {
             "errorCode": errorCode,
             "errorMessage": errorMessage
        }
        return {
            'statusCode': statusCode,
            'body': body
        }


# Function that downloads file from S3 specified S3 bucket, returns a boolean indicating if file download was a success/failure
def downloadfile(bucketname, key, filename):
    try:
        print(f"Trying to download key {key} from bucket {bucketname} to {filename}")
        newfilename = '/tmp/' + filename
        # Download file from S3 to /tmp directory in lambda
        s3_client.download_file(bucketname, key, newfilename)
        # If download is successful, function returns true
        return os.path.exists(newfilename)
    except botocore.exceptions.ClientError as error:
        # Summary of what went wrong
        print(error.response['Error']['Code'])
        # Explanation of what went wrong
        print(error.response['Error']['Message'])
        # If download fails, function returns false
        return False

# Function that performs PGP encryption
def encrypt_file(input_file, output_file, recipient):
    # Configure GPG binary to work with lambda
    gpg = gnupg.GPG(homedir='/tmp', gpgbinary='/bin/gpg')
    # Encrypt file
    encrypted_file = gpg.encrypt_file(local_file_name,recipients= import_result.fingerprints, output=output_file)

    # If encryption fails,return stderr message
    if encrypted_file.status != 0:
        raise Exception("Error encrypting file: {}".format(encrypted_file.stderr))

# Function that wipes /tmp directory clean
def wipe_tmp_directory():
  for root, dirs, files in os.walk("/tmp"):
    for file in files:
      os.remove(os.path.join(root, file))

# Lambda handler
def handler(event, context):

    print(json.dumps(event))

    # Encryption requires PGP public key
    pgpKeyType = 'PGPPublicKey'

    # Get variables from event
    partnerId = event['JobParameters']['body']['partnerId']
    pgpSecret = event['JobParameters']['body']['pgpSecret']
    outputBucket = event['JobParameters']['body']['outputBucket']
    if 'CustomStep' in event:
        bucket = event['CustomStep']['body']['bucket']
        key = urllib.parse.unquote_plus(event['CustomStep']['body']['key'])
    else:
        bucket = event['bucket']
        key = urllib.parse.unquote_plus(event['key'])

    # Set required file names
    file = key.split('/')[-1]
    output_file = '/tmp/' + file + '.gpg'
    encrypted_file_name = file + '.gpg'
    encrypted_key = partnerId + '/' + encrypted_file_name
    print(f'File name: {file}')
    print(f'Output file name: {output_file}')
    print(f'Encrypted file name: {encrypted_file_name}')
    print(f'Encrypted key: {encrypted_key}')

    # Ensure /tmp directory is empty
    print('Wiping tmp directory')
    wipe_tmp_directory()

    # Set GNUPG home directory and point to where the binary is stored.
    gpg = gnupg.GPG(gnupghome='/tmp', gpgbinary='/bin/gpg')
    print("GPG binary initialized successfully")

    # Get PGP key from Secrets Manager
    pgpDetails = get_secret_details(pgpSecret, pgpKeyType)
    PGPPublicKey = pgpDetails['PGPKey']

    # Fix escaped newlines in the PGP key
    if '\\n' in PGPPublicKey:
        print("Found escaped newlines in PGP key, converting to actual newlines")
        PGPPublicKey = PGPPublicKey.replace('\\n', '\n')
        print("Converted escaped newlines in PGP key")

    # Import PGP public key into keyring
    print('Trying importing PGP public key')

    # Print first few characters of the key for debugging (avoid printing the entire key for security)
    key_preview = PGPPublicKey[:30] + "..." if len(PGPPublicKey) > 30 else PGPPublicKey
    print(f"PGP Key preview: {key_preview}")

    # Import the key
    import_result = gpg.import_keys(PGPPublicKey)

    # Print detailed import results
    print(f"Import result summary: {import_result.summary()}")
    print(f"Import count: {import_result.count}")
    print(f"Import fingerprints: {import_result.fingerprints}")
    print(f"Import results: {import_result.results}")

    # Check if import was successful and fingerprints are available
    if not import_result.fingerprints:
        error_msg = "PGP key import failed - no valid fingerprints found"
        print(error_msg)
        return {
            'statusCode': 500,
            'body': {
                'errorMessage': error_msg
            }
        }

    print(f"PGP Public Key imported successfully. Using fingerprints: {import_result.fingerprints}")

    # Download unencrypted file from S3
    try:
        downloadStatus = downloadfile(bucket, key, file)
        local_file_name = '/tmp/' + file

        # If file downloads successfully, continue with encryption process
        if (downloadStatus):
            print("Download successful")

            # Perform PGP encryption
            print(f"Encrypting file with recipients: {import_result.fingerprints}")
            status = gpg.encrypt_file(local_file_name, recipients=import_result.fingerprints, output=output_file)

            # Print encryption status information to logs
            print("ok: ", status.ok)
            print("status: ", status.status)
            print("stderr: ", status.stderr)

            # Check if encryption was successful
            if not status.ok:
                error_msg = f"Encryption failed: {status.stderr}"
                print(error_msg)
                return {
                    'statusCode': 500,
                    'body': {
                        'errorMessage': error_msg
                    }
                }

            # Upload encrypted file to S3 to be sent to remote SFTP server
            try:
                print(f"Uploading file: {output_file}, to bucket: {outputBucket}, as key: {encrypted_key}")
                s3_client.upload_file(output_file, outputBucket, encrypted_key)
                print("File uploaded successfully")
            except ClientError as error:
                # Summary of what went wrong
                print(error.response['Error']['Code'])
                # Explanation of what went wrong
                print(error.response['Error']['Message'])
                return {
                    'statusCode': 500,
                    'body': {
                        'errorCode': error.response['Error']['Code'],
                        'errorMessage': error.response['Error']['Message']
                    }
                }

            # Create JSON body response containing encrypted file S3 path to be passed to next step in step function
            body = {
                'bucket': outputBucket,
                'key': encrypted_key,
                's3_path': ['/' + outputBucket + '/' + encrypted_key]
            }

            statusCode = 200
            response = {
                'statusCode': statusCode,
                'body': body
            }

            # Wipe /tmp directory after encryption has been completed and file has been transferred
            wipe_tmp_directory()

            # Return encrypted file name / S3 path to be passed to next step in step function
            return response


    # If file download from S3 is not successful, return error message
    except Exception as e:
        print(e)
        print('Error getting object {} from bucket {}. Make sure they exist and your bucket is in the same region as this function.'.format(key, bucket))
        raise
