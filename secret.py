import base64
import boto3
import json

SECRET_ID_DB_CONNECTION_PARAMS = 'arn:aws:secretsmanager:eu-central-1:239288348203:secret:prod/db-EvM7pG'
SECRET_ID_COHERE_API_KEY = 'arn:aws:secretsmanager:eu-central-1:239288348203:secret:prod/cohere_api_key-JuK5F4'

def get_secret(secret_id):
    # Initialize a session using Amazon Secrets Manager
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name="eu-central-1",
    )

    try:
        # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
        # In a real-world scenario, you should handle more exceptions.
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_id
        )
        
    except Exception as e:
        print(f"An error occurred: {e}")
        raise e
    
    else:
        # Depending on whether the secret was a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return json.loads(secret)
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return json.loads(decoded_binary_secret)


def db_connection():
    db_connection_params = get_secret(SECRET_ID_DB_CONNECTION_PARAMS)
    return {"dbname": db_connection_params["dbname"],
            "user": db_connection_params["username"],
            "password": db_connection_params["password"],
            "host": db_connection_params["host"],
            "port": db_connection_params["port"]}


def get_cohere_api_key():
    cohere_api_key = get_secret(SECRET_ID_COHERE_API_KEY)
    return cohere_api_key["key"]
