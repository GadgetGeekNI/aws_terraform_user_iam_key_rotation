# ---------------------------------------------------------------------------- #
#                                  What doing?                                 #
# ---------------------------------------------------------------------------- #
# The purpose of this script is to check whether or not the specified IAM 
# Credentials exceed the defined tolerance threshold defined in the variable
# iam_days_before_rotation. This script is intended to be ran as a lambda 
# function on a defined cron cycle such as daily, weekly etc. If the IAM 
# credentials are rotated, it will ensure that they are also updated in 
# Terraform Cloud's Variable Set for the defined IAM user which in this
# specfic instance is Terraform_User.
# After this credential has been rotated, the entry in SecretsManager for both
# Access and Secret Key are updated,
# 
# In TF Cloud there are two variable sets per account. Default and Secondary.
#
# Default is to be used for the main environment the TF workflow takes place in.
#
# Secondary is for accounts that the TF Workflow needs to connect to, a good 
# example of this is shared_services which is more commonly connected to as a 
# secondary AWS account for VPC mapping and isn't always used as the main AWS 
# account.
#
# Based on the result of each of these actions, a Slack message is composed in
# blocks which should allow a DevOps engineer to easily follow along with what 
# has succeeded and what has failed during the run.
#
# The env tag, prod, dev etc from the terraform user will be matched against 
# the Terraform Cloud Workspace Variable name, so it needs to match. This is
# really important

# ---------------------------------- Modules --------------------------------- #
import os
#AWS
import boto3
from botocore.exceptions import ClientError
import datetime
from base64 import b64decode
#Terraform Cloud
from terrasnek.api import TFC
#Slack
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

# ------------------------------- Default Vars ------------------------------- #

# Name list to loop through. These are not named consistently.
terraform_username_list = ["terraform-user","terraform_user","terraform-cloud","terraform_cloud"]
iam_days_before_rotation = 30

# AWS Vars
aws_access_key_id = 'AWS_ACCESS_KEY_ID'
aws_secret_access_key = 'AWS_SECRET_ACCESS_KEY'
# Create a IAM Boto Client
iam_client = boto3.client('iam')
# Create a Secrets Manager Boto client
session = boto3.session.Session()
sm_client = session.client(
    service_name='secretsmanager'
)

# AWS Secrets Manager Vars.
secretsmanager_prefix = "devops/iam_rotation/terraform_user_credentials"

# Terraform Cloud Vars
TFC_URL = "https://app.terraform.io"
TFC_ORG = os.environ['TFC_ORG']
TFC_TOKEN=os.environ['TFC_TOKEN']

terraform_cloud = TFC(TFC_TOKEN, url=TFC_URL)
terraform_cloud.set_org(TFC_ORG)

# Slack Vars
slack_client = WebClient(token=os.environ['SLACK_TOKEN'])
slack_channel_id = token=os.environ['SLACK_CHANNEL_ID']

# ---------------------------------------------------------------------------- #
#                          AWS IAM Credential Rotation                         #
# ---------------------------------------------------------------------------- #

# Get IAM User Details.
def list_access_key(user, days_filter, status_filter):
    keydetails=iam_client.list_access_keys(UserName=user)
    key_details={}
    user_iam_details=[]

    # Some user may have 2 access keys.
    for keys in keydetails.get('AccessKeyMetadata'):
        # Get Time/Date to compare against IAM Users last regeneration date.
        if (days:=time_diff(keys['CreateDate'])) >= days_filter and keys['Status']==status_filter:
            key_details['UserName']=keys['UserName']
            key_details['AccessKeyId']=keys['AccessKeyId']
            key_details['days']=days
            key_details['status']=keys['Status']
            user_iam_details.append(key_details)
            key_details={}
        else: 
            print('IAM Key for '+ user +' is less than ' + str(iam_days_before_rotation) + ' days old. No action taken.')

    return user_iam_details

# Get Time/Date to compare against IAM Users last regeneration date.
def time_diff(keycreatedtime):
    now=datetime.datetime.now(datetime.timezone.utc)
    diff=now-keycreatedtime
    return diff.days

# Get AWS Environment Tag.
def get_aws_environment(user):
    iam_user_tags=iam_client.list_user_tags(UserName=user)

    for tag in iam_user_tags.get('Tags'):
        if tag['Key'] == 'environment':
            aws_environment_tag = tag['Value']
    
    if aws_environment_tag is None:
        # Error. User has no environment tag.
        print(user + " has no environment tag!")
    else:
        print("Current AWS Environment is " + aws_environment_tag)
    
    return aws_environment_tag

# Regenerate IAM Key.
def create_key(username):
    access_key_metadata = iam_client.create_access_key(UserName=username)
    generated_access_key = access_key_metadata['AccessKey']['AccessKeyId']
    generated_secret_key = access_key_metadata['AccessKey']['SecretAccessKey']
    print(generated_access_key + " has been created.")
    return generated_access_key,generated_secret_key

# Disable Existing IAM Key if date greater than tolerance.
def disable_key(access_key, username):
    try:
        iam_client.update_access_key(UserName=username, AccessKeyId=access_key, Status="Inactive")
        print(access_key + " has been disabled.")
    except ClientError as e:
        print("The access key with id %s cannot be found" % access_key)

# Delete Existing IAM Key if date greater than tolerance.
def delete_key(access_key, username):
    try:
        iam_client.delete_access_key(UserName=username, AccessKeyId=access_key)
        print (access_key + " has been deleted.")
    except ClientError as e:
        print("The access key with id %s cannot be found" % access_key)

# ---------------------------------------------------------------------------- #
#                  Terraform Cloud Workspace Credential Update                 #
# ---------------------------------------------------------------------------- #

# Retrieve the ID of the environment varset in TF Cloud.
def get_tf_varsets(aws_environment_tag):
    try:
        tf_varsets = terraform_cloud.var_sets.list_all_for_org()
    except Exception as e:
        print("Error occurred while retrieving tf_varsets:", str(e))
        return None, None

    default_tf_varset_id = None
    secondary_tf_varset_id = None

    try:
        # Iterate through the list of dictionaries in the `data` field for the default tf varset.
        for varset_dict in tf_varsets.get('data'):
            varset_name = varset_dict['attributes']['name']

            if varset_name == 'aws_' + aws_environment_tag + '_default_vars':
                default_tf_varset_id = varset_dict['id']
                break
        
        # Iterate through the list of dictionaries in the `data` field for the secondary tf varset.
        for varset_dict in tf_varsets.get('data'):
            varset_name = varset_dict['attributes']['name']

            if varset_name == 'aws_' + aws_environment_tag + '_secondary_vars':
                secondary_tf_varset_id = varset_dict['id']
                break
    except (KeyError, TypeError):
        print("Unexpected data structure encountered while processing tf_varsets.")
        return None, None

    return default_tf_varset_id, secondary_tf_varset_id

def update_tf_varset_vars(default_tf_varset_id, secondary_tf_varset_id, generated_access_key, generated_secret_key, aws_environment_tag):
    try:
        # Fetch the list of variables in the default varset
        default_tf_varset_vars = terraform_cloud.var_sets.list_vars_in_varset(default_tf_varset_id)
    except Exception as e:
        # Handle exceptions while fetching varset variables
        print(f"Error occurred while fetching default_tf_varset_vars: {e}")
        return None

    try:
        # Loop through the list of variables in the default varset
        for var_dict in default_tf_varset_vars.get('data'):
            var_key = var_dict['attributes']['key']
            var_id = var_dict['id']

            if var_key == "AWS_ACCESS_KEY_ID":
                try:
                    # Update Default AWS_ACCESS_KEY_ID with the newly generated credential
                    terraform_cloud.var_sets.update_var_in_varset(default_tf_varset_id, var_id, {"data": {"attributes": {"value": generated_access_key}}})
                    print("Default Var: AWS_ACCESS_KEY_ID has been updated in TF Cloud")
                except Exception as e:
                    # Handle exceptions while updating AWS_ACCESS_KEY_ID
                    print(f"Error occurred while updating default AWS_ACCESS_KEY_ID: {e}")

            elif var_key == "AWS_SECRET_ACCESS_KEY":
                try:
                    # Update Default AWS_SECRET_ACCESS_KEY with the newly generated credential
                    terraform_cloud.var_sets.update_var_in_varset(default_tf_varset_id, var_id, {"data": {"attributes": {"value": generated_secret_key}}})
                    print("Default Var: AWS_SECRET_ACCESS_KEY has been updated in TF Cloud")
                except Exception as e:
                    # Handle exceptions while updating AWS_SECRET_ACCESS_KEY
                    print(f"Error occurred while updating default AWS_SECRET_ACCESS_KEY: {e}")

    except Exception as e:
        # Handle exceptions while parsing varset variables
        print(f"Error occurred while parsing default_tf_varset_vars: {e}")
        return None

    try:
        # Fetch the list of variables in the secondary varset
        secondary_tf_varset_vars = terraform_cloud.var_sets.list_vars_in_varset(secondary_tf_varset_id)
    except Exception as e:
        # Handle exceptions while fetching varset variables
        print(f"Error occurred while fetching secondary_tf_varset_vars: {e}")
        return None

    try:
        # Loop through the list of variables in the secondary varset
        for var_dict in secondary_tf_varset_vars.get('data'):
            var_key = var_dict['attributes']['key']
            var_id = var_dict['id']

            if var_key == aws_environment_tag + "_access_key":
                try:
                    # Update Secondary AWS_ACCESS_KEY_ID with the newly generated credential
                    terraform_cloud.var_sets.update_var_in_varset(secondary_tf_varset_id, var_id, {"data": {"attributes": {"value": '"' + generated_access_key + '"'}}})
                    print(f"Secondary Var: {aws_environment_tag}_access_key has been updated in TF Cloud")
                except Exception as e:
                    # Handle exceptions while updating AWS_ACCESS_KEY_ID
                    print(f"Error occurred while updating secondary {aws_environment_tag}_access_key: {e}")

            elif var_key == aws_environment_tag + "_secret_key":
                try:
                    # Update Secondary AWS_SECRET_ACCESS_KEY with the newly generated credential
                    terraform_cloud.var_sets.update_var_in_varset(secondary_tf_varset_id, var_id, {"data": {"attributes": {"value": '"' + generated_secret_key + '"'}}})
                    print(f"Secondary Var: {aws_environment_tag}_secret_key has been updated in TF Cloud")
                except Exception as e:
                    # Handle exceptions while updating AWS_SECRET_ACCESS_KEY
                    print(f"Error occurred while updating secondary {aws_environment_tag}_secret_key: {e}")

    except Exception as e:
        # Handle exceptions while parsing varset variables
        print(f"Error occurred while parsing secondary_tf_varset_vars: {e}")
        return None

# ---------------------------------------------------------------------------- #
#                             SecretsManager Update                            #
# ---------------------------------------------------------------------------- #

# Get the ARN Value of the Secret, every time this is rotated the ARN changes so it must always get before it can action.
def get_secret_manager_secret():
    secret_name = secretsmanager_prefix
    secret_manager_arn = None

    try:

        # Define the filter expression to filter secrets by name
        filters = [
            {
                'Key': 'name',
                'Values': [secret_name]
            }
        ]

        secret_list = sm_client.list_secrets(Filters=filters)
        secrets = secret_list['SecretList']

        for secret in secrets:
            if secret['Name'] == secret_name:
                secret_manager_arn = secret['ARN']
                break
        else:
            raise ValueError(f"No secret found with name {secret_name}")

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ResourceNotFoundException':
            raise ValueError(f"No secret found with name : {secret_name}")
        else:
            raise ValueError(f"Failed to list secrets : {error_code}")

    return secret_manager_arn

# Update the grabbed ARN with the latest generated keys. It's good to have a record of these somewhere otherwise we have no
# visibility if we need to use it for anything.

def update_secret_manager_values(generated_access_key, generated_secret_key, secret_manager_arn):
    try:
        secret_value = {
            aws_access_key_id: generated_access_key,
            aws_secret_access_key: generated_secret_key
        }

        sm_client.put_secret_value(
            SecretId=secret_manager_arn,
            SecretString=str(secret_value)
        )

        print("Secret Manager credentials updated successfully!")

    except ClientError as e:
        error_code = e.response['Error']['Code']

        if error_code == 'ResourceNotFoundException':
            raise ValueError(f"No secret found with ARN {secret_manager_arn}")
        elif error_code == 'InvalidParameterException':
            raise ValueError(f"Invalid parameter passed to put_secret_value for ARN {secret_manager_arn}")
        else:
            raise e

def send_slack_failure_notification(error_message):
    try:
        # Call the conversations.list method using the WebClient
        slack_client.chat_postMessage(
            channel=slack_channel_id,
            text=f"An unexpected error occurred which resulted in the IAM key rotation failing on *terraform_user* :\n\n*Error Message: {error_message}*"
        )
    except SlackApiError as e:
        print(f"Error: {e}")

# ---------------------------------------------------------------------------- #
#                                Lambda Function                               #
# ---------------------------------------------------------------------------- #

# Run the Lambda.
def lambda_handler(event, context):
    try:
        non_existent_users = []
        for user in terraform_username_list:
            try:
                iam_client.get_user(UserName=user)
            except iam_client.exceptions.NoSuchEntityException:
                print(f"User '{user}' does not exist. Skipping policy attachment.")
                non_existent_users.append(user)

        # Attach the policy to the existing users
        existing_users = set(terraform_username_list) - set(non_existent_users)
        if existing_users:
            for user in existing_users:
                # Save the Username for this loop
                found_username = user
                user_iam_details=list_access_key(user=user,days_filter=iam_days_before_rotation,status_filter='Active')
                for _ in user_iam_details:
                    # ------------------------------------ AWS ----------------------------------- #
                    # Get AWS Environnent Tag.
                    aws_environment_tag = get_aws_environment(user)
                    # Disable Existing IAM Key if date greater than tolerance.
                    disable_key(access_key=_['AccessKeyId'], username=_['UserName'])
                    # Delete Existing IAM Key if date greater than tolerance.
                    delete_key(access_key=_['AccessKeyId'], username=_['UserName'])
                    # Regenerate IAM Key.
                    generated_access_key, generated_secret_key = create_key(username=_['UserName'])
                    # ------------------------------ Terraform Cloud ----------------------------- #
                    # Get TF Cloud Varset Details.
                    default_tf_varset_id, secondary_tf_varset_id = get_tf_varsets(aws_environment_tag)
                    # Update the values of both TF Varsets with the newly generated IAM credentials.
                    update_tf_varset_vars(default_tf_varset_id, secondary_tf_varset_id, generated_access_key, generated_secret_key, aws_environment_tag)
                    
                    # ------------------------------ Secrets Manager ----------------------------- #
                    # Update the values of SecretsManager with the newly generated IAM Credentials
                    secret_manager_arn = get_secret_manager_secret()
                    update_secret_manager_values(generated_access_key, generated_secret_key, secret_manager_arn)
                    # # Update Slack Message Block with details on successful runs. If parts are missing, they didn't run.
                    # slack_message_block=update_slack_message(generated_access_key,generated_secret_key,aws_environment_tag,default_tf_varset_id,secondary_tf_varset_id,secret_manager_arn,found_username)
                    
                    # # Send a Slack Message to the DevOps team informing them of a successful run.
                    # send_slack_message(slack_message_block)
                else:
                    print("No action taken.")
        # Print a message about non-existent users
        if non_existent_users:
                print(f"Skipping IAM Rotation for non-existent users: {', '.join(non_existent_users)}") 
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        send_slack_failure_notification(str(e))

