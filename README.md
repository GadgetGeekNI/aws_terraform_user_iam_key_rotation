# aws_iam_keys_rotation_lambda

Process: 

Ensure the Environment Tag of Terraform_User matches the name of the var set in TF Cloud (This is important)

Create a new file called account_(env_name).tf
Copy the contents of the template file into the new file
Uncomment the template file
Find & Replate 'account' with the new env name

Add the new aws account secondary var_set in the terraform cloud Workspace.

Commit, push and apply.

Profit(?)

Should anyone require the credentials for manual work, retrieve them from the SecretsManager Entry in the respective account.
