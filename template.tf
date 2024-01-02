/* -------------------------------------------------------------------------- */
/*                        Account IAM Rotation Function                       */
/* -------------------------------------------------------------------------- */

# Find and Replace Account with the Actual Env Name

/* -------------------------------------------------------------------------- */
/*                                AWS Provider                                */
/* -------------------------------------------------------------------------- */

provider "aws" {
  alias      = "account"
  region     = var.region
  access_key = var.account_access_key
  secret_key = var.account_secret_key

  default_tags {
    tags = {
      bill        = var.bill_tag
      purpose     = var.purpose_tag
      managed_by  = var.managed_by_tag
      environment = "account"
    }
  }
}

/* -------------------------------------------------------------------------- */
/*                                  Variables                                 */
/* -------------------------------------------------------------------------- */

variable "account_access_key" {
  type        = string
  default     = ""
  description = "This value is for the AWS Access Key ID for the account environment"
}

variable "account_secret_key" {
  type        = string
  default     = ""
  description = "This value is for the AWS Secret Access Key for the account environment"
}

/* -------------------------------------------------------------------------- */
/*                                Data Sources                                */
/* -------------------------------------------------------------------------- */

data "aws_region" "account" {
  provider = aws.account
}

data "aws_caller_identity" "account" {
  provider = aws.account
}
data "aws_partition" "account" {
  provider = aws.account
}

resource "time_sleep" "lambda_wait_40_seconds_account" {
  depends_on      = [aws_secretsmanager_secret_version.rotated_terraform_user_access_key_id_version_account]
  create_duration = "40s"
}

/* -------------------------------------------------------------------------- */
/*                               Lambda Function                              */
/* -------------------------------------------------------------------------- */

resource "aws_lambda_function" "cycle_iam_credentials_lambda_account" {
  provider                       = aws.account
  filename                       = local.lambda_file_name
  function_name                  = var.resource_naming_convention
  role                           = aws_iam_role.lambda_iam_role_account.arn
  handler                        = local.lambda_handler_name
  timeout                        = local.lambda_function_timeout
  reserved_concurrent_executions = local.lambda_reserved_concurrent_executions
  source_code_hash               = filebase64sha256(local.lambda_file_name)
  runtime                        = local.lambda_runtime_language
  kms_key_arn                    = aws_kms_key.key_services_account[1].arn

  # X-Ray Tracing
  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      TFC_TOKEN        = var.tfc_token
      SLACK_TOKEN      = var.slack_token
      SLACK_CHANNEL_ID = var.slack_channel_id
    }
  }

  depends_on = [time_sleep.lambda_wait_40_seconds_account]
  #checkov:skip=CKV_AWS_116:The Python code has built in error handling with an except block that will send a Slack message.
  #checkov:skip=CKV_AWS_117:This Lambda does not require access to a VPC. It only touches IAM and SecretsManager which are not in a VPC.
  #checkov:skip=CKV_AWS_272:Code Signing being skipped
}

/* -------------------------------------------------------------------------- */
/*                                 Cloudwatch                                 */
/* -------------------------------------------------------------------------- */

resource "aws_cloudwatch_event_rule" "run_lambda_schedule_account" {
  provider            = aws.account
  name                = "iam_rotation_schedule"
  description         = "Run On Defined Schedule"
  schedule_expression = "rate(1 day)"
}

resource "aws_cloudwatch_event_target" "lambda_schedule_target_account" {
  provider  = aws.account
  rule      = aws_cloudwatch_event_rule.run_lambda_schedule_account.name
  target_id = "Invoke-Iam-Rotation"
  arn       = aws_lambda_function.cycle_iam_credentials_lambda_account.arn
}

resource "aws_lambda_permission" "allow_cloudwatch_to_call_check_run_account" {
  provider      = aws.account
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cycle_iam_credentials_lambda_account.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.run_lambda_schedule_account.arn
}

/* -------------------------------------------------------------------------- */
/*                            X-Ray Tracing Policy                            */
/* -------------------------------------------------------------------------- */

data "aws_iam_policy" "xray_tracing_policy_account" {
  provider = aws.account
  arn      = "arn:${data.aws_partition.account.partition}:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

resource "aws_iam_policy" "xray_tracing_policy_account" {
  provider = aws.account
  name     = "${var.resource_naming_convention}_xray_tracing_policy"
  policy   = data.aws_iam_policy.xray_tracing_policy_account.policy
}

resource "aws_iam_role_policy_attachment" "xray_tracing_policy_attachment_account" {
  provider   = aws.account
  role       = aws_iam_role.lambda_iam_role_account.name
  policy_arn = aws_iam_policy.xray_tracing_policy_account.arn
}

/* -------------------------------------------------------------------------- */
/*                                  IAM Role                                  */
/* -------------------------------------------------------------------------- */

data "aws_iam_policy_document" "assume_lambda_role_policy_account" {
  provider = aws.account
  statement {
    sid    = "0"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "lambda_iam_role_account" {
  provider           = aws.account
  name               = "${var.resource_naming_convention}_lambda_execution_role"
  assume_role_policy = data.aws_iam_policy_document.assume_lambda_role_policy_account.json
  tags = merge({
    Name = "${var.resource_naming_convention}_lambda_execution_role"
  })
}

data "aws_iam_policy_document" "aws_lambda_iam_policy_document_account" {
  provider = aws.account
  statement {
    sid = "LambdaIamUserPermissions"

    actions = [
      "iam:ListUsers",
      "iam:GetUser",
      "iam:DeleteAccessKey",
      "iam:GetAccessKeyLastUsed",
      "iam:UpdateAccessKey",
      "iam:CreateAccessKey",
      "iam:ListAccessKeys",
      "iam:ListUserTags"
    ]
    resources = ["arn:aws:iam::${data.aws_caller_identity.account.id}:user/terraform*"]
  }
  statement {
    sid       = "CloudwatchCreateLogGroup"
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup"]
    resources = ["arn:aws:logs:${data.aws_region.account.name}:${data.aws_caller_identity.account.id}:*"]
  }
  statement {
    sid    = "CloudwatchAllowResourceLogging"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["arn:aws:logs:${data.aws_region.account.name}:${data.aws_caller_identity.account.id}:log-group:/aws/lambda/${aws_iam_role.lambda_iam_role_account.name}:*"]
  }
  statement {
    sid    = "SecretsManagerPermissions"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue",
      "secretsmanager:UpdateSecret"
    ]
    resources = ["arn:aws:secretsmanager:${data.aws_region.account.name}:${data.aws_caller_identity.account.id}:secret:${local.secretsmanager_prefix}*"]
  }
  statement {
    sid       = "LambdaIamListSecrets"
    effect    = "Allow"
    actions   = ["secretsmanager:ListSecrets"]
    resources = ["*"]
  }
  statement {
    sid    = "KmsKeyPermissions"
    effect = "Allow"
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:Describe*",
      "kms:Generate*",
      "kms:Get*",
      "kms:List*"
    ]
    resources = [
      aws_kms_key.key_services_account[0].arn,
      aws_kms_key.key_services_account[1].arn
    ]
  }
}

resource "aws_iam_policy" "aws_lambda_role_policy_account" {
  provider = aws.account
  name     = "${var.resource_naming_convention}_lambda_role_policy"
  policy   = data.aws_iam_policy_document.aws_lambda_iam_policy_document_account.json
  tags = merge({
    Name = "${var.resource_naming_convention}_lambda_role_policy"
  })
}

resource "aws_iam_policy_attachment" "lambda_iam_role_policy_attachment_account" {
  provider   = aws.account
  name       = "${var.resource_naming_convention}_lambda_role_attachment"
  roles      = [aws_iam_role.lambda_iam_role_account.name]
  policy_arn = aws_iam_policy.aws_lambda_role_policy_account.arn
}

/* -------------------------------------------------------------------------- */
/*                                     KMS                                    */
/* -------------------------------------------------------------------------- */

resource "aws_kms_key" "key_services_account" {
  provider                = aws.account
  count                   = length(var.key_services)
  description             = "KMS Key for ${var.key_services[count.index]}."
  deletion_window_in_days = 10
  enable_key_rotation     = true
  tags                    = merge({ Name = var.key_services[count.index] })
}

/* -------------------------------------------------------------------------- */
/*                               Secrets Manager                              */
/* -------------------------------------------------------------------------- */

resource "aws_secretsmanager_secret" "rotated_terraform_user_credentials_account" {
  provider = aws.account
  #checkov:skip=CKV2_AWS_57:This is not a rotatable secret.
  name                    = local.secretsmanager_prefix
  description             = "The most up to date version of the terraform user credentials"
  kms_key_id              = aws_kms_key.key_services_account[0].arn
  recovery_window_in_days = var.immediate_secret_deletion
  tags                    = merge({ Name = local.secretsmanager_prefix })
}

resource "aws_secretsmanager_secret_version" "rotated_terraform_user_access_key_id_version_account" {
  provider      = aws.account
  secret_id     = aws_secretsmanager_secret.rotated_terraform_user_credentials_account.id
  secret_string = jsonencode(var.aws_secretsmanager_secret_keys)
}
