/* ---------------------------- Generic Variables --------------------------- */

variable "region" {
  type        = string
  default     = "us-east-1"
  description = "This value specifies the AWS Region that we are working out of."
}

variable "resource_naming_convention" {
  type        = string
  default     = "qol_terraform_iam_credential_rotation"
  description = "This value is just to specify what the general naming convention of the resources will be."
}

variable "immediate_secret_deletion" {
  type        = number
  default     = 0
  description = "A recovery window of 0 days results in immediate deletion. Enabling Terraform Destroy"
}

/* ---------------------------------- Tags ---------------------------------- */

variable "purpose_tag" {
  type        = string
  default     = "Supports IAM Credential Rotation for a specified terraform user account"
  description = "Default Tag for all resources."
}

variable "bill_tag" {
  type        = string
  default     = "admin"
  description = "Default Tag for all resources."
}

variable "managed_by_tag" {
  type        = string
  default     = "terraform"
  description = "Default Tag for all resources."
}

/* ---------------------------- Lambda Variables ---------------------------- */

variable "key_services" {
  type        = list(string)
  description = "Description of services for KMS keys with identical config"
  default = [
    "iam_rotation_lambda_secret",
    "iam_rotation_env_vars"
  ]
}

variable "tfc_token" {
  type        = string
  default     = ""
  description = "Terraform API token"
}

variable "slack_token" {
  type        = string
  default     = ""
  description = "Slack API token"
}

variable "slack_channel_id" {
  type        = string
  default     = ""
  description = "Slack Channel ID"
}

variable "aws_secretsmanager_secret_keys" {
  type = map(string)
  default = {
    AWS_ACCESS_KEY_ID     = "PlaceHolder"
    AWS_SECRET_ACCESS_KEY = "PlaceHolder"
  }
  description = "AWS Attributes to add to the Secrets Manager Entry for Credential tracking"
}
