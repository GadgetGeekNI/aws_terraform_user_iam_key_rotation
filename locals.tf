locals {
  /* -------------------------------------------------------------------------- */
  /*                                   Lambda                                   */
  /* -------------------------------------------------------------------------- */

  lambda_file_name                      = "lambda-package.zip"
  lambda_handler_name                   = "lambda_function.lambda_handler"
  lambda_function_timeout               = 9
  lambda_reserved_concurrent_executions = 2
  lambda_runtime_language               = "python3.10"

  /* -------------------------------------------------------------------------- */
  /*                               Secrets Manager                              */
  /* -------------------------------------------------------------------------- */
  secretsmanager_prefix = "devops/iam_rotation/terraform_user_credentials"
}
