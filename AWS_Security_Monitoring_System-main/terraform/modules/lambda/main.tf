# Common IAM role for Lambda functions
resource "aws_iam_role" "lambda_role" {
  name = "security-monitoring-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      },
    ]
  })
}

# IAM policy for Lambda logging
resource "aws_iam_policy" "lambda_logging" {
  name        = "security-monitoring-lambda-logging"
  description = "IAM policy for logging from Lambda"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# IAM policy for AWS security services access
resource "aws_iam_policy" "lambda_security_access" {
  name        = "security-monitoring-lambda-security-access"
  description = "IAM policy for accessing security services from Lambda"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "guardduty:GetFindings",
          "guardduty:ListFindings",
          "inspector2:ListFindings",
          "inspector2:GetFindings",
          "wafv2:GetWebACL",
          "wafv2:GetSampledRequests"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

# Attach policies to role
resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_logging.arn
}

# S3 access policy attachment using AWS managed policy
resource "aws_iam_role_policy_attachment" "lambda_s3" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "lambda_security" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_security_access.arn
}

# Create Lambda layer for dependencies
resource "aws_lambda_layer_version" "dependencies" {
  layer_name = "security-monitoring-dependencies"

  filename = "${path.module}/../../../lambda/layer/dependencies.zip"

  compatible_runtimes = ["python3.9"]
}

# GuardDuty Collector Lambda
resource "aws_lambda_function" "guardduty_collector" {
  function_name = "guardduty-collector"

  filename         = "${path.module}/../../../lambda/collectors/guardduty_collector.zip"
  source_code_hash = filebase64sha256("${path.module}/../../../lambda/collectors/guardduty_collector.zip")

  handler = "guardduty_collector.lambda_handler"
  runtime = "python3.9"

  role    = aws_iam_role.lambda_role.arn
  timeout = 300

  layers = [aws_lambda_layer_version.dependencies.arn]

  environment {
    variables = {
      DATADOG_API_KEY = var.datadog_api_key
      LOGS_BUCKET     = var.logs_bucket_name
    }
  }
}

# Inspector Collector Lambda
resource "aws_lambda_function" "inspector_collector" {
  function_name = "inspector-collector"

  filename         = "${path.module}/../../../lambda/collectors/inspector_collector.zip"
  source_code_hash = filebase64sha256("${path.module}/../../../lambda/collectors/inspector_collector.zip")

  handler = "inspector_collector.lambda_handler"
  runtime = "python3.9"

  role    = aws_iam_role.lambda_role.arn
  timeout = 300

  layers = [aws_lambda_layer_version.dependencies.arn]

  environment {
    variables = {
      DATADOG_API_KEY = var.datadog_api_key
      LOGS_BUCKET     = var.logs_bucket_name
    }
  }
}

# WAF Collector Lambda
resource "aws_lambda_function" "waf_collector" {
  function_name = "waf-collector"

  filename         = "${path.module}/../../../lambda/collectors/waf_collector.zip"
  source_code_hash = filebase64sha256("${path.module}/../../../lambda/collectors/waf_collector.zip")

  handler = "waf_collector.lambda_handler"
  runtime = "python3.9"

  role    = aws_iam_role.lambda_role.arn
  timeout = 300

  layers = [aws_lambda_layer_version.dependencies.arn]

  environment {
    variables = {
      DATADOG_API_KEY = var.datadog_api_key
      LOGS_BUCKET     = var.logs_bucket_name
    }
  }
}

# AI Anomaly Detection Lambda
resource "aws_lambda_function" "anomaly_detection" {
  function_name = "security-anomaly-detection"

  filename         = "${path.module}/../../../lambda/anomaly_detection/anomaly_detection.zip"
  source_code_hash = filebase64sha256("${path.module}/../../../lambda/anomaly_detection/anomaly_detection.zip")

  handler = "anomaly_detection.lambda_handler"
  runtime = "python3.9"

  role        = aws_iam_role.lambda_role.arn
  timeout     = 600
  memory_size = 1024

  layers = [aws_lambda_layer_version.dependencies.arn]

  environment {
    variables = {
      DATADOG_API_KEY = var.datadog_api_key
      LOGS_BUCKET     = var.logs_bucket_name
    }
  }
}

data "aws_caller_identity" "current" {}
